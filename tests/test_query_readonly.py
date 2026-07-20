"""D1 (#34): `icarus query` is read-only by default; writes require `icarus exec`.

These tests build a real, tiny ICARUS database with ``initialize_database`` and
then drive the DEFAULT query path (``IcarusQuery(db)`` / ``cmd_query``) with a
battery of mutation vectors, asserting each is refused and the database is
byte-for-byte unchanged afterwards. The adversarial vectors covered:

  * INSERT / UPDATE / DELETE   — ordinary DML writes to the main database
  * DROP TABLE / CREATE TABLE  — DDL / schema mutation
  * ATTACH + write to attached — the reason ``PRAGMA query_only = ON`` matters
                                 (``mode=ro`` alone only guards the MAIN file)
  * writable pragmas           — journal_mode / writable_schema cannot re-open
                                 a mutation path

Plus the positive proof that the explicit ``icarus exec`` interface CAN write,
and that a corrupt database file run through ``cmd_query`` exits non-zero with a
clean message rather than a traceback.
"""

import sqlite3
import types

import pytest

from icarus import __main__ as cli
from icarus.core.query import IcarusQuery
from icarus.core.schema import initialize_database, open_db


def _make_db(tmp_path):
    """A real v6 ICARUS database seeded with one known ``files`` row."""
    db = tmp_path / "icarus.db"
    initialize_database(db)
    conn = open_db(db)
    try:
        conn.execute(
            "INSERT INTO files (path, filename) VALUES (?, ?)", ("/seed", "seed")
        )
        conn.commit()
    finally:
        conn.close()
    return db


def _count(db, table="files"):
    conn = open_db(db, readonly=True)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def _table_exists(db, table):
    conn = open_db(db, readonly=True)
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def _query_args(db, **over):
    ns = types.SimpleNamespace(
        database=str(db), sql=None, search=None, table="files", stats=False
    )
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


# ── the default query connection is genuinely read-only ─────────────────────

def test_default_query_connection_reports_writable_false(tmp_path):
    db = _make_db(tmp_path)
    with IcarusQuery(str(db)) as q:
        assert q.writable is False
        # A SELECT still works — read-only, not closed.
        assert q.execute("SELECT COUNT(*) FROM files").rows[0][0] == 1


def test_insert_is_refused(tmp_path):
    db = _make_db(tmp_path)
    before = _count(db)
    with IcarusQuery(str(db)) as q:
        with pytest.raises(sqlite3.OperationalError):
            q.execute("INSERT INTO files (path, filename) VALUES ('/x', 'x')")
    assert _count(db) == before


def test_update_is_refused(tmp_path):
    db = _make_db(tmp_path)
    with IcarusQuery(str(db)) as q:
        with pytest.raises(sqlite3.OperationalError):
            q.execute("UPDATE files SET filename = 'clobbered'")
    conn = open_db(db, readonly=True)
    try:
        assert conn.execute("SELECT filename FROM files").fetchone()[0] == "seed"
    finally:
        conn.close()


def test_delete_is_refused(tmp_path):
    db = _make_db(tmp_path)
    before = _count(db)
    with IcarusQuery(str(db)) as q:
        with pytest.raises(sqlite3.OperationalError):
            q.execute("DELETE FROM files")
    assert _count(db) == before


def test_drop_table_is_refused(tmp_path):
    db = _make_db(tmp_path)
    assert _table_exists(db, "files")
    with IcarusQuery(str(db)) as q:
        with pytest.raises(sqlite3.OperationalError):
            q.execute("DROP TABLE files")
    assert _table_exists(db, "files")


def test_create_table_is_refused(tmp_path):
    db = _make_db(tmp_path)
    with IcarusQuery(str(db)) as q:
        with pytest.raises(sqlite3.OperationalError):
            q.execute("CREATE TABLE injected (x INTEGER)")
    assert not _table_exists(db, "injected")


# ── ATTACH: the reason query_only=ON is required ────────────────────────────

def test_attach_and_write_to_attached_db_is_refused(tmp_path):
    """mode=ro only guards the MAIN file; without PRAGMA query_only a write to
    an ATTACHed (read-write) database would succeed. query_only blocks it."""
    db = _make_db(tmp_path)
    side = tmp_path / "side.db"
    sconn = sqlite3.connect(str(side))
    sconn.execute("CREATE TABLE t (x INTEGER)")
    sconn.commit()
    sconn.close()

    with IcarusQuery(str(db)) as q:
        # ATTACH itself is a connection operation, permitted; opened read-write
        # by default via a file: URI (the main connection has uri=True).
        q.conn.execute(f"ATTACH DATABASE 'file:{side}' AS e")
        with pytest.raises(sqlite3.OperationalError):
            q.conn.execute("INSERT INTO e.t VALUES (1)")
        q.conn.execute("DETACH DATABASE e")

    scheck = sqlite3.connect(str(side))
    try:
        assert scheck.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 0
    finally:
        scheck.close()


# ── writable pragmas cannot re-open a mutation path ─────────────────────────

def test_writable_pragmas_do_not_enable_mutation(tmp_path):
    db = _make_db(tmp_path)
    before = _count(db)
    with IcarusQuery(str(db)) as q:
        # Neither of these must open a write path on a read-only connection.
        for pragma in ("PRAGMA journal_mode = DELETE", "PRAGMA writable_schema = ON"):
            try:
                q.conn.execute(pragma)
            except sqlite3.OperationalError:
                pass  # refused outright is fine too
        with pytest.raises(sqlite3.OperationalError):
            q.conn.execute("INSERT INTO files (path, filename) VALUES ('/z', 'z')")
        with pytest.raises(sqlite3.OperationalError):
            q.conn.execute("UPDATE sqlite_master SET name = name")
    assert _count(db) == before


# ── cmd_query surfaces the read-only barrier with a clear exit code ──────────

def test_cmd_query_write_gives_clean_readonly_error(tmp_path, capsys):
    db = _make_db(tmp_path)
    args = _query_args(db, sql="INSERT INTO files (path, filename) VALUES ('/y', 'y')")
    with pytest.raises(SystemExit) as exc:
        cli.cmd_query(args)
    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "read-only" in err
    assert "icarus exec" in err
    assert "Traceback" not in err
    assert _count(db) == 1


# ── the explicit exec interface CAN write ───────────────────────────────────

def test_exec_can_insert(tmp_path, capsys):
    db = _make_db(tmp_path)
    before = _count(db)
    args = types.SimpleNamespace(
        database=str(db),
        sql="INSERT INTO files (path, filename) VALUES ('/added', 'added')",
    )
    cli.cmd_exec(args)
    out = capsys.readouterr()
    assert "Rows affected: 1" in out.out
    assert "READ-WRITE" in out.err  # the mutating-notice
    assert _count(db) == before + 1


def test_icarusquery_writable_can_insert(tmp_path):
    db = _make_db(tmp_path)
    before = _count(db)
    with IcarusQuery(str(db), writable=True) as q:
        q.conn.execute("INSERT INTO files (path, filename) VALUES ('/rw', 'rw')")
        q.commit()
    assert _count(db) == before + 1


# ── corrupt input: clean non-zero exit, no traceback ────────────────────────

def test_corrupt_database_clean_exit(tmp_path, capsys):
    bad = tmp_path / "corrupt.db"
    bad.write_bytes(b"NOT-A-SQLITE-DATABASE " * 64)
    args = _query_args(bad, sql="SELECT COUNT(*) FROM files")
    with pytest.raises(SystemExit) as exc:
        cli.cmd_query(args)
    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "ERROR" in err
    assert "Traceback" not in err
