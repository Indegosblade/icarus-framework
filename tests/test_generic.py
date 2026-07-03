"""Tests for Phase 3.4 — Generic fallback parsers."""

import sqlite3
import tempfile
from pathlib import Path

import pytest

from icarus.core.schema import initialize_database

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _run_parser_on_fixture(parser, fixture_dir):
    db_path = Path(tempfile.mktemp(suffix=".db"))
    initialize_database(db_path, {"source": "test"})
    parser.extract_entities(fixture_dir, db_path)
    return db_path


def test_generic_json_identifies():
    from icarus.parsers.generic.json_parser import JsonParser
    p = JsonParser()
    assert p.identify(FIXTURES_DIR / "generic_json")
    with tempfile.TemporaryDirectory() as empty:
        assert not p.identify(Path(empty))


def test_generic_json_extracts():
    from icarus.parsers.generic.json_parser import JsonParser
    db = _run_parser_on_fixture(JsonParser(), FIXTURES_DIR / "generic_json")
    try:
        conn = sqlite3.connect(str(db))
        count = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        assert count == 2
        conn.close()
    finally:
        db.unlink(missing_ok=True)


def test_generic_sqlite_identifies():
    from icarus.parsers.generic.sqlite_parser import SqliteParser
    p = SqliteParser()
    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / "test.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        conn.commit()
        conn.close()
        assert p.identify(Path(d))


def test_generic_sqlite_extracts():
    from icarus.parsers.generic.sqlite_parser import SqliteParser
    with tempfile.TemporaryDirectory() as fixture:
        fixture_path = Path(fixture)
        src_db = fixture_path / "test.db"
        conn = sqlite3.connect(str(src_db))
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
        conn.execute("INSERT INTO users VALUES (1, 'test')")
        conn.commit()
        conn.close()
        db = _run_parser_on_fixture(SqliteParser(), fixture_path)
        try:
            out = sqlite3.connect(str(db))
            count = out.execute("SELECT COUNT(*) FROM files").fetchone()[0]
            assert count == 1
            obs = out.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
            assert obs >= 1
            out.close()
        finally:
            db.unlink(missing_ok=True)


def test_generic_specificity_loses_to_windows():
    """Windows dir: Windows parser wins over generic parsers."""
    from icarus.parsers import detect_parser
    src = Path(tempfile.mkdtemp())
    pe_data = bytearray(256)
    pe_data[0:2] = b"MZ"
    (src / "test.exe").write_bytes(bytes(pe_data))
    (src / "data.json").write_text('{"key": "value"}')
    result = detect_parser(src)
    assert result == "windows"


def test_generic_zero_pii_all():
    """HYGEIA passes on all five generic parser outputs."""
    from icarus.integrations.hygeia import verify_clean
    from icarus.parsers.generic.archive_parser import ArchiveParser
    from icarus.parsers.generic.binary_entropy_parser import BinaryEntropyParser
    from icarus.parsers.generic.json_parser import JsonParser
    from icarus.parsers.generic.sqlite_parser import SqliteParser
    from icarus.parsers.generic.xml_parser import XmlParser

    simple_parsers = [
        (JsonParser(), "generic_json"),
        (XmlParser(), "generic_xml"),
        (ArchiveParser(), "generic_archive"),
        (BinaryEntropyParser(), "generic_binary"),
    ]
    for parser, fixture_name in simple_parsers:
        fixture_dir = FIXTURES_DIR / fixture_name
        db = _run_parser_on_fixture(parser, fixture_dir)
        try:
            result = verify_clean(db)
            assert result["passed"], f"{parser.name} failed zero-PII: {result['findings'][:3]}"
        finally:
            db.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory() as d:
        src_db = Path(d) / "test.db"
        conn = sqlite3.connect(str(src_db))
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        conn.commit()
        conn.close()
        db = _run_parser_on_fixture(SqliteParser(), Path(d))
        try:
            result = verify_clean(db)
            assert result["passed"], f"generic/sqlite failed zero-PII: {result['findings'][:3]}"
        finally:
            db.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Audit #73 / #98 — the generic SQLite parser must open untrusted source DBs
# read-only + immutable (no source mutation, no -wal/-shm, no recovery) and
# must always close the source connection, even when the read raises
# DatabaseError on a corrupt/encrypted file.
# ---------------------------------------------------------------------------


def _spy_connect(monkeypatch):
    """Patch the sqlite3.connect used inside the parser to record every source
    (immutable) connection it opens, delegating to the real connect otherwise."""
    import icarus.parsers.generic.sqlite_parser as sp

    opened = []  # list of (target_str, kwargs, connection)
    real_connect = sqlite3.connect

    def spy(target, *args, **kwargs):
        conn = real_connect(target, *args, **kwargs)
        if isinstance(target, str) and "immutable=1" in target:
            opened.append((target, kwargs, conn))
        return conn

    monkeypatch.setattr(sp.sqlite3, "connect", spy)
    return opened


def test_sqlite_source_opened_read_only_immutable(monkeypatch):
    """#98: the untrusted source DB is opened via a read-only immutable URI."""
    from icarus.parsers.generic.sqlite_parser import SqliteParser

    with tempfile.TemporaryDirectory() as fixture:
        src = Path(fixture) / "data.db"
        c = sqlite3.connect(str(src))
        c.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY, v TEXT)")
        c.execute("INSERT INTO secrets(v) VALUES ('x')")
        c.commit()
        c.close()

        opened = _spy_connect(monkeypatch)
        out = Path(tempfile.mktemp(suffix=".db"))
        initialize_database(out, {"source": "test"})
        try:
            SqliteParser().extract_entities(Path(fixture), out)

            assert opened, "source DB was never opened"
            for target, kwargs, _conn in opened:
                assert "mode=ro" in target, f"source not read-only: {target}"
                assert "immutable=1" in target, f"source not immutable: {target}"
                assert kwargs.get("uri") is True, "connect must pass uri=True"

            conn = sqlite3.connect(str(out))
            props = conn.execute(
                "SELECT properties FROM observations WHERE event_type='schema_tables'"
            ).fetchall()
            conn.close()
            assert any("secrets" in p[0] for p in props), \
                "schema was not read from the read-only source"
        finally:
            out.unlink(missing_ok=True)


def test_sqlite_source_connection_closed_on_corrupt_db(monkeypatch):
    """#73: a corrupt/non-database .db raises DatabaseError mid-read; the source
    connection must still be closed (the old code leaked it)."""
    from icarus.parsers.generic.sqlite_parser import SqliteParser

    with tempfile.TemporaryDirectory() as fixture:
        # Not a SQLite file — the SELECT on sqlite_master raises DatabaseError.
        (Path(fixture) / "corrupt.db").write_bytes(b"not a database, just junk " * 8)

        opened = _spy_connect(monkeypatch)
        out = Path(tempfile.mktemp(suffix=".db"))
        initialize_database(out, {"source": "test"})
        try:
            # Must not raise despite the corrupt DB.
            SqliteParser().extract_entities(Path(fixture), out)

            assert opened, "source connection was never opened for the corrupt DB"
            for _target, _kwargs, conn in opened:
                # A live connection would answer SELECT 1; a closed one raises.
                with pytest.raises(sqlite3.ProgrammingError):
                    conn.execute("SELECT 1")

            # The file is still catalogued; only its schema observation is absent.
            conn = sqlite3.connect(str(out))
            files = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
            schema_obs = conn.execute(
                "SELECT COUNT(*) FROM observations WHERE event_type='schema_tables'"
            ).fetchone()[0]
            conn.close()
            assert files == 1
            assert schema_obs == 0
        finally:
            out.unlink(missing_ok=True)


def test_sqlite_no_sidecars_created_for_wal_source():
    """#98: cataloging a WAL-mode source DB leaves no -wal/-shm behind (immutable
    open never creates sidecars in the source tree)."""
    from icarus.parsers.generic.sqlite_parser import SqliteParser

    with tempfile.TemporaryDirectory() as fixture:
        src = Path(fixture) / "wal.db"
        c = sqlite3.connect(str(src))
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("CREATE TABLE creds (id INTEGER PRIMARY KEY, v TEXT)")
        c.execute("INSERT INTO creds(v) VALUES ('y')")
        c.commit()
        c.close()
        # Clean any sidecars left by the WAL writer so the assertion is precise.
        for sidecar in ("wal.db-wal", "wal.db-shm"):
            (Path(fixture) / sidecar).unlink(missing_ok=True)

        out = Path(tempfile.mktemp(suffix=".db"))
        initialize_database(out, {"source": "test"})
        try:
            SqliteParser().extract_entities(Path(fixture), out)

            leftovers = sorted(
                p.name for p in Path(fixture).iterdir()
                if p.name.startswith("wal.db-")
            )
            assert leftovers == [], f"immutable open created sidecars: {leftovers}"
        finally:
            out.unlink(missing_ok=True)


def test_sqlite_filename_cannot_inject_uri_params(monkeypatch):
    """#98: a source filename containing '?' must not inject SQLite URI query
    parameters (e.g. mode=rwc) — the path is percent-encoded."""
    from icarus.parsers.generic.sqlite_parser import SqliteParser

    with tempfile.TemporaryDirectory() as fixture:
        hostile = Path(fixture) / "evil?mode=rwc.db"
        try:
            c = sqlite3.connect(str(hostile))
            c.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            c.commit()
            c.close()
        except (OSError, sqlite3.OperationalError):
            pytest.skip("filesystem does not allow '?' in filenames")

        opened = _spy_connect(monkeypatch)
        out = Path(tempfile.mktemp(suffix=".db"))
        initialize_database(out, {"source": "test"})
        try:
            SqliteParser().extract_entities(Path(fixture), out)
            assert opened, "hostile source DB was never opened"
            target = opened[0][0]
            # The literal '?' from the name is encoded, so the only query string
            # is our own read-only one — the injected mode=rwc cannot take effect.
            assert "%3F" in target, f"filename '?' was not encoded: {target}"
            assert target.endswith("?mode=ro&immutable=1"), \
                f"injected query params present: {target}"
            assert "mode=rwc" not in target.split("?", 1)[1]
        finally:
            out.unlink(missing_ok=True)
