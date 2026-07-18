"""Regression: structural_diff() must key on natural identifiers, not local
autoincrement foreign-key ids.

file_id / profile_id / binary_id are assigned independently in each database, so
comparing them across two databases fabricates "moved" rows from mere insertion-order
skew and can hide real moves when ids coincide. These tests pin the natural-key
behavior: an insertion-order difference is not a move, and a real path change is.
"""
import sqlite3
from pathlib import Path

from icarus.core.differ import IcarusDiffer
from icarus.core.schema import initialize_database


def _insert_min(conn, table, values):
    """INSERT filling any other NOT NULL non-pk column with a typed dummy."""
    info = conn.execute(f"PRAGMA table_info({table})").fetchall()
    data = dict(values)
    for _cid, name, typ, notnull, dflt, pk in info:
        if name in data or pk:
            continue
        if notnull and dflt is None:
            data[name] = 0 if "INT" in (typ or "").upper() else ""
    keys = list(data.keys())
    placeholders = ",".join(["?"] * len(keys))
    conn.execute(
        f"INSERT INTO {table} ({','.join(keys)}) VALUES ({placeholders})",
        [data[k] for k in keys],
    )


def _build(db_path, foo_path, decoy=False):
    initialize_database(Path(db_path))
    conn = sqlite3.connect(str(db_path))
    try:
        if decoy:
            _insert_min(conn, "files", {"path": "/decoy/aaa"})  # shifts foo's file_id
        _insert_min(conn, "files", {"path": foo_path})
        fid = conn.execute("SELECT id FROM files WHERE path=?", (foo_path,)).fetchone()[0]
        _insert_min(conn, "binaries", {"executable_name": "foo", "file_id": fid})
        conn.commit()
    finally:
        conn.close()


def test_insertion_order_skew_is_not_a_move(tmp_path):
    old, new = tmp_path / "old.db", tmp_path / "new.db"
    # Identical logical mapping foo -> /bin/foo in both; NEW inserts a decoy first so
    # foo's file_id differs (1 vs 2). This must NOT be reported as a move.
    _build(str(old), "/bin/foo", decoy=False)
    _build(str(new), "/bin/foo", decoy=True)
    with IcarusDiffer(str(old), str(new)) as d:
        res = d.structural_diff()
    assert res.structural == [], f"insertion-order skew fabricated moves: {res.structural}"


def test_genuine_file_move_is_detected(tmp_path):
    old, new = tmp_path / "old.db", tmp_path / "new.db"
    _build(str(old), "/bin/foo")
    _build(str(new), "/usr/bin/foo")  # binary 'foo' genuinely moved to a new path
    with IcarusDiffer(str(old), str(new)) as d:
        res = d.structural_diff()
    moves = [c for c in res.structural if c["type"] == "binary_file_moved"]
    assert len(moves) == 1, f"expected exactly one real move, got {res.structural}"
    assert moves[0]["old_value"] == "/bin/foo"
    assert moves[0]["new_value"] == "/usr/bin/foo"
