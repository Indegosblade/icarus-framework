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


def _add_binary(conn, *, path, name, bundle_id=None, sha256=None, decoys=0):
    """Insert a file + owning binary; optional decoy files to shift local ids."""
    for i in range(decoys):
        _insert_min(conn, "files", {"path": f"{path}.decoy{i}"})
    _insert_min(conn, "files", {"path": path, "sha256": sha256})
    fid = conn.execute("SELECT id FROM files WHERE path=?", (path,)).fetchone()[0]
    _insert_min(conn, "binaries",
                {"executable_name": name, "file_id": fid, "bundle_id": bundle_id})
    return conn.execute("SELECT id FROM binaries WHERE file_id=?", (fid,)).fetchone()[0]


def test_entitlement_path_move_with_same_owner_is_not_a_reassignment(tmp_path):
    """A binary that moves paths but keeps its identity (bundle_id) and its
    entitlement must produce a binary_file_moved row and NOT a spurious
    entitlement_reassigned row."""
    old, new = tmp_path / "old.db", tmp_path / "new.db"
    for p, db, decoys in [("/A/foo", str(old), 0), ("/B/foo", str(new), 1)]:
        initialize_database(Path(db))
        conn = sqlite3.connect(db)
        try:
            bid = _add_binary(conn, path=p, name="foo",
                              bundle_id="com.example.foo", decoys=decoys)
            _insert_min(conn, "entitlements",
                        {"binary_id": bid, "key": "com.apple.security.cs", "value": "true"})
            conn.commit()
        finally:
            conn.close()
    with IcarusDiffer(str(old), str(new)) as d:
        res = d.structural_diff()
    types = [c["type"] for c in res.structural]
    assert "binary_file_moved" in types, res.structural
    assert "entitlement_reassigned" not in types, (
        f"path move with same owner fabricated a reassignment: {res.structural}")


def test_genuine_entitlement_reassignment_is_detected(tmp_path):
    """An entitlement that genuinely moves from one binary to a different binary
    (distinct bundle_id) must be reported as entitlement_reassigned."""
    old, new = tmp_path / "old.db", tmp_path / "new.db"
    KEY, VAL = "com.apple.private.tcc", "granted"

    initialize_database(Path(old))
    conn = sqlite3.connect(str(old))
    try:
        a = _add_binary(conn, path="/bin/a", name="a", bundle_id="com.a")
        _add_binary(conn, path="/bin/b", name="b", bundle_id="com.b")
        _insert_min(conn, "entitlements", {"binary_id": a, "key": KEY, "value": VAL})
        conn.commit()
    finally:
        conn.close()

    initialize_database(Path(new))
    conn = sqlite3.connect(str(new))
    try:
        _add_binary(conn, path="/bin/a", name="a", bundle_id="com.a")
        b = _add_binary(conn, path="/bin/b", name="b", bundle_id="com.b")
        _insert_min(conn, "entitlements", {"binary_id": b, "key": KEY, "value": VAL})
        conn.commit()
    finally:
        conn.close()

    with IcarusDiffer(str(old), str(new)) as d:
        res = d.structural_diff()
    reassigned = [c for c in res.structural if c["type"] == "entitlement_reassigned"]
    assert len(reassigned) == 1, f"expected one reassignment, got {res.structural}"
    assert reassigned[0]["old_value"] == "com.a"
    assert reassigned[0]["new_value"] == "com.b"


def _add_observation(conn, entity_table, entity_id, event_type, observed_at):
    _insert_min(conn, "observations", {
        "entity_table": entity_table, "entity_id": entity_id,
        "event_type": event_type, "observed_at": observed_at,
    })


def test_observation_diff_insertion_order_skew_is_not_a_change(tmp_path):
    """The same logical observations, on files inserted in a different order (so
    their local file ids differ), must diff to no change."""
    old, new = tmp_path / "old.db", tmp_path / "new.db"

    initialize_database(Path(old))
    conn = sqlite3.connect(str(old))
    try:
        for p in ("/bin/a", "/bin/b"):  # a=1, b=2
            _insert_min(conn, "files", {"path": p})
        for p, ev in (("/bin/a", "seen"), ("/bin/b", "seen")):
            fid = conn.execute("SELECT id FROM files WHERE path=?", (p,)).fetchone()[0]
            _add_observation(conn, "files", fid, ev, "2026-01-01T00:00:00Z")
        conn.commit()
    finally:
        conn.close()

    initialize_database(Path(new))
    conn = sqlite3.connect(str(new))
    try:
        for p in ("/bin/b", "/bin/a"):  # reversed: b=1, a=2 -> ids swapped
            _insert_min(conn, "files", {"path": p})
        for p, ev in (("/bin/a", "seen"), ("/bin/b", "seen")):
            fid = conn.execute("SELECT id FROM files WHERE path=?", (p,)).fetchone()[0]
            _add_observation(conn, "files", fid, ev, "2026-01-01T00:00:00Z")
        conn.commit()
    finally:
        conn.close()

    with IcarusDiffer(str(old), str(new)) as d:
        res = d.observation_diff()
    assert res.added == [] and res.removed == [], (
        f"insertion-order skew fabricated observation changes: "
        f"added={res.added} removed={res.removed}")


def test_observation_diff_detects_genuine_new_observation(tmp_path):
    """A genuinely new observation (by natural key) is reported as added."""
    old, new = tmp_path / "old.db", tmp_path / "new.db"
    for db, extra in [(str(old), False), (str(new), True)]:
        initialize_database(Path(db))
        conn = sqlite3.connect(db)
        try:
            _insert_min(conn, "files", {"path": "/bin/a"})
            fid = conn.execute("SELECT id FROM files WHERE path=?", ("/bin/a",)).fetchone()[0]
            _add_observation(conn, "files", fid, "seen", "2026-01-01T00:00:00Z")
            if extra:
                _add_observation(conn, "files", fid, "exec", "2026-02-02T00:00:00Z")
            conn.commit()
        finally:
            conn.close()
    with IcarusDiffer(str(old), str(new)) as d:
        res = d.observation_diff()
    assert res.removed == [], res.removed
    assert len(res.added) == 1, res.added
    assert res.added[0]["entity_key"] == "/bin/a"
    assert res.added[0]["event_type"] == "exec"


def test_structural_diff_randomized_insertion_order_is_stable(tmp_path):
    """Identical logical content inserted in a shuffled order must never
    fabricate structural changes, regardless of the resulting local ids."""
    import random
    rng = random.Random(1337)
    entities = [(f"/app/bin{i}", f"bin{i}", f"com.example.bin{i}") for i in range(8)]

    def build(db_path, order):
        initialize_database(Path(db_path))
        conn = sqlite3.connect(str(db_path))
        try:
            for path, name, bundle in order:
                bid = _add_binary(conn, path=path, name=name, bundle_id=bundle)
                _insert_min(conn, "entitlements",
                            {"binary_id": bid, "key": "k", "value": name})
            conn.commit()
        finally:
            conn.close()

    order_a = list(entities)
    order_b = list(entities)
    rng.shuffle(order_b)
    build(str(tmp_path / "old.db"), order_a)
    build(str(tmp_path / "new.db"), order_b)
    with IcarusDiffer(str(tmp_path / "old.db"), str(tmp_path / "new.db")) as d:
        res = d.structural_diff()
    assert res.structural == [], f"shuffled insertion order fabricated: {res.structural}"
