"""Tests for Phase 3.6 — STIX 2.1 export."""

import json
import re
import sqlite3
import tempfile
from pathlib import Path

from icarus.core.schema import initialize_database
from icarus.integrations.stix_export import _entity_ref, diff_to_stix, export_to_stix

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "windows"

# RFC 3339 UTC timestamp ending in 'Z', as STIX 2.1 requires for created/modified.
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")

# STIX 2.1 identifier: <type>--<uuid>
STIX_ID_RE = re.compile(
    r"^[a-z0-9][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def _build_db():
    """Build a small ICARUS database from windows fixtures for STIX testing."""
    from icarus.parsers.windows import WindowsParser

    db_path = Path(tempfile.mktemp(suffix=".db"))
    initialize_database(db_path, {"source": "test"})
    WindowsParser().extract_entities(FIXTURES_DIR, db_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT OR IGNORE INTO daemons (label, plist_path, program, user_name) "
        "VALUES (?, ?, ?, ?)",
        ("test-daemon", "/Library/LaunchDaemons/test.plist", "/usr/bin/testd", "root"),
    )
    conn.commit()
    conn.close()
    return db_path


def test_stix_export_produces_bundle():
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        bundle = export_to_stix(db, out)
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        assert len(bundle["objects"]) > 0
        on_disk = json.loads(out.read_text())
        assert on_disk["type"] == "bundle"
        assert on_disk["objects"] == bundle["objects"]
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_files_map_to_sco():
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        bundle = export_to_stix(db, out, include_tables=["files"])
        file_objects = [o for o in bundle["objects"] if o["type"] == "file"]
        assert len(file_objects) > 0
        for obj in file_objects:
            assert obj["id"].startswith("file--")
            assert obj["spec_version"] == "2.1"
            assert "name" in obj
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_daemons_map_to_infrastructure():
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        bundle = export_to_stix(db, out, include_tables=["daemons"])
        infra = [o for o in bundle["objects"] if o["type"] == "infrastructure"]
        assert len(infra) == 1
        assert infra[0]["name"] == "test-daemon"
        assert infra[0]["id"].startswith("infrastructure--")
        assert infra[0]["spec_version"] == "2.1"
        assert "hosting-target" in infra[0]["infrastructure_types"]
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_diff_export():
    db_old = _build_db()
    db_new = _build_db()
    conn = sqlite3.connect(str(db_new))
    conn.execute(
        "INSERT OR IGNORE INTO daemons (label, plist_path, program, user_name) "
        "VALUES (?, ?, ?, ?)",
        ("new-daemon", "/Library/LaunchDaemons/new.plist", "/usr/bin/newd", "nobody"),
    )
    conn.commit()
    conn.close()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        bundle = diff_to_stix(db_old, db_new, out)
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        on_disk = json.loads(out.read_text())
        assert on_disk["type"] == "bundle"

        # Finding #58/#163: the bundle must contain a real note object for
        # the added daemon (not just an envelope with no content).
        notes = [o for o in bundle["objects"] if o["type"] == "note"]
        assert notes, "diff_to_stix produced no note objects for an added daemon"

        added_daemon_notes = [
            n for n in notes
            if n.get("x_icarus_diff_category") == "addition"
            and n.get("x_icarus_diff_table") == "daemons_added"
        ]
        assert len(added_daemon_notes) == 1
        assert "new-daemon" in added_daemon_notes[0]["content"]
        # item must be indexed by key_column (label), not the stringified dict.
        assert "{" not in added_daemon_notes[0]["content"]
    finally:
        db_old.unlink(missing_ok=True)
        db_new.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_diff_export_includes_structural_change():
    """Finding #58/#163: diff_to_stix must not silently drop structural changes."""
    db_old = _build_db()
    db_new = _build_db()

    # Give the same (unique) executable_name a different owning file_id in
    # old vs. new — this is exactly what IcarusDiffer.structural_diff()'s
    # binary_file_moved case detects.
    conn_old = sqlite3.connect(str(db_old))
    conn_old.execute(
        "INSERT INTO files (path, filename, extension, size, file_type) "
        "VALUES (?, ?, ?, ?, ?)",
        ("/synthetic/old/_filler.bin", "_filler.bin", ".bin", 1, "data"),
    )
    conn_old.execute(
        "INSERT INTO files (path, filename, extension, size, file_type) "
        "VALUES (?, ?, ?, ?, ?)",
        ("/synthetic/old/zzz_structural_probe.exe", "zzz_structural_probe.exe",
         ".exe", 10, "binary"),
    )
    old_file_id = conn_old.execute(
        "SELECT id FROM files WHERE path=?",
        ("/synthetic/old/zzz_structural_probe.exe",),
    ).fetchone()[0]
    conn_old.execute(
        "INSERT INTO binaries (file_id, executable_name, arch) VALUES (?, ?, ?)",
        (old_file_id, "zzz_structural_probe.exe", "x86_64"),
    )
    conn_old.commit()
    conn_old.close()

    conn_new = sqlite3.connect(str(db_new))
    conn_new.execute(
        "INSERT INTO files (path, filename, extension, size, file_type) "
        "VALUES (?, ?, ?, ?, ?)",
        ("/synthetic/new/zzz_structural_probe.exe", "zzz_structural_probe.exe",
         ".exe", 10, "binary"),
    )
    new_file_id = conn_new.execute(
        "SELECT id FROM files WHERE path=?",
        ("/synthetic/new/zzz_structural_probe.exe",),
    ).fetchone()[0]
    conn_new.execute(
        "INSERT INTO binaries (file_id, executable_name, arch) VALUES (?, ?, ?)",
        (new_file_id, "zzz_structural_probe.exe", "x86_64"),
    )
    conn_new.commit()
    conn_new.close()

    assert old_file_id != new_file_id, "test setup must give the binary distinct file_ids"

    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        bundle = diff_to_stix(db_old, db_new, out)
        structural_notes = [
            o for o in bundle["objects"]
            if o["type"] == "note" and o.get("x_icarus_diff_category") == "structural"
        ]
        assert len(structural_notes) == 1
        assert "zzz_structural_probe.exe" in structural_notes[0]["content"]
        assert structural_notes[0]["x_icarus_diff_table"] == "structural"
    finally:
        db_old.unlink(missing_ok=True)
        db_new.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_bundle_has_spec_version():
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        bundle = export_to_stix(db, out)
        assert bundle["spec_version"] == "2.1"
        for obj in bundle["objects"]:
            assert obj["spec_version"] == "2.1"
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_daemon_sdo_has_created_and_modified():
    """Finding #53: STIX 2.1 requires created/modified on every SDO."""
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        bundle = export_to_stix(db, out, include_tables=["daemons"])
        infra = [o for o in bundle["objects"] if o["type"] == "infrastructure"]
        assert len(infra) == 1
        assert TIMESTAMP_RE.match(infra[0].get("created", "")), infra[0].get("created")
        assert TIMESTAMP_RE.match(infra[0].get("modified", "")), infra[0].get("modified")
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_entitlement_sdo_has_created_and_modified():
    """Finding #53: STIX 2.1 requires created/modified on every SDO."""
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        conn = sqlite3.connect(str(db))
        binary_id = conn.execute("SELECT id FROM binaries LIMIT 1").fetchone()[0]
        conn.execute(
            "INSERT INTO entitlements (binary_id, key, value) VALUES (?, ?, ?)",
            (binary_id, "com.apple.security.test", "true"),
        )
        conn.commit()
        conn.close()

        bundle = export_to_stix(db, out, include_tables=["entitlements"])
        coa = [o for o in bundle["objects"] if o["type"] == "course-of-action"]
        assert len(coa) == 1
        assert TIMESTAMP_RE.match(coa[0].get("created", "")), coa[0].get("created")
        assert TIMESTAMP_RE.match(coa[0].get("modified", "")), coa[0].get("modified")
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_observed_data_has_created_modified_and_object_refs():
    """Finding #53: observed-data must carry created/modified and a valid
    object_refs pointing at the referenced SCO/SDO."""
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        conn = sqlite3.connect(str(db))
        daemon_id = conn.execute(
            "SELECT id FROM daemons WHERE label=?", ("test-daemon",)
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO observations "
            "(entity_table, entity_id, observed_at, event_type) "
            "VALUES (?, ?, datetime('now'), ?)",
            ("daemons", daemon_id, "daemon_registered"),
        )
        conn.commit()
        conn.close()

        bundle = export_to_stix(db, out, include_tables=["observations"])
        observed = [o for o in bundle["objects"] if o["type"] == "observed-data"]
        assert len(observed) == 1
        obj = observed[0]

        assert TIMESTAMP_RE.match(obj.get("created", "")), obj.get("created")
        assert TIMESTAMP_RE.match(obj.get("modified", "")), obj.get("modified")

        assert "object_refs" in obj
        assert obj["object_refs"], "object_refs must not be empty"
        for ref in obj["object_refs"]:
            assert STIX_ID_RE.match(ref), ref
        # Must point at the daemon this observation is actually about.
        assert obj["object_refs"] == [_entity_ref("daemons", daemon_id)]
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)
