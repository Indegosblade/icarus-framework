"""Tests for Phase 3.6 — STIX 2.1 export."""

import json
import sqlite3
import tempfile
from pathlib import Path

from icarus.core.schema import initialize_database
from icarus.integrations.stix_export import diff_to_stix, export_to_stix

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "windows"


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
