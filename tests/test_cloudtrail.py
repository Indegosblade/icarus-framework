"""Tests for Phase 3.5 — CloudTrail parser."""

import sqlite3
import tempfile
from pathlib import Path

from icarus.core.schema import initialize_database

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "cloud_aws_cloudtrail"
PARSERS_DIR = Path(__file__).parent.parent / "icarus" / "parsers"


def _run_cloudtrail():
    from icarus.parsers.cloud.cloudtrail import CloudTrailParser
    db_path = Path(tempfile.mktemp(suffix=".db"))
    initialize_database(db_path, {"source": "test"})
    CloudTrailParser().extract_entities(FIXTURES_DIR, db_path)
    return db_path


def test_cloudtrail_identifies():
    from icarus.parsers.cloud.cloudtrail import CloudTrailParser
    assert CloudTrailParser().identify(FIXTURES_DIR)
    with tempfile.TemporaryDirectory() as empty:
        assert not CloudTrailParser().identify(Path(empty))


def test_cloudtrail_extracts_identities():
    db = _run_cloudtrail()
    try:
        conn = sqlite3.connect(str(db))
        daemons = conn.execute("SELECT label FROM daemons ORDER BY label").fetchall()
        arns = [d[0] for d in daemons]
        assert any("test-admin" in a for a in arns)
        assert any("test-readonly" in a for a in arns)
        assert any("root" in a for a in arns)
        assert len(daemons) == 4
        conn.close()
    finally:
        db.unlink(missing_ok=True)


def test_cloudtrail_extracts_observations():
    db = _run_cloudtrail()
    try:
        conn = sqlite3.connect(str(db))
        obs_count = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
        assert obs_count == 6
        conn.close()
    finally:
        db.unlink(missing_ok=True)


def test_cloudtrail_observation_event_type():
    db = _run_cloudtrail()
    try:
        conn = sqlite3.connect(str(db))
        events = conn.execute(
            "SELECT DISTINCT event_type FROM observations"
        ).fetchall()
        event_names = {e[0] for e in events}
        assert "DescribeInstances" in event_names
        assert "ConsoleLogin" in event_names
        assert "CreateUser" in event_names
        conn.close()
    finally:
        db.unlink(missing_ok=True)


def test_cloudtrail_zero_pii():
    from icarus.integrations.hygeia import verify_clean
    db = _run_cloudtrail()
    try:
        result = verify_clean(db)
        assert result["passed"], f"PII found: {result['findings'][:3]}"
    finally:
        db.unlink(missing_ok=True)


def test_cloudtrail_idempotency():
    from icarus.parsers.cloud.cloudtrail import CloudTrailParser
    db = _run_cloudtrail()
    try:
        conn = sqlite3.connect(str(db))
        daemons_first = conn.execute("SELECT COUNT(*) FROM daemons").fetchone()[0]
        conn.close()

        CloudTrailParser().extract_entities(FIXTURES_DIR, db)

        conn = sqlite3.connect(str(db))
        daemons_second = conn.execute("SELECT COUNT(*) FROM daemons").fetchone()[0]
        conn.close()
        assert daemons_first == daemons_second
    finally:
        db.unlink(missing_ok=True)


def test_cloudtrail_harness_all_pass():
    from icarus.parsers.cloud.cloudtrail import CloudTrailParser
    from icarus.parsers.manifest import load_manifest
    from icarus.parsers.testing import ParserTestHarness

    manifest = load_manifest(PARSERS_DIR / "cloud" / "cloudtrail.yaml")
    harness = ParserTestHarness(CloudTrailParser(), manifest, FIXTURES_DIR)
    results = harness.run_all()
    for r in results:
        assert r.passed, f"{r.test_name} failed: {r.message}"
