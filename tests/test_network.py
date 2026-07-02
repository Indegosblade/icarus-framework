"""Tests for the network parsers — privacy_stack and deploy_scripts."""

import sqlite3
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PARSERS_DIR = Path(__file__).parent.parent / "icarus" / "parsers"

GATES = ["test_golden_output", "test_schema_conformance", "test_idempotency", "test_zero_pii"]


def _harness(parser, manifest_rel, fixture_name):
    from icarus.parsers.manifest import load_manifest
    from icarus.parsers.testing import ParserTestHarness

    manifest = load_manifest(PARSERS_DIR / manifest_rel)
    return ParserTestHarness(parser, manifest, FIXTURES_DIR / fixture_name)


def _privacy_harness():
    from icarus.parsers.network.privacy_stack import PrivacyStackParser

    return _harness(PrivacyStackParser(), "network/privacy_stack.yaml", "network_privacy_stack")


def _deploy_harness():
    from icarus.parsers.network.deploy_scripts import DeployScriptsParser

    return _harness(DeployScriptsParser(), "network/deploy_scripts.yaml", "network_deploy_scripts")


@pytest.mark.parametrize("gate", GATES)
def test_privacy_stack_harness(gate):
    result = getattr(_privacy_harness(), gate)()
    assert result.passed, f"{gate} failed: {result.message}"


@pytest.mark.parametrize("gate", GATES)
def test_deploy_scripts_harness(gate):
    result = getattr(_deploy_harness(), gate)()
    assert result.passed, f"{gate} failed: {result.message}"


def test_privacy_stack_detects_fixture():
    from icarus.parsers import detect_parser

    assert detect_parser(FIXTURES_DIR / "network_privacy_stack") == "network/privacy_stack"


def test_deploy_scripts_detects_fixture():
    from icarus.parsers import detect_parser

    assert detect_parser(FIXTURES_DIR / "network_deploy_scripts") == "network/deploy_scripts"


def test_root_level_files_are_catalogued(tmp_path):
    """Regression: files directly in the source root must not be skipped.

    Previously rel_dir for the root resolved to '.', which the hidden-path
    check treated as a dotfile and dropped every root-level file.
    """
    from icarus.core.schema import initialize_database
    from icarus.parsers.network.deploy_scripts import DeployScriptsParser

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("import paramiko\n")
    (src / "b.py").write_text("import paramiko\n")
    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(src)})
    DeployScriptsParser().extract_entities(src, db)

    conn = sqlite3.connect(str(db))
    try:
        n = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    finally:
        conn.close()
    assert n == 2, "root-level files were skipped"
