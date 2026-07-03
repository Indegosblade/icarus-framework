"""Tests for the network parsers — privacy_stack and deploy_scripts."""

import json
import sqlite3
import time
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


# ---------------------------------------------------------------------------
# Audit #103 — the deploy_scripts DOTALL regexes must not backtrack to EOF on
# attacker-controlled scripts (quadratic ReDoS). The span caps + pre-cap keep
# the sweep bounded regardless of missing terminators.
# ---------------------------------------------------------------------------

# Wall-clock ceiling for the bounded sweep. On the audited (unbounded) patterns
# the pathological input below took ~30s; the bounded patterns finish in well
# under a second, so this generous bound still fails loudly on a regression.
_PROMPT_SECONDS = 8.0


def _analyze(payload):
    from icarus.parsers.network.deploy_scripts import DeployScriptsParser

    found = set()
    observations = []
    entitlements = []
    start = time.perf_counter()
    DeployScriptsParser._analyze_script(
        payload, "evil.py", found, observations, entitlements
    )
    return time.perf_counter() - start, found, observations, entitlements


def test_deploy_scripts_many_connects_no_kwargs_is_prompt():
    """Missing username=/password= sentinels used to make the DOTALL `.*?`
    groups scan to end-of-file on every one of thousands of .connect() calls."""
    payload = "import paramiko\n" + "conn.connect('10.0.0.1')\n" * 12000
    elapsed, _found, observations, _ents = _analyze(payload)

    assert elapsed < _PROMPT_SECONDS, \
        f"connect() sweep took {elapsed:.1f}s — quadratic backtracking not fixed"
    ssh = [o for o in observations if o[1] == "ssh_connection"]
    assert len(ssh) == 12000, "bounded pattern lost correctness under load"


def test_deploy_scripts_unterminated_exec_is_prompt():
    """exec_command string with no closing quote — the old `(.+?)` + re.S ran to
    EOF; the bounded [^'\"]{1,500} cannot backtrack past its cap."""
    payload = "import paramiko\nssh.exec_command('" + ("A" * 900_000)
    elapsed, _found, observations, _ents = _analyze(payload)

    assert elapsed < _PROMPT_SECONDS, \
        f"unterminated command sweep took {elapsed:.1f}s"
    # No closing quote within the cap → no command is captured.
    assert not any(o[1] == "remote_command" for o in observations)


def test_deploy_scripts_analysis_text_is_pre_capped():
    """Content past MAX_SCRIPT_ANALYZE_BYTES is not scanned, so an adversary
    cannot force work proportional to a multi-megabyte padded script."""
    from icarus.parsers.network.deploy_scripts import MAX_SCRIPT_ANALYZE_BYTES

    filler = "x = 1\n" * ((MAX_SCRIPT_ANALYZE_BYTES // 6) + 5000)
    assert len(filler) > MAX_SCRIPT_ANALYZE_BYTES
    payload = "import paramiko\n" + filler + "conn.connect('9.9.9.9')\n"
    elapsed, _found, observations, _ents = _analyze(payload)

    assert elapsed < _PROMPT_SECONDS
    # The connect() lives beyond the analyzed window, so it is never seen.
    assert not any(
        o[1] == "ssh_connection" and "9.9.9.9" in o[2] for o in observations
    )


def test_deploy_scripts_normal_extraction_preserved():
    """The bounded patterns still extract a well-formed script correctly."""
    script = (
        "import paramiko\n"
        "c = paramiko.SSHClient()\n"
        "c.connect('192.168.88.8', username='root', "
        "password='KHE718', timeout=10)\n"
        "_, o, e = c.exec_command('systemctl restart pihole-FTL')\n"
    )
    _elapsed, found, observations, _ents = _analyze(script)

    kinds = {o[1] for o in observations}
    assert "ssh_connection" in kinds
    assert "remote_command" in kinds
    assert "service_management" in kinds
    assert "pihole-FTL" in found

    ssh = [json.loads(o[2]) for o in observations if o[1] == "ssh_connection"]
    assert ssh[0]["host"] == "192.168.88.8"
    assert ssh[0]["user"] == "root"
    assert ssh[0]["has_password"] is True

    cmds = [json.loads(o[2])["command"] for o in observations
            if o[1] == "remote_command"]
    assert "systemctl restart pihole-FTL" in cmds
