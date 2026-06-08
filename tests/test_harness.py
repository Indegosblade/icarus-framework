"""Tests for Phase 3.3 — Parser testing harness."""

import tempfile
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PARSERS_DIR = Path(__file__).parent.parent / "icarus" / "parsers"


def _load_windows_harness():
    from icarus.parsers.manifest import load_manifest
    from icarus.parsers.testing import ParserTestHarness
    from icarus.parsers.windows import WindowsParser

    manifest = load_manifest(PARSERS_DIR / "windows.yaml")
    return ParserTestHarness(WindowsParser(), manifest, FIXTURES_DIR / "windows")


def test_harness_golden_windows():
    harness = _load_windows_harness()
    result = harness.test_golden_output()
    assert result.passed, f"Golden output failed: {result.message}"


def test_harness_idempotency_windows():
    harness = _load_windows_harness()
    result = harness.test_idempotency()
    assert result.passed, f"Idempotency failed: {result.message}"


def test_harness_zero_pii_windows():
    harness = _load_windows_harness()
    result = harness.test_zero_pii()
    assert result.passed, f"Zero PII failed: {result.message}"


def test_harness_schema_conformance():
    harness = _load_windows_harness()
    result = harness.test_schema_conformance()
    assert result.passed, f"Schema conformance failed: {result.message}"


def test_harness_fixture_missing_raises():
    from icarus.parsers.manifest import load_manifest
    from icarus.parsers.testing import ParserTestHarness
    from icarus.parsers.windows import WindowsParser

    manifest = load_manifest(PARSERS_DIR / "windows.yaml")
    with pytest.raises(FileNotFoundError):
        ParserTestHarness(WindowsParser(), manifest, Path(tempfile.mkdtemp()) / "nonexistent")
