"""Tests for Phase 3.1 — Parser manifest format."""

import tempfile
from pathlib import Path

import pytest
import yaml

PARSERS_DIR = Path(__file__).parent.parent / "icarus" / "parsers"


def test_manifest_schema_valid():
    """Windows and linux manifests pass JSON Schema validation."""
    from icarus.parsers.manifest import validate_manifest

    validate_manifest(PARSERS_DIR / "windows.yaml")
    validate_manifest(PARSERS_DIR / "linux.yaml")


def test_manifest_load():
    """ParserManifest loads correctly from YAML."""
    from icarus.parsers.manifest import load_manifest

    m = load_manifest(PARSERS_DIR / "windows.yaml")
    assert m.parser_id == "windows"
    assert m.version == "1.0.0"
    assert m.spec_version == "icarus-parser/1.0"
    assert m.quality_tier == "production"
    assert m.specificity_level == 20
    assert m.confidence == 0.85
    assert "files" in m.entity_types
    assert "binaries" in m.entity_types

    m2 = load_manifest(PARSERS_DIR / "linux.yaml")
    assert m2.parser_id == "linux"
    assert "daemons" in m2.entity_types
    assert m2.dependencies.get("tools") == ["readelf"]


def test_manifest_invalid_raises():
    """Missing required field raises on load."""
    from icarus.parsers.manifest import validate_manifest

    bad = {
        "parser_id": "test",
        "version": "1.0.0",
    }
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
        yaml.dump(bad, f)
        bad_path = Path(f.name)

    try:
        with pytest.raises(Exception):
            validate_manifest(bad_path)
    finally:
        bad_path.unlink(missing_ok=True)


def test_manifest_quality_tiers():
    """All four tier values accepted, others rejected."""
    from icarus.parsers.manifest import validate_manifest_data

    base = {
        "parser_id": "test",
        "version": "1.0.0",
        "spec_version": "icarus-parser/1.0",
        "author": "test",
        "license": "MIT",
        "description": "test parser",
        "identify": {"specificity_level": 50},
        "consumes": ["application/json"],
        "produces": {"entity_types": ["files"]},
        "reliability": "C",
        "default_confidence": 0.5,
    }

    for tier in ("production", "candidate", "prototype", "private"):
        data = {**base, "quality_tier": tier}
        validate_manifest_data(data)

    with pytest.raises(Exception):
        validate_manifest_data({**base, "quality_tier": "invalid"})


def test_manifest_specificity_range():
    """specificity_level must be 1-100."""
    from icarus.parsers.manifest import validate_manifest_data

    base = {
        "parser_id": "test",
        "version": "1.0.0",
        "spec_version": "icarus-parser/1.0",
        "author": "test",
        "license": "MIT",
        "quality_tier": "prototype",
        "description": "test parser",
        "consumes": ["application/json"],
        "produces": {"entity_types": ["files"]},
        "reliability": "C",
        "default_confidence": 0.5,
    }

    validate_manifest_data({**base, "identify": {"specificity_level": 1}})
    validate_manifest_data({**base, "identify": {"specificity_level": 100}})

    with pytest.raises(Exception):
        validate_manifest_data({**base, "identify": {"specificity_level": 0}})

    with pytest.raises(Exception):
        validate_manifest_data({**base, "identify": {"specificity_level": 101}})
