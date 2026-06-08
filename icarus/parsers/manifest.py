"""ICARUS Parser Manifest — declarative metadata for parser modules."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

try:
    import jsonschema
except ImportError:
    jsonschema = None

_SCHEMA_PATH = Path(__file__).parent / "schema" / "parser_manifest.schema.json"
_SCHEMA = None


def _get_schema() -> dict:
    global _SCHEMA
    if _SCHEMA is None:
        _SCHEMA = json.loads(_SCHEMA_PATH.read_text())
    return _SCHEMA


@dataclass
class ParserManifest:
    parser_id: str
    version: str
    spec_version: str
    author: str
    license: str
    quality_tier: str
    description: str
    identify: Dict[str, Any]
    consumes: List[str]
    produces: Dict[str, Any]
    reliability: str
    default_confidence: float
    dependencies: Dict[str, Any] = field(default_factory=dict)
    tests: Optional[Dict[str, Any]] = None

    @property
    def specificity_level(self) -> int:
        return self.identify.get("specificity_level", 50)

    @property
    def confidence(self) -> float:
        return self.identify.get("confidence", self.default_confidence)

    @property
    def entity_types(self) -> List[str]:
        return self.produces.get("entity_types", [])


def load_manifest(path: Path) -> ParserManifest:
    """Load a parser manifest from a YAML file. Validates against JSON Schema."""
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError(f"Manifest must be a YAML mapping, got {type(raw).__name__}")
    validate_manifest_data(raw)
    return ParserManifest(
        parser_id=raw["parser_id"],
        version=raw["version"],
        spec_version=raw["spec_version"],
        author=raw["author"],
        license=raw["license"],
        quality_tier=raw["quality_tier"],
        description=raw["description"],
        identify=raw["identify"],
        consumes=raw["consumes"],
        produces=raw["produces"],
        reliability=raw["reliability"],
        default_confidence=raw["default_confidence"],
        dependencies=raw.get("dependencies", {}),
        tests=raw.get("tests"),
    )


def validate_manifest(path: Path) -> None:
    """Validate a manifest file against the JSON Schema. Raises on failure."""
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError(f"Manifest must be a YAML mapping, got {type(raw).__name__}")
    validate_manifest_data(raw)


def validate_manifest_data(data: dict) -> None:
    """Validate manifest data dict against the JSON Schema. Raises on failure."""
    if jsonschema is None:
        raise ImportError("jsonschema is required for manifest validation: pip install jsonschema")
    schema = _get_schema()
    jsonschema.validate(instance=data, schema=schema)
