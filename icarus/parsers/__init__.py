"""ICARUS parsers — pluggable data source modules."""

from pathlib import Path
from typing import Optional

from icarus.core.registry import ParserRegistry
from icarus.parsers.base import BaseParser
from icarus.parsers.manifest import load_manifest

_REGISTRY = ParserRegistry()
_PARSERS_DIR = Path(__file__).parent

try:
    from icarus.parsers.windows import WindowsParser

    _manifest = None
    _yaml_path = _PARSERS_DIR / "windows.yaml"
    if _yaml_path.exists():
        try:
            _manifest = load_manifest(_yaml_path)
        except Exception:
            pass
    _REGISTRY.register(WindowsParser, _manifest)
except ImportError:
    pass

try:
    from icarus.parsers.linux import LinuxParser

    _manifest = None
    _yaml_path = _PARSERS_DIR / "linux.yaml"
    if _yaml_path.exists():
        try:
            _manifest = load_manifest(_yaml_path)
        except Exception:
            pass
    _REGISTRY.register(LinuxParser, _manifest)
except ImportError:
    pass

_GENERIC_PARSERS = [
    ("icarus.parsers.generic.json_parser", "JsonParser", "generic/json_parser.yaml"),
    ("icarus.parsers.generic.xml_parser", "XmlParser", "generic/xml_parser.yaml"),
    ("icarus.parsers.generic.sqlite_parser", "SqliteParser", "generic/sqlite_parser.yaml"),
    ("icarus.parsers.generic.archive_parser", "ArchiveParser", "generic/archive_parser.yaml"),
    ("icarus.parsers.generic.binary_entropy_parser", "BinaryEntropyParser",
     "generic/binary_entropy_parser.yaml"),
]

for _mod_path, _cls_name, _yaml_name in _GENERIC_PARSERS:
    try:
        import importlib
        _mod = importlib.import_module(_mod_path)
        _cls = getattr(_mod, _cls_name)
        _manifest = None
        _yaml_path = _PARSERS_DIR / _yaml_name
        if _yaml_path.exists():
            try:
                _manifest = load_manifest(_yaml_path)
            except Exception:
                pass
        _REGISTRY.register(_cls, _manifest)
    except ImportError:
        pass


def get_parser(name: str) -> BaseParser:
    """Get a parser instance by name."""
    return _REGISTRY.get(name)


def detect_parser(source: Path) -> Optional[str]:
    """Auto-detect parser for a source path. Returns parser name or None."""
    return _REGISTRY.detect(source)


def list_parsers() -> dict:
    """List all registered parsers with descriptions."""
    return {p["name"]: p["description"] for p in _REGISTRY.list_all()}


def get_registry() -> ParserRegistry:
    """Get the global parser registry."""
    return _REGISTRY
