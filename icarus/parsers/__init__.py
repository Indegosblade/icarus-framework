"""ICARUS parsers — pluggable data source modules."""

from pathlib import Path
from typing import Optional

from icarus.parsers.base import BaseParser

PARSERS = {}

try:
    from icarus.parsers.windows import WindowsParser
    PARSERS["windows"] = WindowsParser
except ImportError:
    pass

try:
    from icarus.parsers.linux import LinuxParser
    PARSERS["linux"] = LinuxParser
except ImportError:
    pass


def get_parser(name: str) -> BaseParser:
    """Get a parser instance by name."""
    if name not in PARSERS:
        available = list(PARSERS.keys()) or ["(none registered)"]
        raise ValueError(f"Unknown parser: '{name}'. Available: {available}")
    return PARSERS[name]()


def detect_parser(source: Path) -> Optional[str]:
    """Auto-detect parser for a source path. Returns parser name or None."""
    for name, cls in PARSERS.items():
        try:
            if cls().identify(source):
                return name
        except (PermissionError, OSError):
            continue
    return None


def list_parsers() -> dict:
    """List all registered parsers with descriptions."""
    return {name: cls().description for name, cls in PARSERS.items()}
