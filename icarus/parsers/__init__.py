"""ICARUS parsers — pluggable data source modules."""

from icarus.parsers.base import BaseParser

PARSERS = {}

try:
    from icarus.parsers.ios import iOSParser
    PARSERS["ios"] = iOSParser
except ImportError:
    pass


def get_parser(name: str) -> BaseParser:
    """Get a parser instance by name."""
    if name not in PARSERS:
        available = list(PARSERS.keys()) or ["(none registered)"]
        raise ValueError(f"Unknown parser: '{name}'. Available: {available}")
    return PARSERS[name]()


def list_parsers() -> dict:
    """List all registered parsers with descriptions."""
    return {name: cls().description for name, cls in PARSERS.items()}
