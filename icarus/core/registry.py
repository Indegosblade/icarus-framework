"""ICARUS Parser Registry — discovery, versioning, and quality-tier management."""

from pathlib import Path
from typing import Dict, List, Optional

from icarus.parsers.base import BaseParser
from icarus.parsers.manifest import ParserManifest


class ParserRegistry:
    """Registry for parser discovery, quality-tier management, and most-specific-wins contest.

    Most-specific-wins contest:
        When multiple parsers return True from identify(), the one with the lowest
        specificity_level in its manifest wins. If no manifest exists, specificity
        defaults to 50 (mid-range). Confidence is the tie-break: higher confidence wins.
    """

    def __init__(self):
        self._parsers: Dict[str, type] = {}
        self._manifests: Dict[str, ParserManifest] = {}

    def register(self, parser_cls: type, manifest: Optional[ParserManifest] = None) -> None:
        """Register a parser class with an optional manifest."""
        inst = parser_cls()
        name = inst.name
        self._parsers[name] = parser_cls
        if manifest is not None:
            self._manifests[name] = manifest

    def detect(self, source: Path) -> Optional[str]:
        """Run identify() contest. Most-specific-wins: lowest specificity_level.
        Tie-break: highest confidence. Returns parser name or None."""
        candidates = []
        for name, cls in self._parsers.items():
            try:
                if cls().identify(source):
                    manifest = self._manifests.get(name)
                    spec = manifest.specificity_level if manifest else 50
                    conf = manifest.confidence if manifest else 0.5
                    candidates.append((spec, -conf, name))
            except (PermissionError, OSError):
                continue
        if not candidates:
            return None
        candidates.sort()
        return candidates[0][2]

    def get(self, name: str) -> BaseParser:
        """Return a parser instance by name. Raises ValueError if unknown."""
        if name not in self._parsers:
            available = list(self._parsers.keys()) or ["(none registered)"]
            raise ValueError(f"Unknown parser: '{name}'. Available: {available}")
        return self._parsers[name]()

    def get_manifest(self, name: str) -> Optional[ParserManifest]:
        """Return the registered manifest for a parser, or None if it has none."""
        return self._manifests.get(name)

    def list_all(self) -> List[dict]:
        """Return metadata dicts for all registered parsers."""
        results = []
        for name, cls in self._parsers.items():
            inst = cls()
            manifest = self._manifests.get(name)
            results.append({
                "name": name,
                "tier": manifest.quality_tier if manifest else "unknown",
                "description": inst.description,
                "version": manifest.version if manifest else "unknown",
                "specificity": manifest.specificity_level if manifest else 50,
            })
        return results

    def list_production(self) -> List[dict]:
        """Return metadata for parsers in the production quality tier."""
        return [p for p in self.list_all() if p["tier"] == "production"]

    def list_candidate(self) -> List[dict]:
        """Return metadata for parsers in the candidate quality tier."""
        return [p for p in self.list_all() if p["tier"] == "candidate"]
