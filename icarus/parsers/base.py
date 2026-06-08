"""
ICARUS Base Parser — Abstract interface for data source parsers.

Every parser implements this interface. The pipeline calls these methods
in sequence. Each parser knows how to extract entities and relationships
from one specific data source type.
"""

import hashlib
import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional


class BaseParser(ABC):
    """
    Abstract base class for ICARUS parsers.

    Implement this to add support for a new data source type.
    The pipeline calls methods in order: identify → extract_entities →
    extract_relationships → verify.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this parser (e.g., 'windows', 'linux', 'android')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """One-line description of what this parser handles."""
        ...

    @abstractmethod
    def identify(self, source: Path) -> bool:
        """
        Return True if this parser can handle the given source.

        The pipeline may call this on multiple parsers to auto-detect
        the source type. Check for characteristic files/structures.
        """
        ...

    @abstractmethod
    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        """
        Walk the source and extract entities into the database.

        This is the main extraction phase. Write files, binaries,
        daemons, entitlements, etc. into the ICARUS schema tables.

        Returns stats dict (e.g., {"files": 500000, "binaries": 15000}).
        """
        ...

    @abstractmethod
    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        """
        Map relationships between extracted entities.

        Called after extract_entities. Link daemons to binaries,
        binaries to entitlements, sandbox profiles to rules, etc.

        Returns stats dict.
        """
        ...

    def verify(self, db_path: Path) -> Dict[str, Any]:
        """
        Run quality gates on the populated database.

        Override to add parser-specific verification. Default
        checks that core tables have rows.
        """
        conn = sqlite3.connect(str(db_path))
        try:
            tables = ["files", "binaries"]
            stats = {}
            for t in tables:
                try:
                    count = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                    stats[t] = count
                except sqlite3.OperationalError:
                    stats[t] = 0
        finally:
            conn.close()

        if stats.get("files", 0) == 0:
            raise ValueError("Verification failed: files table is empty")

        return stats

    def get_required_tools(self) -> list:
        """
        Return list of external tools this parser requires.

        Override to declare dependencies (e.g., ['readelf'] for Linux).
        The pipeline checks availability before starting.
        """
        return []

    @staticmethod
    def _rel_path(path: Path, source: Path) -> str:
        """Normalized relative path for database storage."""
        return "/" + str(path.relative_to(source)).replace("\\", "/")

    @staticmethod
    def _safe_hash(path: Path, size: int) -> Optional[str]:
        """SHA-256 of file contents, or None if >50MB or inaccessible."""
        if size >= 50_000_000:
            return None
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except (PermissionError, OSError):
            return None

    @staticmethod
    def _check_magic(path: Path, magic: bytes) -> bool:
        """Check if file starts with the given magic bytes."""
        try:
            with open(path, "rb") as f:
                return f.read(len(magic)) == magic
        except (PermissionError, OSError):
            return False
