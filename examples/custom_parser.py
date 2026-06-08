"""
ICARUS Custom Parser Example — How to write your own parser.

This example shows a minimal Linux rootfs parser. Replace the extraction
logic with whatever your data source requires.
"""

import sqlite3
from pathlib import Path
from typing import Any, Dict

from icarus.parsers.base import BaseParser


class LinuxParser(BaseParser):
    """Example parser for Linux rootfs dumps."""

    @property
    def name(self) -> str:
        return "linux"

    @property
    def description(self) -> str:
        return "Linux filesystem rootfs (debootstrap, container export, etc.)"

    def identify(self, source: Path) -> bool:
        """Check for characteristic Linux filesystem markers."""
        markers = [
            source / "etc" / "passwd",
            source / "usr" / "bin",
            source / "lib" / "systemd",
        ]
        return any(m.exists() for m in markers)

    def get_required_tools(self) -> list:
        return ["readelf"]  # For ELF binary analysis

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        """
        Walk Linux rootfs and extract entities.

        Adapt this to your data source — the pattern is always:
        1. Walk/iterate your source
        2. Normalize into ICARUS schema tables
        3. Commit in batches for memory efficiency
        """
        conn = sqlite3.connect(str(db_path))
        stats = {"files": 0, "binaries": 0, "daemons": 0}

        # Phase 1: Catalog all files
        for path in source.rglob("*"):
            if not path.is_file():
                continue

            rel_path = "/" + str(path.relative_to(source)).replace("\\", "/")
            stat = path.stat()

            conn.execute("""
                INSERT OR IGNORE INTO files
                (path, filename, extension, size, file_type)
                VALUES (?, ?, ?, ?, ?)
            """, (
                rel_path, path.name,
                path.suffix.lower() if path.suffix else None,
                stat.st_size,
                self._classify(path),
            ))
            stats["files"] += 1

            if stats["files"] % 5000 == 0:
                conn.commit()

        # Phase 2: Find ELF binaries
        for bin_dir in ["usr/bin", "usr/sbin", "bin", "sbin", "usr/libexec"]:
            search = source / bin_dir
            if not search.exists():
                continue

            for path in search.iterdir():
                if path.is_file() and self._is_elf(path):
                    rel_path = "/" + str(path.relative_to(source)).replace("\\", "/")
                    file_row = conn.execute(
                        "SELECT id FROM files WHERE path = ?", (rel_path,)
                    ).fetchone()
                    if file_row:
                        conn.execute("""
                            INSERT OR IGNORE INTO binaries (file_id, executable_name, arch)
                            VALUES (?, ?, 'aarch64')
                        """, (file_row[0], path.name))
                        stats["binaries"] += 1

        # Phase 3: Parse systemd service units
        systemd_dir = source / "lib" / "systemd" / "system"
        if systemd_dir.exists():
            for unit in systemd_dir.glob("*.service"):
                label = unit.stem
                conn.execute("""
                    INSERT OR IGNORE INTO daemons
                    (label, plist_path, program)
                    VALUES (?, ?, ?)
                """, (label, str(unit.relative_to(source)), ""))
                stats["daemons"] += 1

        conn.commit()
        conn.close()
        return stats

    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        """Link systemd services to their binaries."""
        # Implement as needed for your source
        return {"linked": 0}

    def _classify(self, path: Path) -> str:
        ext = path.suffix.lower()
        return {".so": "shared_lib", ".service": "systemd_unit",
                ".conf": "config", ".py": "script"}.get(ext, "other")

    def _is_elf(self, path: Path) -> bool:
        try:
            with open(path, "rb") as f:
                return f.read(4) == b"\x7fELF"
        except (PermissionError, OSError):
            return False


# Register with ICARUS (add to icarus/parsers/__init__.py):
# from icarus.parsers.linux import LinuxParser
# PARSERS = {"linux": LinuxParser}
