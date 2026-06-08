"""
ICARUS Linux Parser — ELF binary detection, systemd services, filesystem analysis.
"""

import hashlib
import sqlite3
import struct
from pathlib import Path
from typing import Any, Dict

from icarus.parsers.base import BaseParser


class LinuxParser(BaseParser):
    """Parser for Linux filesystem trees — ELF binaries, systemd units, shared libraries."""

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
        conn = sqlite3.connect(str(db_path))
        stats = {"files": 0, "binaries": 0, "daemons": 0, "frameworks": 0}

        for path in source.rglob("*"):
            if not path.is_file():
                continue

            rel_path = "/" + str(path.relative_to(source)).replace("\\", "/")
            try:
                stat = path.stat()
            except (PermissionError, OSError):
                continue

            sha256 = None
            if stat.st_size < 50_000_000:
                try:
                    sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
                except (PermissionError, OSError):
                    pass

            conn.execute("""
                INSERT OR IGNORE INTO files
                (path, filename, extension, size, sha256, file_type)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                rel_path, path.name,
                path.suffix.lower() if path.suffix else None,
                stat.st_size, sha256,
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
                        arch = self._detect_elf_arch(path)
                        conn.execute("""
                            INSERT OR IGNORE INTO binaries (file_id, executable_name, arch)
                            VALUES (?, ?, ?)
                        """, (file_row[0], path.name, arch))
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

        for lib_dir in ["usr/lib", "lib", "usr/lib64", "lib64"]:
            search = source / lib_dir
            if not search.exists():
                continue
            for path in search.rglob("*.so*"):
                if path.is_file() and self._is_elf(path):
                    rel_path = "/" + str(path.relative_to(source)).replace("\\", "/")
                    conn.execute("""
                        INSERT OR IGNORE INTO frameworks (name, path, is_private)
                        VALUES (?, ?, 0)
                    """, (path.name, rel_path))
                    stats["frameworks"] += 1

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

    def _detect_elf_arch(self, path: Path) -> str:
        try:
            with open(path, "rb") as f:
                f.seek(18)
                machine = struct.unpack("<H", f.read(2))[0]
                return {
                    0x03: "x86", 0x3E: "x86_64", 0xB7: "aarch64",
                    0x28: "arm", 0xF3: "riscv",
                }.get(machine, "unknown")
        except (PermissionError, OSError, struct.error):
            return "unknown"
