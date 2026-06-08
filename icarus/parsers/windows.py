"""
ICARUS Windows Parser — Generic Windows application/directory analysis.

Extracts entities from any Windows directory tree:
- Filesystem inventory (every file, hashed)
- PE binaries (EXE/DLL metadata)
- Frameworks (DLLs as shared libraries)
"""

import hashlib
import json
import sqlite3
import struct
from pathlib import Path
from typing import Any, Dict

from icarus.parsers.base import BaseParser


class WindowsParser(BaseParser):
    """Parser for Windows application directories."""

    @property
    def name(self) -> str:
        return "windows"

    @property
    def description(self) -> str:
        return "Windows application directory or filesystem tree"

    def identify(self, source: Path) -> bool:
        if not source.is_dir():
            return False
        for f in source.rglob("*"):
            if f.suffix.lower() in (".exe", ".dll"):
                return True
        return False

    def get_required_tools(self) -> list:
        return []

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = sqlite3.connect(str(db_path))
        stats = {"files": 0, "binaries": 0, "frameworks": 0}

        stats["files"] = self._extract_files(source, conn)
        stats["binaries"] = self._extract_binaries(source, conn)
        stats["frameworks"] = self._extract_frameworks(source, conn)

        conn.commit()
        conn.close()
        return stats

    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        return {"linked": 0}

    def _extract_files(self, source: Path, conn: sqlite3.Connection) -> int:
        count = 0
        for path in source.rglob("*"):
            if not path.is_file():
                continue
            try:
                rel_path = "/" + str(path.relative_to(source)).replace("\\", "/")
                stat = path.stat()
                sha256 = None
                if stat.st_size < 50_000_000:
                    try:
                        sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
                    except (PermissionError, OSError):
                        pass

                file_type = self._classify_file(path)
                conn.execute("""
                    INSERT OR IGNORE INTO files
                    (path, filename, extension, size, sha256, file_type)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    rel_path, path.name,
                    path.suffix.lower() if path.suffix else None,
                    stat.st_size, sha256, file_type,
                ))
                count += 1
            except (PermissionError, OSError):
                continue

            if count % 5000 == 0:
                conn.commit()

        return count

    def _extract_binaries(self, source: Path, conn: sqlite3.Connection) -> int:
        count = 0
        for path in source.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in (".exe", ".dll"):
                continue
            if not self._is_pe(path):
                continue

            rel_path = "/" + str(path.relative_to(source)).replace("\\", "/")
            file_row = conn.execute(
                "SELECT id FROM files WHERE path = ?", (rel_path,)
            ).fetchone()
            if not file_row:
                continue

            arch = self._detect_pe_arch(path)
            conn.execute("""
                INSERT OR IGNORE INTO binaries (file_id, executable_name, arch)
                VALUES (?, ?, ?)
            """, (file_row[0], path.name, arch))
            count += 1

        return count

    def _extract_frameworks(self, source: Path, conn: sqlite3.Connection) -> int:
        count = 0
        for path in source.rglob("*.dll"):
            if not path.is_file():
                continue
            rel_path = "/" + str(path.relative_to(source)).replace("\\", "/")
            conn.execute("""
                INSERT OR IGNORE INTO frameworks (name, path, is_private)
                VALUES (?, ?, 0)
            """, (path.stem, rel_path))
            count += 1
        return count

    def _classify_file(self, path: Path) -> str:
        ext = path.suffix.lower()
        type_map = {
            ".exe": "binary", ".dll": "dylib", ".sys": "driver",
            ".json": "config", ".xml": "config", ".ini": "config",
            ".pdb": "debug", ".pak": "resource", ".dat": "data",
            ".manifest": "manifest", ".cat": "catalog",
        }
        return type_map.get(ext, "other")

    def _is_pe(self, path: Path) -> bool:
        try:
            with open(path, "rb") as f:
                magic = f.read(2)
            return magic == b"MZ"
        except (PermissionError, OSError):
            return False

    def _detect_pe_arch(self, path: Path) -> str:
        try:
            with open(path, "rb") as f:
                f.seek(0x3C)
                pe_offset = struct.unpack("<I", f.read(4))[0]
                f.seek(pe_offset + 4)
                machine = struct.unpack("<H", f.read(2))[0]
                if machine == 0x8664:
                    return "x86_64"
                elif machine == 0x14C:
                    return "x86"
                elif machine == 0xAA64:
                    return "arm64"
        except (PermissionError, OSError, struct.error):
            pass
        return "unknown"
