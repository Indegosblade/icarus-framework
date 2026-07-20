"""
ICARUS Windows Parser — Generic Windows application/directory analysis.

Extracts entities from any Windows directory tree in a single walk:
- Filesystem inventory (every file, hashed)
- PE binaries (EXE/DLL with architecture detection)
- Frameworks (DLLs as shared libraries)
"""

import os
import struct
from pathlib import Path
from typing import Any, Dict

from icarus.core.schema import open_db
from icarus.parsers.base import BATCH_COMMIT_INTERVAL, BaseParser

PE_MAGIC = b"MZ"
PE_ARCH = {0x8664: "x86_64", 0x14C: "x86", 0xAA64: "arm64"}
FILE_TYPES = {
    ".exe": "binary", ".dll": "dylib", ".sys": "driver",
    ".json": "config", ".xml": "config", ".ini": "config",
    ".pdb": "debug", ".pak": "resource", ".dat": "data",
    ".manifest": "manifest", ".cat": "catalog",
}


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
        for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
            for fname in filenames:
                if fname.lower().endswith((".exe", ".dll")):
                    return True
        return False

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = open_db(db_path)
        stats = {"files": 0, "binaries": 0, "frameworks": 0}
        try:
            for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
                for fname in filenames:
                    path = Path(dirpath) / fname
                    try:
                        st, kind = self._file_kind(path)
                        if st is None or kind in ("special", "unreadable"):
                            continue
                        ext = path.suffix.lower()
                        rel = self._rel_path(path, source)
                        filename = self._safe_text(path.name)
                        is_link = kind == "symlink"
                        file_type = "symlink" if is_link else FILE_TYPES.get(ext, "other")

                        conn.execute(
                            "INSERT OR IGNORE INTO files "
                            "(path,filename,extension,size,sha256,file_type,"
                            "is_symlink,symlink_target) VALUES (?,?,?,?,?,?,?,?)",
                            (rel, filename, ext or None, st.st_size,
                             self._safe_hash(path, st.st_size),
                             file_type, int(is_link), self._symlink_target(path)),
                        )
                        stats["files"] += 1

                        if is_link:
                            if stats["files"] % BATCH_COMMIT_INTERVAL == 0:
                                conn.commit()
                            continue

                        if ext in (".exe", ".dll") and self._check_magic(path, PE_MAGIC):
                            row = conn.execute(
                                "SELECT id FROM files WHERE path=?", (rel,)
                            ).fetchone()
                            if row:
                                existing = conn.execute(
                                    "SELECT id FROM binaries WHERE file_id=?",
                                    (row[0],),
                                ).fetchone()
                                if not existing:
                                    conn.execute(
                                        "INSERT INTO binaries "
                                        "(file_id,executable_name,arch) VALUES (?,?,?)",
                                        (row[0], filename, _detect_pe_arch(path)),
                                    )
                                    stats["binaries"] += 1

                        if ext == ".dll":
                            conn.execute(
                                "INSERT OR IGNORE INTO frameworks "
                                "(name,path,is_private) VALUES (?,?,0)",
                                (self._safe_text(path.stem), rel),
                            )
                            stats["frameworks"] += 1
                    except (PermissionError, OSError):
                        continue
                    if stats["files"] % BATCH_COMMIT_INTERVAL == 0:
                        conn.commit()
            conn.commit()
        finally:
            conn.close()
        return stats

    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        return {"linked": 0}


def _detect_pe_arch(path: Path) -> str:
    try:
        with BaseParser._open_regular(path) as f:
            f.seek(0x3C)
            pe_offset = struct.unpack("<I", f.read(4))[0]
            f.seek(pe_offset + 4)
            machine = struct.unpack("<H", f.read(2))[0]
            return PE_ARCH.get(machine, "unknown")
    except (PermissionError, OSError, struct.error):
        return "unknown"
