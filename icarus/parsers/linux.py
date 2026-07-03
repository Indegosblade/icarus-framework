"""
ICARUS Linux Parser — ELF binary detection, systemd services, filesystem analysis.

Single-walk extraction: catalogs files, detects ELF binaries in standard paths,
parses systemd units, and inventories shared libraries.
"""

import os
import re
import sqlite3
import struct
from pathlib import Path
from typing import Any, Dict

from icarus.parsers.base import BATCH_COMMIT_INTERVAL, BaseParser, link_daemons_to_binaries

ELF_MAGIC = b"\x7fELF"
ELF_ARCH = {0x03: "x86", 0x3E: "x86_64", 0xB7: "aarch64", 0x28: "arm", 0xF3: "riscv"}
FILE_TYPES = {".so": "shared_lib", ".service": "systemd_unit", ".conf": "config", ".py": "script"}
BIN_DIRS = frozenset({"usr/bin", "usr/sbin", "bin", "sbin", "usr/libexec"})
LIB_DIRS = frozenset({"usr/lib", "lib", "usr/lib64", "lib64"})


class LinuxParser(BaseParser):
    """Parser for Linux filesystem trees — ELF binaries, systemd units, shared libraries."""

    @property
    def name(self) -> str:
        return "linux"

    @property
    def description(self) -> str:
        return "Linux filesystem rootfs (debootstrap, container export, etc.)"

    def identify(self, source: Path) -> bool:
        markers = [source / "etc" / "passwd", source / "usr" / "bin", source / "lib" / "systemd"]
        return any(m.exists() for m in markers)

    def get_required_tools(self) -> list:
        return ["readelf"]

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = sqlite3.connect(str(db_path))
        stats = {"files": 0, "binaries": 0, "daemons": 0, "frameworks": 0}
        try:
            for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
                try:
                    rel_dir = str(Path(dirpath).relative_to(source)).replace("\\", "/")
                except ValueError:
                    continue
                in_bin = _match_dir(rel_dir, BIN_DIRS)
                in_lib = _match_dir(rel_dir, LIB_DIRS)
                is_systemd = rel_dir == "lib/systemd/system"

                for fname in filenames:
                    path = Path(dirpath) / fname
                    try:
                        st = path.stat()
                        ext = path.suffix.lower()
                        rel = self._rel_path(path, source)

                        conn.execute(
                            "INSERT OR IGNORE INTO files "
                            "(path,filename,extension,size,sha256,file_type) VALUES (?,?,?,?,?,?)",
                            (rel, path.name, ext or None, st.st_size,
                             self._safe_hash(path, st.st_size),
                             FILE_TYPES.get(ext, "other")),
                        )
                        stats["files"] += 1

                        if in_bin and self._check_magic(path, ELF_MAGIC):
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
                                        (row[0], path.name, _detect_elf_arch(path)),
                                    )
                                    stats["binaries"] += 1

                        if is_systemd and ext == ".service":
                            conn.execute(
                                "INSERT OR IGNORE INTO daemons "
                                "(label,plist_path,program) VALUES (?,?,?)",
                                (path.stem, f"{rel_dir}/{fname}", _parse_execstart(path)),
                            )
                            stats["daemons"] += 1

                        if in_lib and ".so" in fname and self._check_magic(path, ELF_MAGIC):
                            conn.execute(
                                "INSERT OR IGNORE INTO frameworks "
                                "(name,path,is_private) VALUES (?,?,0)",
                                (path.name, rel),
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
        conn = sqlite3.connect(str(db_path))
        try:
            linked = link_daemons_to_binaries(conn)
            conn.commit()
        finally:
            conn.close()
        return {"linked": linked}


def _match_dir(rel_dir: str, dir_set: frozenset) -> bool:
    """Check if rel_dir is or is under any directory in dir_set."""
    return any(rel_dir == d or rel_dir.startswith(d + "/") for d in dir_set)


_EXECSTART_RE = re.compile(r"^\s*ExecStart\s*=\s*(.+)$", re.MULTILINE)


def _parse_execstart(path: Path) -> str:
    """Executable path from a systemd unit's ExecStart= directive, or "" if
    absent/unreadable. systemd allows leading modifier chars (-, @, +, !, :) on
    the command; the executable is the first whitespace-delimited token."""
    try:
        if path.stat().st_size > 1_000_000:
            return ""
        text = path.read_text(errors="ignore")
    except OSError:
        return ""
    m = _EXECSTART_RE.search(text)
    if not m:
        return ""
    cmd = m.group(1).strip().lstrip("-@+!:").strip()
    return cmd.split()[0] if cmd else ""


def _detect_elf_arch(path: Path) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(18)
            machine = struct.unpack("<H", f.read(2))[0]
            return ELF_ARCH.get(machine, "unknown")
    except (PermissionError, OSError, struct.error):
        return "unknown"
