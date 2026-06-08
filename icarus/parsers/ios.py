"""
ICARUS iOS Parser — Reference implementation for Apple firmware analysis.

Extracts entities from an iOS rootfs (extracted IPSW or jailbroken device dump):
- Filesystem inventory (every file, hashed)
- Mach-O binary metadata and code signatures
- Entitlements per binary (via ldid or ipsw)
- LaunchDaemons/Agents → MachServices mapping
- IOKit kernel extensions and personalities
- Sandbox profiles (via SandBlaster)
- System and Private frameworks
"""

import hashlib
import json
import plistlib
import sqlite3
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from icarus.parsers.base import BaseParser


class iOSParser(BaseParser):
    """Parser for iOS firmware rootfs dumps."""

    @property
    def name(self) -> str:
        return "ios"

    @property
    def description(self) -> str:
        return "iOS firmware rootfs (IPSW extraction or device dump)"

    def identify(self, source: Path) -> bool:
        markers = [
            source / "System" / "Library" / "CoreServices",
            source / "usr" / "lib" / "dyld",
            source / "System" / "Library" / "LaunchDaemons",
        ]
        return any(m.exists() for m in markers)

    def get_required_tools(self) -> list:
        return ["ipsw", "ldid"]

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = sqlite3.connect(str(db_path))
        stats = {"files": 0, "binaries": 0, "entitlements": 0,
                 "daemons": 0, "kexts": 0, "frameworks": 0}

        stats["files"] = self._extract_files(source, conn)
        stats["binaries"] = self._extract_binaries(source, conn)
        stats["entitlements"] = self._extract_entitlements(source, conn)
        stats["daemons"] = self._extract_daemons(source, conn)
        stats["kexts"] = self._extract_kexts(source, conn)
        stats["frameworks"] = self._extract_frameworks(source, conn)

        conn.commit()
        conn.close()
        return stats

    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = sqlite3.connect(str(db_path))
        linked = self._link_daemons_to_binaries(conn)
        conn.commit()
        conn.close()
        return {"daemon_binary_links": linked}

    def _extract_files(self, source: Path, conn: sqlite3.Connection) -> int:
        """Walk filesystem and catalog every file."""
        count = 0
        for path in source.rglob("*"):
            if not path.is_file():
                continue

            rel_path = str(path.relative_to(source))
            stat = path.stat()

            sha256 = None
            if stat.st_size < 100_000_000:  # Skip files > 100MB
                try:
                    sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
                except (PermissionError, OSError):
                    pass

            file_type = self._classify_file(path)

            conn.execute("""
                INSERT OR IGNORE INTO files
                (path, filename, extension, size, modified_time, sha256, file_type, is_symlink)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "/" + rel_path.replace("\\", "/"),
                path.name,
                path.suffix.lower() if path.suffix else None,
                stat.st_size,
                str(stat.st_mtime),
                sha256,
                file_type,
                1 if path.is_symlink() else 0
            ))
            count += 1

            if count % 10000 == 0:
                conn.commit()
                print(f"  [ios] {count} files cataloged...")

        return count

    def _extract_binaries(self, source: Path, conn: sqlite3.Connection) -> int:
        """Find and catalog Mach-O binaries."""
        count = 0
        binary_extensions = {".dylib", ""}
        binary_paths = [
            "usr/bin", "usr/sbin", "usr/libexec", "bin", "sbin",
            "System/Library/Frameworks", "System/Library/PrivateFrameworks",
        ]

        for base_path in binary_paths:
            search_dir = source / base_path
            if not search_dir.exists():
                continue

            for path in search_dir.rglob("*"):
                if not path.is_file():
                    continue
                if path.suffix not in binary_extensions and not self._is_macho(path):
                    continue

                rel_path = "/" + str(path.relative_to(source)).replace("\\", "/")

                file_row = conn.execute(
                    "SELECT id FROM files WHERE path = ?", (rel_path,)
                ).fetchone()

                if not file_row:
                    continue

                arch = self._detect_arch(path)
                conn.execute("""
                    INSERT OR IGNORE INTO binaries (file_id, executable_name, arch)
                    VALUES (?, ?, ?)
                """, (file_row[0], path.name, arch))
                count += 1

        return count

    def _extract_entitlements(self, source: Path, conn: sqlite3.Connection) -> int:
        """Extract entitlements from cataloged binaries via ldid."""
        count = 0
        binaries = conn.execute(
            "SELECT b.id, f.path FROM binaries b JOIN files f ON b.file_id = f.id"
        ).fetchall()

        for binary_id, db_path in binaries:
            fs_path = str(source / db_path.lstrip("/"))
            ents = self._get_entitlements(fs_path)
            if not ents:
                continue

            for key, value in ents.items():
                value_type = type(value).__name__
                conn.execute("""
                    INSERT INTO entitlements (binary_id, key, value, value_type)
                    VALUES (?, ?, ?, ?)
                """, (binary_id, key, json.dumps(value), value_type))
                count += 1

        return count

    def _extract_daemons(self, source: Path, conn: sqlite3.Connection) -> int:
        """Parse LaunchDaemons and LaunchAgents."""
        count = 0
        daemon_dirs = [
            source / "System" / "Library" / "LaunchDaemons",
            source / "System" / "Library" / "LaunchAgents",
        ]

        for daemon_dir in daemon_dirs:
            if not daemon_dir.exists():
                continue

            for plist_path in daemon_dir.glob("*.plist"):
                try:
                    with open(plist_path, "rb") as f:
                        plist = plistlib.load(f)
                except Exception:
                    continue

                label = plist.get("Label", plist_path.stem)
                program = plist.get("Program", "")
                if not program:
                    args = plist.get("ProgramArguments", [])
                    program = args[0] if args else ""

                mach_services = plist.get("MachServices")
                if mach_services:
                    mach_services = json.dumps(mach_services)

                rel_path = "/" + str(plist_path.relative_to(source)).replace("\\", "/")

                conn.execute("""
                    INSERT OR IGNORE INTO daemons
                    (label, plist_path, program, program_arguments, user_name,
                     group_name, run_at_load, keep_alive, sandbox_profile, mach_services)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    label, rel_path, program,
                    json.dumps(plist.get("ProgramArguments", [])),
                    plist.get("UserName"),
                    plist.get("GroupName"),
                    1 if plist.get("RunAtLoad") else 0,
                    1 if plist.get("KeepAlive") else 0,
                    plist.get("SandboxProfile") or plist.get("ProcessType"),
                    mach_services,
                ))
                count += 1

        return count

    def _extract_kexts(self, source: Path, conn: sqlite3.Connection) -> int:
        """Catalog kernel extensions."""
        count = 0
        kext_dir = source / "System" / "Library" / "Extensions"
        if not kext_dir.exists():
            return 0

        for kext_path in kext_dir.glob("*.kext"):
            info_plist = kext_path / "Contents" / "Info.plist"
            if not info_plist.exists():
                info_plist = kext_path / "Info.plist"
            if not info_plist.exists():
                continue

            try:
                with open(info_plist, "rb") as f:
                    info = plistlib.load(f)
            except Exception:
                continue

            bundle_id = info.get("CFBundleIdentifier", kext_path.stem)
            personalities = info.get("IOKitPersonalities", {})
            has_uc = any(
                "UserClient" in str(v) for v in personalities.values()
            ) if personalities else False

            conn.execute("""
                INSERT OR IGNORE INTO kexts
                (bundle_id, name, version, personalities, iokit_classes, has_user_client)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                bundle_id,
                info.get("CFBundleName", kext_path.name),
                info.get("CFBundleVersion", ""),
                json.dumps(list(personalities.keys())) if personalities else None,
                json.dumps(list(personalities.keys())) if personalities else None,
                1 if has_uc else 0,
            ))
            count += 1

        return count

    def _extract_frameworks(self, source: Path, conn: sqlite3.Connection) -> int:
        """Catalog system and private frameworks."""
        count = 0
        framework_dirs = [
            (source / "System" / "Library" / "Frameworks", False),
            (source / "System" / "Library" / "PrivateFrameworks", True),
        ]

        for fw_dir, is_private in framework_dirs:
            if not fw_dir.exists():
                continue

            for fw_path in fw_dir.glob("*.framework"):
                rel_path = "/" + str(fw_path.relative_to(source)).replace("\\", "/")
                conn.execute("""
                    INSERT OR IGNORE INTO frameworks (name, path, is_private)
                    VALUES (?, ?, ?)
                """, (fw_path.stem, rel_path, 1 if is_private else 0))
                count += 1

        return count

    def _link_daemons_to_binaries(self, conn: sqlite3.Connection) -> int:
        """Link daemons to their binary entries."""
        linked = 0
        daemons = conn.execute(
            "SELECT id, program FROM daemons WHERE program IS NOT NULL"
        ).fetchall()

        for daemon_id, program in daemons:
            binary = conn.execute(
                "SELECT b.id FROM binaries b JOIN files f ON b.file_id = f.id WHERE f.path = ?",
                (program,)
            ).fetchone()

            if binary:
                conn.execute(
                    "UPDATE daemons SET binary_id = ? WHERE id = ?",
                    (binary[0], daemon_id)
                )
                linked += 1

        return linked

    def _detect_arch(self, path: Path) -> str:
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic == b"\xca\xfe\xba\xbe":
                    return "universal"
                if magic in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
                    return "arm64"
                if magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
                    return "arm64e"
        except (PermissionError, OSError):
            pass
        return "unknown"

    def _classify_file(self, path: Path) -> str:
        ext = path.suffix.lower()
        type_map = {
            ".dylib": "dylib", ".framework": "framework",
            ".plist": "plist", ".db": "database",
            ".sqlite": "database", ".kext": "kext",
            ".sb": "sandbox_profile",
        }
        return type_map.get(ext, "other")

    def _is_macho(self, path: Path) -> bool:
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
            return magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                           b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe")
        except (PermissionError, OSError):
            return False

    def _get_entitlements(self, binary_path: str) -> Optional[dict]:
        try:
            result = subprocess.run(
                ["ldid", "-e", binary_path],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                return plistlib.loads(result.stdout.encode())
        except (subprocess.TimeoutExpired, Exception):
            pass
        return None
