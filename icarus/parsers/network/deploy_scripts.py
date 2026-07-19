"""
ICARUS Deploy Scripts Parser — extracts SSH connections, remote commands,
file uploads, service references, and permission grants from paramiko-based
deploy/fix scripts used to manage a remote server.

Identifies directories containing Python scripts that import paramiko and
connect to remote hosts. Targets the pattern found in home-lab and
infrastructure projects where a laptop drives a Pi/server over SSH.

Single-walk extraction: catalogs all .py files, parses each for paramiko
connection patterns, exec_command calls, SFTP uploads, systemctl references,
and permission-granting commands (sudoers, UFW rules).
"""

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from icarus.core.schema import open_db
from icarus.parsers.base import BATCH_COMMIT_INTERVAL, BaseParser

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FILE_TYPES = {
    ".py": "script",
    ".sh": "script",
    ".md": "documentation",
    ".conf": "config",
    ".toml": "config",
    ".yaml": "config",
    ".yml": "config",
    ".json": "config",
    ".txt": "text",
    ".html": "template",
    ".css": "stylesheet",
    ".service": "systemd_unit",
    ".sudoers": "sudoers",
}

# Upper bound on how much of a single script is scanned by the regex patterns
# below. Deploy scripts are small; capping the analyzed text keeps the total
# regex work bounded even for a pathological/adversarial input near the 2 MB
# file-read ceiling (defense-in-depth alongside the per-pattern span caps).
MAX_SCRIPT_ANALYZE_BYTES = 1_000_000

# SSH connection pattern: c.connect('host', username='user', password='pass')
# Spans are length-capped so a script missing the username=/password= sentinel
# (or a missing closing quote) can't make the lazy `.` scan to end-of-file —
# that unbounded DOTALL scan was quadratic across many .connect() calls (ReDoS).
# re.S is kept because a connect() call may wrap across a line; the caps keep
# each skip bounded to a real call's argument list.
SSH_CONNECT_PATTERN = re.compile(
    r"\.connect\(\s*['\"]([^'\"]{1,256})['\"]"
    r"(?:.{0,200}?username\s*=\s*['\"]([^'\"]{1,256})['\"])?"
    r"(?:.{0,200}?password\s*=\s*['\"]([^'\"]{1,256})['\"])?",
    re.S,
)

# Variable-style connection: HOST = 'x.x.x.x', USER = 'root', PASS = 'xxx'
HOST_VAR_PATTERN = re.compile(
    r"^(?:HOST|host|REMOTE_HOST)\s*=\s*['\"]([^'\"]+)['\"]", re.M
)
USER_VAR_PATTERN = re.compile(
    r"^(?:USER|user|SSH_USER|USERNAME)\s*=\s*['\"]([^'\"]+)['\"]", re.M
)
PASS_VAR_PATTERN = re.compile(
    r"^(?:PASS|pass|PASSWORD|SSH_PASS)\s*=\s*['\"]([^'\"]+)['\"]", re.M
)

# exec_command pattern — captures the command string.
# The negated class `[^'\"]` already spans newlines, so re.S is unnecessary; the
# {1,500} cap stops the capture at a bounded length instead of scanning to EOF
# when the closing quote is missing (the old `(.+?)` + re.S was the ReDoS vector).
# Commands are truncated to 200 chars downstream, so the 500 cap loses nothing.
EXEC_CMD_PATTERN = re.compile(
    r"\.exec_command\(\s*['\"]([^'\"]{1,500})['\"]"
)
# Also catch: exec_command(cmd, ...) where cmd is a variable set with cmd('...')
# and the helper pattern: def cmd(s): ... exec_command(s)
HELPER_CMD_PATTERN = re.compile(
    r"(?:cmd|run|exec_cmd|execute)\(\s*['\"]([^'\"]{1,500})['\"]"
)

# systemctl commands inside strings
SYSTEMCTL_PATTERN = re.compile(
    r"systemctl\s+(start|stop|restart|enable|disable|reload|"
    r"daemon-reload|is-active|status)\s+([\w@.-]+)"
)

# SFTP upload patterns
SFTP_PUT_PATTERN = re.compile(
    r"\.put\(\s*([^,)]+),\s*['\"]([^'\"]+)['\"]"
)
SFTP_OPEN_PATTERN = re.compile(
    r"sftp\.open\(\s*['\"]([^'\"]+)['\"]"
)

# File copy/write on remote via exec_command
REMOTE_FILE_WRITE_PATTERN = re.compile(
    r"(?:cp|mv|cat\s*>|tee)\s+([/\w._-]+(?:/[/\w._-]+)+)"
)

# UFW rule in command strings
UFW_CMD_PATTERN = re.compile(
    r"ufw\s+(allow|deny|reject|limit)\s+(.+?)(?:['\"]|$)", re.I
)

# Sudoers write pattern
SUDOERS_WRITE_PATTERN = re.compile(
    r"(?:cp|mv|cat\s*>|tee)\s+(/etc/sudoers\.d/\S+|.*sudoers\S*)"
)

# chmod/chown commands (permission changes)
PERMISSION_CMD_PATTERN = re.compile(
    r"(chmod|chown)\s+([\w:.-]+)\s+([/\w._*-]+(?:/[/\w._*-]+)*)"
)

# Python import pattern
PYTHON_IMPORT_PATTERN = re.compile(
    r"^(?:import|from)\s+([\w.]+)", re.M
)

# IP address pattern
IP_PATTERN = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b"
)

# Port pattern in command strings
PORT_PATTERN = re.compile(r"\bport\s+(\d+)\b", re.I)

# Words that are not valid service names (caught by regex in prose/docs)
_NOISE_WORDS = frozenset({
    "for", "the", "and", "out", "all", "get", "set",
    "run", "any", "not", "is", "it", "in", "on",
    "or", "at", "to", "up", "do", "no", "if",
    "--quiet", "--no-pager", "--now",
})


def _is_valid_unit(name: str) -> bool:
    """Return True if name looks like a valid systemd unit name."""
    if not name or len(name) < 3:
        return False
    if name.lower() in _NOISE_WORDS:
        return False
    if name.startswith("-"):
        return False
    # Must contain a letter and match unit-name pattern
    if not re.match(r"^[\w][\w@.-]+$", name):
        return False
    # Reject bare "wg-quick@" without a suffix
    if name.endswith("@"):
        return False
    return True


# Known service labels from systemctl unit names
KNOWN_SERVICE_LABELS = {
    "pihole-FTL": "pihole-FTL",
    "wg-quick@wg-mullvad": "wg-mullvad",
    "wg-quick@wg0": "wg0",
    "unbound": "unbound",
    "picontrol": "picontrol",
    "apache2": "apache2",
    "mariadb": "mariadb",
    "netdata": "netdata",
    "gitea": "gitea",
    "fail2ban": "fail2ban",
    "ntfy": "ntfy",
    "ttyd": "ttyd",
    "macchanger-wlan0": "macchanger",
}


class DeployScriptsParser(BaseParser):
    """Parser for paramiko-based deploy/fix scripts — SSH connections,
    remote commands, file uploads, and service management."""

    @property
    def name(self) -> str:
        return "network/deploy_scripts"

    @property
    def description(self) -> str:
        return "Paramiko-based deploy/fix scripts for remote server management"

    def identify(self, source: Path) -> bool:
        """Return True if this looks like a collection of paramiko deploy scripts.

        Checks for:
        - scripts/ directory (or source IS the scripts dir) containing .py files
        - At least 2 .py files with 'import paramiko' inside
        """
        if not source.is_dir():
            return False

        scripts_dir = source / "scripts"
        search_dir = scripts_dir if scripts_dir.is_dir() else source

        paramiko_count = 0
        py_checked = 0

        try:
            for entry in search_dir.iterdir():
                if not entry.is_file() or entry.suffix != ".py":
                    continue
                py_checked += 1
                if py_checked > 20:
                    # Enough sampling
                    break
                try:
                    # Read first 2KB — paramiko import is always near top
                    text = entry.read_text(errors="replace")[:2048]
                    if "import paramiko" in text or "from paramiko" in text:
                        paramiko_count += 1
                        if paramiko_count >= 2:
                            return True
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            return False

        return paramiko_count >= 2

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        """Walk source tree and extract files, daemons, observations,
        and entitlements from deploy scripts."""
        conn = open_db(db_path)
        now = datetime.now(timezone.utc).isoformat()
        stats = {
            "files": 0,
            "daemons": 0,
            "observations": 0,
            "entitlements": 0,
        }

        # Collected across all scripts
        found_services: Set[str] = set()
        # List of (script_path, observation_type, properties_json)
        observations_queue: List[Tuple[str, str, str]] = []
        # List of (script_path, key, value, value_type)
        entitlements_queue: List[Tuple[str, str, str, str]] = []

        try:
            # ── Phase 1: Walk all files, catalog them ─────────────────
            for dirpath, _dirs, filenames in os.walk(source, onerror=lambda e: None):
                rel_dir = ""
                try:
                    rel_dir = str(
                        Path(dirpath).relative_to(source)
                    ).replace("\\", "/")
                except ValueError:
                    continue
                # Skip hidden dirs, __pycache__, .git
                if any(
                    part.startswith(".") or part == "__pycache__"
                    for part in rel_dir.split("/")
                    if part and part != "."
                ):
                    continue

                for fname in filenames:
                    path = Path(dirpath) / fname
                    try:
                        st = path.stat()
                        ext = path.suffix.lower()
                        rel = self._rel_path(path, source)

                        file_type = FILE_TYPES.get(ext, "other")

                        conn.execute(
                            "INSERT OR IGNORE INTO files "
                            "(path,filename,extension,size,sha256,file_type) "
                            "VALUES (?,?,?,?,?,?)",
                            (rel, path.name, ext or None, st.st_size,
                             self._safe_hash(path, st.st_size), file_type),
                        )
                        stats["files"] += 1

                        # ── Deep analysis of Python scripts ───────
                        if ext == ".py" and 0 < st.st_size < 2_000_000:
                            try:
                                text = path.read_text(errors="replace")
                            except (PermissionError, OSError):
                                text = ""

                            if text and (
                                "paramiko" in text
                                or "exec_command" in text
                                or "sftp" in text.lower()
                            ):
                                self._analyze_script(
                                    text, rel, found_services,
                                    observations_queue,
                                    entitlements_queue,
                                )

                    except (PermissionError, OSError):
                        continue

                    if stats["files"] % BATCH_COMMIT_INTERVAL == 0:
                        conn.commit()

            conn.commit()

            # ── Phase 2: Insert discovered daemons ────────────────────
            for svc_label in sorted(found_services):
                # Map unit names to clean labels
                clean_label = KNOWN_SERVICE_LABELS.get(svc_label, svc_label)
                # Normalize: strip .service suffix, handle wg-quick@ prefix
                clean_label = clean_label.replace(".service", "")
                if clean_label.startswith("wg-quick@"):
                    clean_label = clean_label[len("wg-quick@"):]
                # Determine the systemd unit name
                if svc_label in KNOWN_SERVICE_LABELS:
                    unit_name = svc_label
                else:
                    unit_name = svc_label

                conn.execute(
                    "INSERT OR IGNORE INTO daemons "
                    "(label,plist_path,program) VALUES (?,?,?)",
                    (clean_label, unit_name, ""),
                )
                stats["daemons"] += 1

            conn.commit()

            # ── Phase 3: Insert observations ──────────────────────────
            for script_path, event_type, properties in observations_queue:
                # Anchor observation to the script file
                file_row = conn.execute(
                    "SELECT id FROM files WHERE path=?",
                    (script_path,),
                ).fetchone()
                if not file_row:
                    continue
                file_id = file_row[0]

                # Dedup check
                existing = conn.execute(
                    "SELECT id FROM observations WHERE entity_table=? "
                    "AND entity_id=? AND event_type=? AND properties=?",
                    ("files", file_id, event_type, properties),
                ).fetchone()
                if not existing:
                    conn.execute(
                        "INSERT INTO observations "
                        "(entity_table,entity_id,observed_at,observer,"
                        "event_type,properties,confidence) "
                        "VALUES (?,?,?,?,?,?,?)",
                        ("files", file_id, now,
                         "network/deploy_scripts", event_type,
                         properties, 0.85),
                    )
                    stats["observations"] += 1

            conn.commit()

            # ── Phase 4: Insert entitlements ──────────────────────────
            for script_path, key, value, value_type in entitlements_queue:
                file_row = conn.execute(
                    "SELECT id FROM files WHERE path=?",
                    (script_path,),
                ).fetchone()
                if not file_row:
                    continue
                file_id = file_row[0]

                # Create synthetic binary for FK target
                existing_bin = conn.execute(
                    "SELECT id FROM binaries WHERE file_id=?",
                    (file_id,),
                ).fetchone()
                if existing_bin:
                    binary_id = existing_bin[0]
                else:
                    conn.execute(
                        "INSERT INTO binaries "
                        "(file_id,executable_name,arch) VALUES (?,?,?)",
                        (file_id, Path(script_path).stem, "python"),
                    )
                    binary_id = conn.execute(
                        "SELECT id FROM binaries WHERE file_id=?",
                        (file_id,),
                    ).fetchone()[0]

                # Dedup check
                existing = conn.execute(
                    "SELECT id FROM entitlements WHERE binary_id=? "
                    "AND key=? AND value=?",
                    (binary_id, key, value),
                ).fetchone()
                if not existing:
                    conn.execute(
                        "INSERT INTO entitlements "
                        "(binary_id,key,value,value_type,confidence) "
                        "VALUES (?,?,?,?,?)",
                        (binary_id, key, value, value_type, 0.85),
                    )
                    stats["entitlements"] += 1

            conn.commit()
        finally:
            conn.close()

        return stats

    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        """Link scripts to the daemons they manage via observations."""
        conn = open_db(db_path)
        linked = 0
        now = datetime.now(timezone.utc).isoformat()
        try:
            # Find scripts that reference each daemon
            daemons = conn.execute(
                "SELECT id, label FROM daemons"
            ).fetchall()

            for daemon_id, label in daemons:
                # Look for observations of type remote_command that mention
                # this service label
                obs_rows = conn.execute(
                    "SELECT entity_id FROM observations "
                    "WHERE event_type='remote_command' "
                    "AND properties LIKE ?",
                    (f"%{label}%",),
                ).fetchall()

                for (file_id,) in obs_rows:
                    # Get file path for context
                    file_row = conn.execute(
                        "SELECT path FROM files WHERE id=?",
                        (file_id,),
                    ).fetchone()
                    if not file_row:
                        continue

                    existing = conn.execute(
                        "SELECT id FROM observations WHERE "
                        "entity_table='daemons' AND entity_id=? "
                        "AND event_type='managed_by_script' "
                        "AND properties=?",
                        (daemon_id, file_row[0]),
                    ).fetchone()
                    if not existing:
                        conn.execute(
                            "INSERT INTO observations "
                            "(entity_table,entity_id,observed_at,observer,"
                            "event_type,properties,confidence) "
                            "VALUES (?,?,?,?,?,?,?)",
                            ("daemons", daemon_id, now,
                             "network/deploy_scripts",
                             "managed_by_script", file_row[0], 0.80),
                        )
                        linked += 1

            conn.commit()
        finally:
            conn.close()
        return {"linked": linked}

    def verify(self, db_path: Path) -> Dict[str, Any]:
        """Verify extraction produced expected entities."""
        conn = open_db(db_path)
        try:
            stats = {}
            for table in ("files", "daemons", "observations", "entitlements"):
                try:
                    count = conn.execute(
                        f"SELECT COUNT(*) FROM {table}"  # nosec B608 - table iterates the hardcoded tuple literal above, not external input
                    ).fetchone()[0]
                    stats[table] = count
                except sqlite3.OperationalError:
                    stats[table] = 0
        finally:
            conn.close()

        if stats.get("files", 0) == 0:
            raise ValueError("Verification failed: files table is empty")
        if stats.get("observations", 0) == 0:
            raise ValueError(
                "Verification failed: no observations extracted "
                "(expected SSH connections, commands, etc.)"
            )
        return stats

    # ------------------------------------------------------------------
    # Private analysis helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _analyze_script(
        text: str,
        rel_path: str,
        found_services: Set[str],
        observations_queue: List[Tuple[str, str, str]],
        entitlements_queue: List[Tuple[str, str, str, str]],
    ) -> None:
        """Deep-parse a single Python script for deploy patterns."""

        # Pre-cap the analyzed text so the regex sweep below is bounded even for
        # an adversarially large script (belt-and-suspenders with the per-pattern
        # length caps that prevent backtracking to end-of-file).
        if len(text) > MAX_SCRIPT_ANALYZE_BYTES:
            text = text[:MAX_SCRIPT_ANALYZE_BYTES]

        # ── SSH connections ────────────────────────────────────────
        # Try explicit .connect() calls first
        for match in SSH_CONNECT_PATTERN.finditer(text):
            host = match.group(1)
            user = match.group(2) or ""
            passwd = match.group(3) or ""
            info = json.dumps({
                "host": host,
                "user": user,
                "has_password": bool(passwd),
                "script": rel_path,
            })
            observations_queue.append((rel_path, "ssh_connection", info))

        # Try variable-style connections
        host_match = HOST_VAR_PATTERN.search(text)
        user_match = USER_VAR_PATTERN.search(text)
        pass_match = PASS_VAR_PATTERN.search(text)
        if host_match:
            info = json.dumps({
                "host": host_match.group(1),
                "user": user_match.group(1) if user_match else "",
                "has_password": bool(pass_match),
                "script": rel_path,
            })
            observations_queue.append((rel_path, "ssh_connection", info))

        # ── Remote commands ────────────────────────────────────────
        commands_seen: Set[str] = set()

        for pattern in (EXEC_CMD_PATTERN, HELPER_CMD_PATTERN):
            for match in pattern.finditer(text):
                cmd_str = match.group(1).strip()
                # Truncate very long commands
                if len(cmd_str) > 200:
                    cmd_str = cmd_str[:200] + "..."
                # Skip duplicates within the same script
                if cmd_str in commands_seen:
                    continue
                commands_seen.add(cmd_str)

                info = json.dumps({
                    "command": cmd_str,
                    "script": rel_path,
                })
                observations_queue.append(
                    (rel_path, "remote_command", info)
                )

                # Extract service references from commands
                for svc_match in SYSTEMCTL_PATTERN.finditer(cmd_str):
                    action = svc_match.group(1)
                    unit = svc_match.group(2)
                    if _is_valid_unit(unit):
                        found_services.add(unit)

                    svc_info = json.dumps({
                        "action": action,
                        "unit": unit,
                        "script": rel_path,
                    })
                    observations_queue.append(
                        (rel_path, "service_management", svc_info)
                    )

                # Extract UFW rules from commands
                for ufw_match in UFW_CMD_PATTERN.finditer(cmd_str):
                    action = ufw_match.group(1)
                    rule_spec = ufw_match.group(2).strip()
                    entitlements_queue.append((
                        rel_path,
                        f"ufw_{action}",
                        rule_spec,
                        "firewall_rule",
                    ))

                # Extract permission changes
                for perm_match in PERMISSION_CMD_PATTERN.finditer(cmd_str):
                    perm_cmd = perm_match.group(1)
                    perm_val = perm_match.group(2)
                    target = perm_match.group(3)
                    entitlements_queue.append((
                        rel_path,
                        f"{perm_cmd}",
                        f"{perm_val} {target}",
                        "permission_change",
                    ))

                # Extract sudoers writes
                for sudoers_match in SUDOERS_WRITE_PATTERN.finditer(cmd_str):
                    target = sudoers_match.group(1)
                    entitlements_queue.append((
                        rel_path,
                        "sudoers_install",
                        target,
                        "sudoers_rule",
                    ))

        # ── File uploads (SFTP) ────────────────────────────────────
        for match in SFTP_PUT_PATTERN.finditer(text):
            local = match.group(1).strip().strip("'\"")
            remote = match.group(2).strip()
            info = json.dumps({
                "local": local,
                "remote": remote,
                "script": rel_path,
            })
            observations_queue.append(
                (rel_path, "file_upload", info)
            )

        for match in SFTP_OPEN_PATTERN.finditer(text):
            remote = match.group(1).strip()
            info = json.dumps({
                "remote": remote,
                "script": rel_path,
                "method": "sftp.open",
            })
            observations_queue.append(
                (rel_path, "file_upload", info)
            )

        # ── Remote file writes via cp/cat/tee ──────────────────────
        for match in REMOTE_FILE_WRITE_PATTERN.finditer(text):
            target = match.group(1).strip()
            # Only include paths that look like absolute paths
            if target.startswith("/"):
                info = json.dumps({
                    "remote": target,
                    "script": rel_path,
                    "method": "command",
                })
                observations_queue.append(
                    (rel_path, "file_upload", info)
                )

        # ── Also extract systemctl references outside commands ─────
        # (e.g., in string literals, comments referencing services)
        for match in SYSTEMCTL_PATTERN.finditer(text):
            unit = match.group(2)
            if _is_valid_unit(unit):
                found_services.add(unit)
