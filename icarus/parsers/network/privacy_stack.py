"""
ICARUS Network Privacy Stack Parser — extracts services, firewall rules,
credentials, blocklists, and frameworks from a home network privacy project.

Identifies projects containing Pi-hole, WireGuard, Mullvad VPN, Unbound,
and a Flask control dashboard. Targets the directory structure produced by
an Orange Pi / Raspberry Pi privacy stack with deploy scripts and configs.

Single-walk extraction: catalogs all files, detects services from systemd
units and config references, parses UFW/sudoers for entitlements, finds
credentials and IPs, and inventories blocklists and Python packages.
"""

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

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
    ".ini": "config",
    ".cfg": "config",
    ".html": "template",
    ".css": "stylesheet",
    ".js": "javascript",
    ".svg": "image",
    ".png": "image",
    ".jpg": "image",
    ".pdf": "document",
    ".txt": "text",
    ".service": "systemd_unit",
    ".sudoers": "sudoers",
}

# Known services in a privacy stack project — label -> (systemd unit, typical port)
KNOWN_SERVICES = {
    "pihole-FTL":          ("pihole-FTL",           "53,8080"),
    "unbound":             ("unbound",              "5335"),
    "wg-mullvad":          ("wg-quick@wg-mullvad",  ""),
    "wg0":                 ("wg-quick@wg0",         "51820"),
    "picontrol":           ("picontrol",            "5001"),
    "apache2":             ("apache2",              "80"),
    "mariadb":             ("mariadb",              "3306"),
    "netdata":             ("netdata",              "19999"),
    "gitea":               ("gitea",                "3000"),
    "fail2ban":            ("fail2ban",             ""),
    "ntfy":                ("ntfy",                 "8090"),
    "ttyd":                ("ttyd",                 "7681"),
    "macchanger":          ("macchanger-wlan0",     ""),
}

# Patterns to detect services mentioned in text
SERVICE_PATTERNS = [
    (re.compile(r"pihole[-_]?FTL|Pi-hole|pihole", re.I), "pihole-FTL"),
    (re.compile(r"unbound", re.I), "unbound"),
    (re.compile(r"wg-?mullvad|Mullvad\s+VPN|mullvad", re.I), "wg-mullvad"),
    (re.compile(r"wg-?quick@wg0|wg0|WireGuard.*server|PiVPN", re.I), "wg0"),
    (re.compile(r"picontrol|Pi\s*Control", re.I), "picontrol"),
    (re.compile(r"\bapache2?\b", re.I), "apache2"),
    (re.compile(r"\bmariadb\b|\bmysql\b", re.I), "mariadb"),
    (re.compile(r"\bnetdata\b", re.I), "netdata"),
    (re.compile(r"\bgitea\b", re.I), "gitea"),
    (re.compile(r"\bfail2ban\b", re.I), "fail2ban"),
    (re.compile(r"\bntfy\b", re.I), "ntfy"),
    (re.compile(r"\bttyd\b", re.I), "ttyd"),
    (re.compile(r"\bnextcloud\b", re.I), "nextcloud"),
    (re.compile(r"\bmacchanger\b", re.I), "macchanger"),
]

# IP address pattern (IPv4)
IP_PATTERN = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b"
)

# Credential patterns (key=value, password, etc.)
CREDENTIAL_PATTERNS = [
    re.compile(r"(?:password|passwd|pass)\s*[=:]\s*['\"]?(\S+)", re.I),
    re.compile(r"(?:PrivateKey|private_key)\s*=\s*(\S+)", re.I),
    re.compile(r"(?:PublicKey|public_key)\s*=\s*(\S+)", re.I),
]

# Port mapping pattern
PORT_PATTERN = re.compile(r"\b(\d+)/(tcp|udp|TCP|UDP)\b")

# UFW rule pattern — captures rule spec, strips trailing quotes/comments
UFW_RULE_PATTERN = re.compile(
    r"ufw\s+(allow|deny|reject|limit)\s+(.+?)(?:['\"\n]|$)", re.I
)

# Sudoers entry pattern
SUDOERS_PATTERN = re.compile(
    r"^(\S+)\s+.*NOPASSWD:\s*(.+)$", re.M
)

# Blocklist URL pattern — match known blocklist hosting domains and path patterns.
# Excludes localhost API URLs, SVG data, and general web URLs.
BLOCKLIST_URL_PATTERN = re.compile(
    r"https?://(?:"
    r"(?:raw\.githubusercontent\.com|cdn\.jsdelivr\.net|"
    r"adguardteam\.github\.io|big\.oisd\.nl|small\.oisd\.nl|"
    r"v\.firebog\.net|hosts-file\.net|someonewhocares\.org|"
    r"pgl\.yoyo\.org|blocklistproject\.github\.io|"
    r"[\w.-]+\.github\.io|dbl\.oisd\.nl)"
    r"/\S+"
    r"|"
    r"\S+/(?:hosts(?:file)?|adblock|blocklist|adlist|denylist)\S*"
    r")",
    re.I,
)

# Python import pattern
PYTHON_IMPORT_PATTERN = re.compile(
    r"^(?:import|from)\s+([\w.]+)", re.M
)

# systemctl command pattern
SYSTEMCTL_PATTERN = re.compile(
    r"systemctl\s+(start|stop|restart|enable|disable|is-active|status)\s+([\w@.-]+)"
)

# WireGuard endpoint pattern
WG_ENDPOINT_PATTERN = re.compile(r"Endpoint\s*=\s*(\S+)")

# DNS config pattern
DNS_UPSTREAM_PATTERN = re.compile(
    r"(?:forward-addr|server|upstream|DNS)\s*[=:]\s*(\S+)", re.I
)


class PrivacyStackParser(BaseParser):
    """Parser for home network privacy stack projects — Pi-hole, WireGuard,
    Mullvad, Unbound, Flask dashboard, deploy scripts, and config files."""

    @property
    def name(self) -> str:
        return "network/privacy_stack"

    @property
    def description(self) -> str:
        return "Home network privacy stack (Pi-hole, WireGuard, Mullvad, dashboard, deploy scripts)"

    def identify(self, source: Path) -> bool:
        """Return True if this looks like a home network privacy stack project.

        Checks for:
        - AGENTS.md or HANDOFF.md with Pi-hole/WireGuard references
        - dashboard/app.py with Pi-hole API integration
        - scripts/ directory with paramiko deploy scripts
        """
        if not source.is_dir():
            return False

        # Primary markers: project context files
        agents_md = source / "AGENTS.md"
        handoff_md = source / "HANDOFF.md"
        dashboard_app = source / "dashboard" / "app.py"

        # Must have at least one context file
        has_context = agents_md.exists() or handoff_md.exists()
        if not has_context:
            return False

        # Check context file mentions privacy stack services
        for ctx_file in (agents_md, handoff_md):
            if ctx_file.exists():
                try:
                    text = ctx_file.read_text(errors="replace")[:8000]
                    pihole_ref = "Pi-hole" in text or "pihole" in text.lower()
                    wg_ref = "WireGuard" in text or "wireguard" in text.lower()
                    if pihole_ref and wg_ref:
                        return True
                except (PermissionError, OSError):
                    continue

        # Secondary: dashboard with Pi-hole API calls
        if dashboard_app.exists():
            try:
                text = dashboard_app.read_text(errors="replace")[:4000]
                if "pihole" in text.lower() and "flask" in text.lower():
                    return True
            except (PermissionError, OSError):
                pass

        return False

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        """Walk source tree and extract files, daemons, entitlements,
        observations, and frameworks into the ICARUS database."""
        conn = sqlite3.connect(str(db_path))
        now = datetime.now(timezone.utc).isoformat()
        stats = {
            "files": 0,
            "daemons": 0,
            "entitlements": 0,
            "observations": 0,
            "frameworks": 0,
        }

        # Track what we've found to avoid duplicate observations
        found_services: Set[str] = set()
        found_ips: Set[str] = set()
        found_credentials: Set[str] = set()
        found_frameworks: Set[str] = set()
        found_blocklists: Set[str] = set()
        found_endpoints: Set[str] = set()

        try:
            # ── Phase 1: Walk all files ──────────────────────────────
            for dirpath, _dirs, filenames in os.walk(source, onerror=lambda e: None):
                # Skip hidden dirs, __pycache__, .git
                rel_dir = ""
                try:
                    rel_dir = str(Path(dirpath).relative_to(source)).replace("\\", "/")
                except ValueError:
                    continue
                if any(part.startswith(".") or part == "__pycache__"
                       for part in rel_dir.split("/") if part and part != "."):
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

                        # ── Analyze text files for content extraction ──
                        if st.st_size > 0 and st.st_size < 2_000_000 and ext in (
                            ".py", ".sh", ".md", ".conf", ".toml", ".yaml",
                            ".yml", ".json", ".service", ".sudoers", ".txt",
                            ".html", ".css", ".rules",
                        ):
                            try:
                                text = path.read_text(errors="replace")
                            except (PermissionError, OSError):
                                text = ""

                            if text:
                                self._extract_services(
                                    text, rel, found_services
                                )
                                self._extract_ips(
                                    text, rel, ext, found_ips
                                )
                                self._extract_credentials(
                                    text, rel, found_credentials
                                )
                                self._extract_python_packages(
                                    text, rel, ext, found_frameworks
                                )
                                self._extract_blocklist_urls(
                                    text, rel, found_blocklists
                                )
                                self._extract_endpoints(
                                    text, rel, found_endpoints
                                )

                                # Sudoers files -> entitlements
                                if ext == ".sudoers" or "sudoers" in fname.lower():
                                    self._extract_sudoers(
                                        conn, text, rel, now, stats
                                    )

                                # UFW rules files -> entitlements
                                if "ufw" in rel.lower() or "rules" in fname.lower():
                                    self._extract_ufw_rules(
                                        conn, text, rel, now, stats
                                    )

                                # systemd unit files -> daemons
                                if ext == ".service":
                                    self._extract_systemd_unit(
                                        conn, text, rel, path, now, stats
                                    )

                    except (PermissionError, OSError):
                        continue

                    if stats["files"] % BATCH_COMMIT_INTERVAL == 0:
                        conn.commit()

            # ── Phase 2: Insert collected daemons ────────────────────
            for svc_label in found_services:
                svc_info = KNOWN_SERVICES.get(svc_label, (svc_label, ""))
                unit_name = svc_info[0]
                ports = svc_info[1]
                conn.execute(
                    "INSERT OR IGNORE INTO daemons "
                    "(label,plist_path,program,program_arguments) VALUES (?,?,?,?)",
                    (svc_label, unit_name, "", ports),
                )
                stats["daemons"] += 1

            conn.commit()

            # ── Phase 3: Insert observations ─────────────────────────
            # We attach observations to a synthetic "project" file entry
            project_row = conn.execute(
                "SELECT id FROM files WHERE path=? OR path=?",
                ("/AGENTS.md", "/HANDOFF.md"),
            ).fetchone()
            anchor_table = "files"
            anchor_id = project_row[0] if project_row else 1

            # IP addresses
            for ip_info in sorted(found_ips):
                existing = conn.execute(
                    "SELECT id FROM observations WHERE entity_table=? "
                    "AND entity_id=? AND event_type=? AND properties=?",
                    (anchor_table, anchor_id, "ip_address", ip_info),
                ).fetchone()
                if not existing:
                    conn.execute(
                        "INSERT INTO observations "
                        "(entity_table,entity_id,observed_at,observer,"
                        "event_type,properties,confidence) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (anchor_table, anchor_id, now,
                         "network/privacy_stack", "ip_address",
                         ip_info, 0.90),
                    )
                    stats["observations"] += 1

            # Credentials
            for cred_info in sorted(found_credentials):
                existing = conn.execute(
                    "SELECT id FROM observations WHERE entity_table=? "
                    "AND entity_id=? AND event_type=? AND properties=?",
                    (anchor_table, anchor_id, "credential_found", cred_info),
                ).fetchone()
                if not existing:
                    conn.execute(
                        "INSERT INTO observations "
                        "(entity_table,entity_id,observed_at,observer,"
                        "event_type,properties,confidence) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (anchor_table, anchor_id, now,
                         "network/privacy_stack", "credential_found",
                         cred_info, 0.95),
                    )
                    stats["observations"] += 1

            # Endpoints (WireGuard, DNS upstreams)
            for ep_info in sorted(found_endpoints):
                existing = conn.execute(
                    "SELECT id FROM observations WHERE entity_table=? "
                    "AND entity_id=? AND event_type=? AND properties=?",
                    (anchor_table, anchor_id, "endpoint", ep_info),
                ).fetchone()
                if not existing:
                    conn.execute(
                        "INSERT INTO observations "
                        "(entity_table,entity_id,observed_at,observer,"
                        "event_type,properties,confidence) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (anchor_table, anchor_id, now,
                         "network/privacy_stack", "endpoint",
                         ep_info, 0.85),
                    )
                    stats["observations"] += 1

            conn.commit()

            # ── Phase 4: Insert frameworks (blocklists + packages) ───
            for url in sorted(found_blocklists):
                conn.execute(
                    "INSERT OR IGNORE INTO frameworks "
                    "(name,path,is_private,version) VALUES (?,?,0,?)",
                    (_blocklist_name(url), url, "blocklist"),
                )
                stats["frameworks"] += 1

            for pkg in sorted(found_frameworks):
                pkg_path = f"python/{pkg}"
                conn.execute(
                    "INSERT OR IGNORE INTO frameworks "
                    "(name,path,is_private,version) VALUES (?,?,0,?)",
                    (pkg, pkg_path, "python_package"),
                )
                stats["frameworks"] += 1

            conn.commit()
        finally:
            conn.close()

        return stats

    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        """Link daemons to their config files via observations."""
        conn = sqlite3.connect(str(db_path))
        linked = 0
        now = datetime.now(timezone.utc).isoformat()
        try:
            # Link daemons to files that reference them
            daemons = conn.execute("SELECT id, label FROM daemons").fetchall()
            for daemon_id, label in daemons:
                # Find files mentioning this service
                patterns = KNOWN_SERVICES.get(label, (label, ""))
                unit_name = patterns[0]
                search_terms = {label, unit_name}

                for term in search_terms:
                    if not term:
                        continue
                    # Search in file paths for config references
                    matches = conn.execute(
                        "SELECT id, path FROM files WHERE path LIKE ? "
                        "OR path LIKE ? LIMIT 5",
                        (f"%{term}%", f"%{label}%"),
                    ).fetchall()
                    for file_id, file_path in matches:
                        existing = conn.execute(
                            "SELECT id FROM observations WHERE "
                            "entity_table='daemons' AND entity_id=? "
                            "AND event_type='config_reference' AND properties=?",
                            (daemon_id, file_path),
                        ).fetchone()
                        if not existing:
                            conn.execute(
                                "INSERT INTO observations "
                                "(entity_table,entity_id,observed_at,observer,"
                                "event_type,properties,confidence) "
                                "VALUES (?,?,?,?,?,?,?)",
                                ("daemons", daemon_id, now,
                                 "network/privacy_stack",
                                 "config_reference", file_path, 0.80),
                            )
                            linked += 1
            conn.commit()
        finally:
            conn.close()
        return {"linked": linked}

    def verify(self, db_path: Path) -> Dict[str, Any]:
        """Verify extraction produced expected entities."""
        conn = sqlite3.connect(str(db_path))
        try:
            stats = {}
            for table in ("files", "daemons", "entitlements",
                          "observations", "frameworks"):
                try:
                    count = conn.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    stats[table] = count
                except sqlite3.OperationalError:
                    stats[table] = 0
        finally:
            conn.close()

        if stats.get("files", 0) == 0:
            raise ValueError("Verification failed: files table is empty")
        if stats.get("daemons", 0) == 0:
            raise ValueError(
                "Verification failed: no services detected "
                "(expected Pi-hole, WireGuard, etc.)"
            )
        return stats

    # ------------------------------------------------------------------
    # Private extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_services(text: str, rel_path: str,
                          found: Set[str]) -> None:
        """Scan text for references to known services."""
        for pattern, label in SERVICE_PATTERNS:
            if pattern.search(text):
                found.add(label)

        # Also catch explicit systemctl commands
        for match in SYSTEMCTL_PATTERN.finditer(text):
            unit = match.group(2)
            # Normalize unit names to labels
            unit_clean = unit.replace("wg-quick@", "").replace(".service", "")
            if unit_clean in KNOWN_SERVICES:
                found.add(unit_clean)
            elif unit in KNOWN_SERVICES:
                found.add(unit)
            else:
                # Only add as discovered service if it looks like a valid
                # unit name (contains a letter, not a common English word)
                noise = frozenset({
                    "for", "the", "and", "out", "all", "get", "set",
                    "run", "any", "not", "is", "it", "in", "on",
                    "or", "at", "to", "up", "do", "no", "if",
                })
                if (len(unit_clean) > 2
                        and unit_clean.lower() not in noise
                        and re.match(r"^[\w][\w@.-]+$", unit_clean)):
                    found.add(unit_clean)

    @staticmethod
    def _extract_ips(text: str, rel_path: str, ext: str,
                     found: Set[str]) -> None:
        """Extract IP addresses with context."""
        for match in IP_PATTERN.finditer(text):
            ip = match.group(1)
            # Skip trivially common IPs
            if ip.startswith("0.0.0.0") or ip == "255.255.255.255":  # nosec B104
                continue
            # Include context about where it was found
            context_start = max(0, match.start() - 30)
            context_end = min(len(text), match.end() + 30)
            context = text[context_start:context_end].strip()
            context = re.sub(r"\s+", " ", context)[:80]
            info = json.dumps({
                "ip": ip,
                "file": rel_path,
                "context": context,
            })
            found.add(info)

    @staticmethod
    def _extract_credentials(text: str, rel_path: str,
                             found: Set[str]) -> None:
        """Extract credential references (password assignments, keys)."""
        for pattern in CREDENTIAL_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(1).rstrip("'\"`,;)")
                if len(value) < 3 or value in ("None", "null", "''", '""', "password"):
                    continue
                info = json.dumps({
                    "type": "credential",
                    "file": rel_path,
                    "pattern": match.group(0)[:60],
                })
                found.add(info)

    @staticmethod
    def _extract_python_packages(text: str, rel_path: str, ext: str,
                                 found: Set[str]) -> None:
        """Extract Python package imports."""
        if ext != ".py":
            return
        for match in PYTHON_IMPORT_PATTERN.finditer(text):
            pkg = match.group(1).split(".")[0]
            # Skip stdlib modules
            if pkg in ("os", "sys", "re", "json", "time", "datetime",
                        "pathlib", "subprocess", "hashlib", "sqlite3",
                        "urllib", "socket", "struct", "stat", "shutil",
                        "glob", "io", "abc", "typing", "collections",
                        "functools", "itertools", "contextlib",
                        "dataclasses", "enum", "textwrap", "platform",
                        "tempfile", "copy", "math", "string", "base64",
                        "logging", "argparse", "configparser", "csv",
                        "traceback", "threading", "multiprocessing",
                        "http", "html", "xml", "email", "unittest",
                        "pprint", "warnings", "signal", "ctypes"):
                continue
            found.add(pkg)

    @staticmethod
    def _extract_blocklist_urls(text: str, rel_path: str,
                                found: Set[str]) -> None:
        """Extract blocklist/adlist URLs."""
        for match in BLOCKLIST_URL_PATTERN.finditer(text):
            url = match.group(0).rstrip("'\"`,;)>\\")
            if url and len(url) > 15:
                found.add(url)

        # Also look for plain HTTP URLs in adlist/blocklist context
        if "adlist" in rel_path.lower() or "blocklist" in rel_path.lower():
            for match in re.finditer(r"https?://\S+", text):
                url = match.group(0).rstrip("'\"`,;)>\\")
                # Skip localhost/API URLs and very short URLs
                if (len(url) > 20
                        and "localhost" not in url
                        and "127.0.0.1" not in url
                        and "/api/" not in url
                        and "w3.org" not in url):
                    found.add(url)

    @staticmethod
    def _extract_endpoints(text: str, rel_path: str,
                           found: Set[str]) -> None:
        """Extract WireGuard endpoints and DNS upstream servers."""
        for match in WG_ENDPOINT_PATTERN.finditer(text):
            ep = match.group(1)
            info = json.dumps({
                "type": "wireguard_endpoint",
                "endpoint": ep,
                "file": rel_path,
            })
            found.add(info)

        for match in DNS_UPSTREAM_PATTERN.finditer(text):
            server = match.group(1)
            info = json.dumps({
                "type": "dns_upstream",
                "server": server,
                "file": rel_path,
            })
            found.add(info)

    @staticmethod
    def _extract_sudoers(conn: sqlite3.Connection, text: str,
                         rel_path: str, now: str,
                         stats: Dict[str, int]) -> None:
        """Extract sudoers entries as entitlements.

        Entitlements require a binary_id FK. We create a synthetic binary
        entry for the sudoers file itself so we have a valid FK target.
        """
        entries = SUDOERS_PATTERN.findall(text)
        if not entries:
            return

        # Get or create a file row for the sudoers file
        file_row = conn.execute(
            "SELECT id FROM files WHERE path=?", (rel_path,)
        ).fetchone()
        if not file_row:
            return
        file_id = file_row[0]

        # Create synthetic binary entry as FK target for entitlements
        existing_bin = conn.execute(
            "SELECT id FROM binaries WHERE file_id=?", (file_id,)
        ).fetchone()
        if existing_bin:
            binary_id = existing_bin[0]
        else:
            conn.execute(
                "INSERT INTO binaries (file_id,executable_name,arch) "
                "VALUES (?,?,?)",
                (file_id, "sudoers", "config"),
            )
            binary_id = conn.execute(
                "SELECT id FROM binaries WHERE file_id=?", (file_id,)
            ).fetchone()[0]

        for user, commands in entries:
            for cmd in commands.split(","):
                cmd = cmd.strip()
                if not cmd:
                    continue
                key = f"sudoers:{user}"
                value = cmd
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
                        (binary_id, key, value, "sudoers_rule", 0.95),
                    )
                    stats["entitlements"] += 1

    @staticmethod
    def _extract_ufw_rules(conn: sqlite3.Connection, text: str,
                           rel_path: str, now: str,
                           stats: Dict[str, int]) -> None:
        """Extract UFW firewall rules as entitlements."""
        # Parse ufw allow/deny commands from scripts or docs
        rules: List[str] = []
        for match in UFW_RULE_PATTERN.finditer(text):
            action = match.group(1).strip()
            spec = match.group(2).strip()
            rules.append(f"{action} {spec}")

        # Also parse UFW user.rules format: ### tuple lines
        for match in re.finditer(
            r"^### tuple ###\s*(.+)$", text, re.M
        ):
            rules.append(match.group(1).strip())

        if not rules:
            return

        file_row = conn.execute(
            "SELECT id FROM files WHERE path=?", (rel_path,)
        ).fetchone()
        if not file_row:
            return
        file_id = file_row[0]

        existing_bin = conn.execute(
            "SELECT id FROM binaries WHERE file_id=?", (file_id,)
        ).fetchone()
        if existing_bin:
            binary_id = existing_bin[0]
        else:
            conn.execute(
                "INSERT INTO binaries (file_id,executable_name,arch) "
                "VALUES (?,?,?)",
                (file_id, "ufw_rules", "config"),
            )
            binary_id = conn.execute(
                "SELECT id FROM binaries WHERE file_id=?", (file_id,)
            ).fetchone()[0]

        for rule in rules:
            existing = conn.execute(
                "SELECT id FROM entitlements WHERE binary_id=? "
                "AND key=? AND value=?",
                (binary_id, "ufw_rule", rule),
            ).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO entitlements "
                    "(binary_id,key,value,value_type,confidence) "
                    "VALUES (?,?,?,?,?)",
                    (binary_id, "ufw_rule", rule, "firewall_rule", 0.90),
                )
                stats["entitlements"] += 1

    @staticmethod
    def _extract_systemd_unit(conn: sqlite3.Connection, text: str,
                              rel_path: str, path: Path, now: str,
                              stats: Dict[str, int]) -> None:
        """Extract systemd service unit as a daemon entry."""
        label = path.stem  # filename without .service
        program = ""
        user = ""

        for line in text.splitlines():
            line = line.strip()
            if line.startswith("ExecStart="):
                program = line.split("=", 1)[1].strip()
            elif line.startswith("User="):
                user = line.split("=", 1)[1].strip()

        conn.execute(
            "INSERT OR IGNORE INTO daemons "
            "(label,plist_path,program,user_name) VALUES (?,?,?,?)",
            (label, rel_path, program, user),
        )
        stats["daemons"] += 1


def _blocklist_name(url: str) -> str:
    """Derive a short name from a blocklist URL."""
    # Use the domain + last path segment
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or "unknown"
        path_parts = [p for p in parsed.path.split("/") if p]
        suffix = path_parts[-1] if path_parts else ""
        if suffix and len(suffix) < 60:
            return f"{host}/{suffix}"
        return host
    except Exception:
        return url[:60]
