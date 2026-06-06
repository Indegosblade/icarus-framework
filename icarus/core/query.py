"""
ICARUS Query Engine — SQL interface with full-text search and intelligence views.

Provides both raw SQL access and pre-built intelligence queries
for common patterns (privilege escalation surface, anomalies, etc.).
"""

import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Any, Optional


class QueryResult:
    """Structured query result with metadata."""

    def __init__(self, rows: List[tuple], columns: List[str], query_name: str = ""):
        self.rows = rows
        self.columns = columns
        self.query_name = query_name

    @property
    def count(self):
        return len(self.rows)

    def as_dicts(self) -> List[Dict[str, Any]]:
        return [dict(zip(self.columns, row)) for row in self.rows]

    def to_markdown(self) -> str:
        if not self.rows:
            return f"*{self.query_name}: No results.*\n"

        lines = []
        if self.query_name:
            lines.append(f"### {self.query_name} ({self.count} results)\n")

        lines.append("| " + " | ".join(self.columns) + " |")
        lines.append("| " + " | ".join(["---"] * len(self.columns)) + " |")

        for row in self.rows[:100]:
            cells = []
            for v in row:
                s = str(v) if v is not None else ""
                if len(s) > 60:
                    s = s[:57] + "..."
                cells.append(s)
            lines.append("| " + " | ".join(cells) + " |")

        if self.count > 100:
            lines.append(f"\n*... and {self.count - 100} more rows.*")

        return "\n".join(lines)


VALID_TABLES = frozenset({
    "files", "binaries", "daemons", "entitlements",
    "sandbox_profiles", "sandbox_rules", "kexts", "frameworks",
    "metadata", "versions",
})

VALID_FTS_TABLES = frozenset({"files", "daemons"})


def _validate_identifier(name: str, allowed: frozenset, kind: str = "table") -> str:
    if name not in allowed:
        raise ValueError(f"Invalid {kind} name: {name!r}")
    return name


class IcarusQuery:
    """
    Query engine for ICARUS intelligence databases.

    Supports raw SQL, full-text search, and pre-built intelligence queries.
    """

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {db_path}")
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

    def execute(self, sql: str, params: tuple = ()) -> QueryResult:
        """Execute raw SQL and return structured result."""
        cursor = self.conn.execute(sql, params)
        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        rows = cursor.fetchall()
        return QueryResult([tuple(r) for r in rows], columns)

    def search(self, query: str, table: str = "files") -> QueryResult:
        """Full-text search via FTS5."""
        table = _validate_identifier(table, VALID_FTS_TABLES)
        fts_table = f"{table}_fts"
        sql = f"""
            SELECT * FROM {table}
            WHERE id IN (SELECT rowid FROM {fts_table} WHERE {fts_table} MATCH ?)
            LIMIT 100
        """
        return self.execute(sql, (query,))

    def root_daemons(self) -> QueryResult:
        """Daemons running as root with no sandbox."""
        result = self.execute("""
            SELECT label, program, mach_services
            FROM daemons
            WHERE (user_name = 'root' OR user_name IS NULL)
              AND (sandbox_profile IS NULL OR sandbox_profile = '')
            ORDER BY label
        """)
        result.query_name = "Root Daemons (No Sandbox)"
        return result

    def privileged_entitlements(self, keys: Optional[List[str]] = None) -> QueryResult:
        """Binaries holding specified privileged entitlements."""
        default_keys = [
            "com.apple.private.security.no-sandbox",
            "com.apple.private.skip-library-validation",
            "task_for_pid-allow",
            "platform-application",
        ]
        search_keys = keys or default_keys
        placeholders = ",".join(["?"] * len(search_keys))
        result = self.execute(f"""
            SELECT e.key, e.value, b.bundle_id, f.path
            FROM entitlements e
            JOIN binaries b ON e.binary_id = b.id
            JOIN files f ON b.file_id = f.id
            WHERE e.key IN ({placeholders})
            ORDER BY e.key, b.bundle_id
        """, tuple(search_keys))
        result.query_name = "Privileged Entitlements"
        return result

    def service_map(self) -> QueryResult:
        """All MachServices mapped to their daemons."""
        result = self.execute("""
            SELECT label, mach_services, sandbox_profile, user_name
            FROM daemons
            WHERE mach_services IS NOT NULL
            ORDER BY label
        """)
        result.query_name = "MachService Map"
        return result

    def kernel_surface(self) -> QueryResult:
        """IOKit classes with UserClients (kernel-reachable)."""
        result = self.execute("SELECT * FROM v_kernel_attack_surface")
        result.query_name = "Kernel Attack Surface"
        return result

    def test_binaries(self) -> QueryResult:
        """Debug/test artifacts in production."""
        result = self.execute("SELECT * FROM v_test_binaries")
        result.query_name = "Test Binaries in Production"
        return result

    def escape_surface(self) -> QueryResult:
        """Privileged daemons reachable via mach-lookup."""
        result = self.execute("SELECT * FROM v_sandbox_escape_surface")
        result.query_name = "Sandbox Escape Surface"
        return result

    def stats(self) -> Dict[str, int]:
        """Database statistics."""
        counts = {}
        for table in sorted(VALID_TABLES - {"metadata", "versions"}):
            try:
                row = self.conn.execute(f"SELECT COUNT(*) FROM [{table}]").fetchone()
                counts[table] = row[0]
            except sqlite3.OperationalError:
                counts[table] = 0
        return counts

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
