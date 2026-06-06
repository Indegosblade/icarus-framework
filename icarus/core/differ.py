"""
ICARUS Differ — Cross-version intelligence comparison.

Compares two ICARUS databases and identifies what changed between versions:
added entities, removed entities, modified entities, and relationship changes.
"""

import re
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

VALID_TABLES = frozenset({
    "files", "binaries", "daemons", "entitlements",
    "sandbox_profiles", "sandbox_rules", "kexts", "frameworks",
    "metadata", "versions",
})


def _validate_table(name: str) -> str:
    if name not in VALID_TABLES:
        raise ValueError(f"Invalid table name: {name!r}")
    return name


def _validate_column(name: str) -> str:
    if not _IDENTIFIER_RE.match(name):
        raise ValueError(f"Invalid column name: {name!r}")
    return name


@dataclass
class DiffResult:
    """Result of a cross-version comparison."""
    added: List[Dict[str, Any]]
    removed: List[Dict[str, Any]]
    changed: List[Dict[str, Any]]
    table: str
    key_column: str

    @property
    def total_changes(self):
        return len(self.added) + len(self.removed) + len(self.changed)

    def to_markdown(self) -> str:
        lines = [f"## {self.table} diff ({self.total_changes} changes)\n"]

        if self.added:
            lines.append(f"### Added ({len(self.added)})")
            for item in self.added[:50]:
                lines.append(f"- `{item.get(self.key_column, '?')}`")

        if self.removed:
            lines.append(f"\n### Removed ({len(self.removed)})")
            for item in self.removed[:50]:
                lines.append(f"- `{item.get(self.key_column, '?')}`")

        if self.changed:
            lines.append(f"\n### Changed ({len(self.changed)})")
            for item in self.changed[:50]:
                lines.append(f"- `{item.get(self.key_column, '?')}`")

        return "\n".join(lines)


class IcarusDiffer:
    """
    Compare two ICARUS databases for version-to-version analysis.

    Attach both databases and run set-difference queries to find
    what was added, removed, or modified between versions.
    """

    def __init__(self, old_db: str, new_db: str):
        self.old_path = Path(old_db)
        self.new_path = Path(new_db)

        if not self.old_path.exists():
            raise FileNotFoundError(f"Old database not found: {old_db}")
        if not self.new_path.exists():
            raise FileNotFoundError(f"New database not found: {new_db}")

        self.conn = sqlite3.connect(str(self.new_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(f"ATTACH DATABASE ? AS old_db", (str(self.old_path),))

    def added_entities(self, table: str, key: str) -> DiffResult:
        """Entities present in new DB but not in old DB."""
        table = _validate_table(table)
        key = _validate_column(key)
        rows = self.conn.execute(f"""
            SELECT n.* FROM main.[{table}] n
            LEFT JOIN old_db.[{table}] o ON n.[{key}] = o.[{key}]
            WHERE o.[{key}] IS NULL
        """).fetchall()

        return DiffResult(
            added=[dict(r) for r in rows],
            removed=[],
            changed=[],
            table=table,
            key_column=key
        )

    def removed_entities(self, table: str, key: str) -> DiffResult:
        """Entities present in old DB but not in new DB."""
        table = _validate_table(table)
        key = _validate_column(key)
        rows = self.conn.execute(f"""
            SELECT o.* FROM old_db.[{table}] o
            LEFT JOIN main.[{table}] n ON o.[{key}] = n.[{key}]
            WHERE n.[{key}] IS NULL
        """).fetchall()

        return DiffResult(
            added=[],
            removed=[dict(r) for r in rows],
            changed=[],
            table=table,
            key_column=key
        )

    def changed_entities(self, table: str, key: str, compare: str) -> DiffResult:
        """Entities present in both but with different values in compare column."""
        table = _validate_table(table)
        key = _validate_column(key)
        compare = _validate_column(compare)
        rows = self.conn.execute(f"""
            SELECT n.[{key}], o.[{compare}] AS old_value, n.[{compare}] AS new_value
            FROM main.[{table}] n
            JOIN old_db.[{table}] o ON n.[{key}] = o.[{key}]
            WHERE n.[{compare}] != o.[{compare}]
        """).fetchall()

        return DiffResult(
            added=[],
            removed=[],
            changed=[dict(r) for r in rows],
            table=table,
            key_column=key
        )

    def entitlement_diff(self, dangerous_keys: Optional[List[str]] = None) -> Dict[str, DiffResult]:
        """Specialized entitlement comparison across versions."""
        results = {}

        results["new_entitlements"] = self.added_entities("entitlements", "id")

        if dangerous_keys:
            placeholders = ",".join(["?"] * len(dangerous_keys))
            rows = self.conn.execute(f"""
                SELECT e.key, e.value, b.bundle_id
                FROM main.entitlements e
                JOIN main.binaries b ON e.binary_id = b.id
                WHERE e.key IN ({placeholders})
                AND e.key NOT IN (
                    SELECT eo.key FROM old_db.entitlements eo
                    JOIN old_db.binaries bo ON eo.binary_id = bo.id
                    WHERE bo.bundle_id = b.bundle_id AND eo.key = e.key
                )
            """, tuple(dangerous_keys)).fetchall()

            results["new_dangerous"] = DiffResult(
                added=[dict(r) for r in rows],
                removed=[], changed=[],
                table="entitlements", key_column="key"
            )

        return results

    def full_diff(self) -> Dict[str, DiffResult]:
        """Run diff across all major tables."""
        results = {}
        results["files_added"] = self.added_entities("files", "path")
        results["files_removed"] = self.removed_entities("files", "path")
        results["files_changed"] = self.changed_entities("files", "path", "sha256")
        results["daemons_added"] = self.added_entities("daemons", "label")
        results["daemons_removed"] = self.removed_entities("daemons", "label")
        results["kexts_added"] = self.added_entities("kexts", "bundle_id")
        results["kexts_removed"] = self.removed_entities("kexts", "bundle_id")
        return results

    def generate_report(self) -> str:
        """Generate a full Markdown diff report."""
        results = self.full_diff()
        lines = [f"# ICARUS Version Diff\n",
                 f"Old: `{self.old_path.name}`\n",
                 f"New: `{self.new_path.name}`\n",
                 "---\n"]

        for name, diff in results.items():
            if diff.total_changes > 0:
                lines.append(diff.to_markdown())
                lines.append("")

        return "\n".join(lines)

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
