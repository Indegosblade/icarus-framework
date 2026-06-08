"""
ICARUS Differ — Cross-version intelligence comparison.

Compares two ICARUS databases and identifies what changed between versions:
added entities, removed entities, modified entities, and relationship changes.

Five diff categories:
  ADDITION        — entity exists in new, not in old
  DELETION        — entity exists in old, not in new
  PROPERTY_CHANGE — same entity, different attribute value
  STRUCTURAL      — relationship topology changed (edges, not nodes)
  RESOLUTION_CHANGE — reserved for Phase 2 entity resolution (never produced in v1)
"""

import enum
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from icarus.core import validate_column, validate_table


class DiffCategory(enum.Enum):
    ADDITION = "addition"
    DELETION = "deletion"
    PROPERTY_CHANGE = "property_change"
    STRUCTURAL = "structural"
    RESOLUTION_CHANGE = "resolution_change"


@dataclass
class DiffResult:
    """Result of a cross-version comparison."""
    added: List[Dict[str, Any]]
    removed: List[Dict[str, Any]]
    changed: List[Dict[str, Any]]
    table: str
    key_column: str
    structural: List[Dict[str, Any]] = field(default_factory=list)
    category: Optional[DiffCategory] = None

    @property
    def total_changes(self):
        return len(self.added) + len(self.removed) + len(self.changed) + len(self.structural)

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

        if self.structural:
            lines.append(f"\n### Structural ({len(self.structural)})")
            for item in self.structural[:50]:
                lines.append(f"- {item.get('description', '?')}")

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
        self.conn.execute("ATTACH DATABASE ? AS old_db", (str(self.old_path),))

    def added_entities(self, table: str, key: str) -> DiffResult:
        """Entities present in new DB but not in old DB."""
        table = validate_table(table)
        key = validate_column(key)
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
        table = validate_table(table)
        key = validate_column(key)
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
        table = validate_table(table)
        key = validate_column(key)
        compare = validate_column(compare)
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

    def structural_diff(self) -> DiffResult:
        """Detect relationship topology changes between versions.

        Finds entities whose foreign-key relationships changed even when
        the entity itself still exists in both versions. For example:
        a binary that moved to a different daemon, or an entitlement
        that shifted to a different binary.
        """
        structural_changes = []

        # Binaries whose parent file changed
        rows = self.conn.execute("""
            SELECT n.id, n.executable_name, n.file_id AS new_file_id, o.file_id AS old_file_id
            FROM main.binaries n
            JOIN old_db.binaries o ON n.executable_name = o.executable_name
            WHERE n.file_id != o.file_id
        """).fetchall()
        for r in rows:
            r = dict(r)
            structural_changes.append({
                "type": "binary_file_moved",
                "entity": r.get("executable_name"),
                "old_value": r.get("old_file_id"),
                "new_value": r.get("new_file_id"),
                "description": f"binary '{r.get('executable_name')}' file_id: "
                               f"{r.get('old_file_id')} -> {r.get('new_file_id')}",
            })

        # Sandbox rules whose profile assignment changed
        rows = self.conn.execute("""
            SELECT n.id, n.operation, n.action, n.profile_id AS new_pid, o.profile_id AS old_pid
            FROM main.sandbox_rules n
            JOIN old_db.sandbox_rules o
                ON n.operation = o.operation AND n.action = o.action
            WHERE n.profile_id != o.profile_id
        """).fetchall()
        for r in rows:
            r = dict(r)
            structural_changes.append({
                "type": "sandbox_rule_reassigned",
                "entity": f"{r.get('operation')}:{r.get('action')}",
                "old_value": r.get("old_pid"),
                "new_value": r.get("new_pid"),
                "description": f"sandbox rule '{r.get('operation')}:{r.get('action')}' "
                               f"profile: {r.get('old_pid')} -> {r.get('new_pid')}",
            })

        # Entitlements whose binary assignment changed (same key+value, different binary)
        rows = self.conn.execute("""
            SELECT n.key, n.value, n.binary_id AS new_bid, o.binary_id AS old_bid
            FROM main.entitlements n
            JOIN old_db.entitlements o ON n.key = o.key AND n.value = o.value
            WHERE n.binary_id != o.binary_id
        """).fetchall()
        for r in rows:
            r = dict(r)
            structural_changes.append({
                "type": "entitlement_reassigned",
                "entity": r.get("key"),
                "old_value": r.get("old_bid"),
                "new_value": r.get("new_bid"),
                "description": f"entitlement '{r.get('key')}' "
                               f"binary: {r.get('old_bid')} -> {r.get('new_bid')}",
            })

        return DiffResult(
            added=[], removed=[], changed=[],
            structural=structural_changes,
            table="cross_table",
            key_column="entity",
            category=DiffCategory.STRUCTURAL,
        )

    def full_diff(self) -> Dict[str, DiffResult]:
        """Run diff across all major tables, including structural analysis."""
        results = {}
        results["files_added"] = self.added_entities("files", "path")
        results["files_removed"] = self.removed_entities("files", "path")
        results["files_changed"] = self.changed_entities("files", "path", "sha256")
        results["daemons_added"] = self.added_entities("daemons", "label")
        results["daemons_removed"] = self.removed_entities("daemons", "label")
        results["kexts_added"] = self.added_entities("kexts", "bundle_id")
        results["kexts_removed"] = self.removed_entities("kexts", "bundle_id")
        results["structural"] = self.structural_diff()
        return results

    def generate_report(self) -> str:
        """Generate a full Markdown diff report."""
        results = self.full_diff()
        lines = ["# ICARUS Version Diff\n",
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
