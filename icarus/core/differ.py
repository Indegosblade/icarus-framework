"""
ICARUS Differ — Cross-version intelligence comparison.

Compares two ICARUS databases and identifies what changed between versions:
added entities, removed entities, modified entities, and relationship changes.

Five diff categories:
  ADDITION        — entity exists in new, not in old
  DELETION        — entity exists in old, not in new
  PROPERTY_CHANGE — same entity, different attribute value
  STRUCTURAL      — relationship topology changed (edges, not nodes)
  RESOLUTION_CHANGE — entity resolution changes (Phase 2)
"""

import enum
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from icarus.core import validate_column, validate_table

DIFF_DISPLAY_LIMIT = 50


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
    def total_changes(self) -> int:
        return len(self.added) + len(self.removed) + len(self.changed) + len(self.structural)

    def to_markdown(self) -> str:
        lines = [f"## {self.table} diff ({self.total_changes} changes)\n"]

        if self.added:
            lines.append(f"### Added ({len(self.added)})")
            for item in self.added[:DIFF_DISPLAY_LIMIT]:
                lines.append(f"- `{item.get(self.key_column, '?')}`")

        if self.removed:
            lines.append(f"\n### Removed ({len(self.removed)})")
            for item in self.removed[:DIFF_DISPLAY_LIMIT]:
                lines.append(f"- `{item.get(self.key_column, '?')}`")

        if self.changed:
            lines.append(f"\n### Changed ({len(self.changed)})")
            for item in self.changed[:DIFF_DISPLAY_LIMIT]:
                lines.append(f"- `{item.get(self.key_column, '?')}`")

        if self.structural:
            lines.append(f"\n### Structural ({len(self.structural)})")
            for item in self.structural[:DIFF_DISPLAY_LIMIT]:
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

        # Diff never writes: open both databases immutable read-only via URI so
        # an untrusted export can never be mutated (and no -wal/-shm is created).
        self.conn = sqlite3.connect(
            f"file:{self.new_path}?mode=ro&immutable=1", uri=True
        )
        try:
            self.conn.row_factory = sqlite3.Row
            self.conn.execute(
                "ATTACH DATABASE ? AS old_db",
                (f"file:{self.old_path}?mode=ro&immutable=1",),
            )
        except Exception:
            self.conn.close()
            raise

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
            WHERE n.[{compare}] IS NOT o.[{compare}]
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

        # Diff on the natural key (owning binary's bundle_id + entitlement
        # key/value), NOT the autoincrement id, which is assigned independently
        # in each DB and so carries no cross-version meaning.
        new_rows = self.conn.execute("""
            SELECT e.key, e.value, b.bundle_id, e.binary_id
            FROM main.entitlements e
            JOIN main.binaries b ON e.binary_id = b.id
            WHERE NOT EXISTS (
                SELECT 1 FROM old_db.entitlements eo
                JOIN old_db.binaries bo ON eo.binary_id = bo.id
                WHERE bo.bundle_id IS b.bundle_id
                  AND eo.key = e.key
                  AND eo.value = e.value
            )
        """).fetchall()
        results["new_entitlements"] = DiffResult(
            added=[dict(r) for r in new_rows],
            removed=[], changed=[],
            table="entitlements", key_column="key",
        )

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

        # Binaries whose parent file changed.
        # executable_name is not unique, so restrict to names that identify
        # exactly one binary on each side; otherwise the join Cartesian-products
        # duplicates into false "moved" rows. Ambiguous names are skipped.
        rows = self.conn.execute("""
            SELECT n.executable_name,
                   n.file_id AS new_file_id, o.file_id AS old_file_id
            FROM (
                SELECT executable_name, file_id FROM main.binaries
                WHERE executable_name IS NOT NULL
                GROUP BY executable_name HAVING COUNT(*) = 1
            ) n
            JOIN (
                SELECT executable_name, file_id FROM old_db.binaries
                WHERE executable_name IS NOT NULL
                GROUP BY executable_name HAVING COUNT(*) = 1
            ) o ON n.executable_name = o.executable_name
            WHERE n.file_id IS NOT o.file_id
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

        # Sandbox rules whose profile assignment changed.
        # (operation, action) is not unique; restrict to pairs identifying
        # exactly one rule on each side so duplicates cannot cross-product.
        rows = self.conn.execute("""
            SELECT n.operation, n.action,
                   n.profile_id AS new_pid, o.profile_id AS old_pid
            FROM (
                SELECT operation, action, profile_id FROM main.sandbox_rules
                GROUP BY operation, action HAVING COUNT(*) = 1
            ) n
            JOIN (
                SELECT operation, action, profile_id FROM old_db.sandbox_rules
                GROUP BY operation, action HAVING COUNT(*) = 1
            ) o ON n.operation = o.operation AND n.action = o.action
            WHERE n.profile_id IS NOT o.profile_id
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

        # Entitlements whose binary assignment changed (same key+value,
        # different binary). (key, value) is not unique; restrict to pairs
        # identifying exactly one entitlement on each side so duplicates
        # cannot cross-product into false "reassigned" rows.
        rows = self.conn.execute("""
            SELECT n.key, n.value,
                   n.binary_id AS new_bid, o.binary_id AS old_bid
            FROM (
                SELECT key, value, binary_id FROM main.entitlements
                GROUP BY key, value HAVING COUNT(*) = 1
            ) n
            JOIN (
                SELECT key, value, binary_id FROM old_db.entitlements
                GROUP BY key, value HAVING COUNT(*) = 1
            ) o ON n.key = o.key AND n.value = o.value
            WHERE n.binary_id IS NOT o.binary_id
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

    def observation_diff(self) -> DiffResult:
        """Diff observation records between old and new databases."""
        added_rows = self.conn.execute("""
            SELECT n.entity_table, n.entity_id, n.event_type, n.observed_at
            FROM main.observations n
            LEFT JOIN old_db.observations o
                ON n.entity_table = o.entity_table
                AND n.entity_id = o.entity_id
                AND n.event_type = o.event_type
                AND n.observed_at = o.observed_at
            WHERE o.id IS NULL
        """).fetchall()

        removed_rows = self.conn.execute("""
            SELECT o.entity_table, o.entity_id, o.event_type, o.observed_at
            FROM old_db.observations o
            LEFT JOIN main.observations n
                ON o.entity_table = n.entity_table
                AND o.entity_id = n.entity_id
                AND o.event_type = n.event_type
                AND o.observed_at = n.observed_at
            WHERE n.id IS NULL
        """).fetchall()

        return DiffResult(
            added=[dict(r) for r in added_rows],
            removed=[dict(r) for r in removed_rows],
            changed=[],
            table="observations",
            key_column="entity_table",
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

    def close(self) -> None:
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
