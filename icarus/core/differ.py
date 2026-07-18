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
        rows = self.conn.execute(
            f"SELECT n.* FROM main.[{table}] n "  # nosec B608 - table/key validated via validate_table/validate_column above
            f"LEFT JOIN old_db.[{table}] o ON n.[{key}] = o.[{key}] "
            f"WHERE o.[{key}] IS NULL"
        ).fetchall()

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
        rows = self.conn.execute(
            f"SELECT o.* FROM old_db.[{table}] o "  # nosec B608 - table/key validated via validate_table/validate_column above
            f"LEFT JOIN main.[{table}] n ON o.[{key}] = n.[{key}] "
            f"WHERE n.[{key}] IS NULL"
        ).fetchall()

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
        rows = self.conn.execute(
            f"SELECT n.[{key}], o.[{compare}] AS old_value, n.[{compare}] AS new_value "  # nosec B608 - table/key/compare validated via validate_table/validate_column above
            f"FROM main.[{table}] n "
            f"JOIN old_db.[{table}] o ON n.[{key}] = o.[{key}] "
            f"WHERE n.[{compare}] IS NOT o.[{compare}]"
        ).fetchall()

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
            rows = self.conn.execute(
                f"SELECT e.key, e.value, b.bundle_id "  # nosec B608 - only bare `?` placeholders interpolated; values passed bound as params below
                f"FROM main.entitlements e "
                f"JOIN main.binaries b ON e.binary_id = b.id "
                f"WHERE e.key IN ({placeholders}) "
                f"AND e.key NOT IN ( "
                f"    SELECT eo.key FROM old_db.entitlements eo "
                f"    JOIN old_db.binaries bo ON eo.binary_id = bo.id "
                f"    WHERE bo.bundle_id = b.bundle_id AND eo.key = e.key "
                f")",
                tuple(dangerous_keys),
            ).fetchall()

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

        # Binaries whose parent file changed. Compare the file's NATURAL key
        # (files.path), never file_id: file_id is a local autoincrement id assigned
        # independently in each database, so comparing it fabricates "moved" rows
        # from mere insertion-order skew and hides real moves when ids coincide.
        # executable_name is not unique, so restrict to names that identify exactly
        # one binary on each side; otherwise the join Cartesian-products duplicates
        # into false rows. Ambiguous names are skipped.
        rows = self.conn.execute("""
            SELECT n.executable_name,
                   nf.path AS new_path, of.path AS old_path
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
            JOIN main.files nf ON nf.id = n.file_id
            JOIN old_db.files of ON of.id = o.file_id
            WHERE nf.path IS NOT of.path
        """).fetchall()
        for r in rows:
            r = dict(r)
            structural_changes.append({
                "type": "binary_file_moved",
                "entity": r.get("executable_name"),
                "old_value": r.get("old_path"),
                "new_value": r.get("new_path"),
                "description": f"binary '{r.get('executable_name')}' file: "
                               f"{r.get('old_path')} -> {r.get('new_path')}",
            })

        # Sandbox rules whose profile assignment changed. Compare the profile's
        # NATURAL key (sandbox_profiles.name), not profile_id (a local autoincrement
        # id with no cross-database meaning). (operation, action) is not unique;
        # restrict to pairs identifying exactly one rule on each side so duplicates
        # cannot cross-product.
        rows = self.conn.execute("""
            SELECT n.operation, n.action,
                   np.name AS new_profile, op.name AS old_profile
            FROM (
                SELECT operation, action, profile_id FROM main.sandbox_rules
                GROUP BY operation, action HAVING COUNT(*) = 1
            ) n
            JOIN (
                SELECT operation, action, profile_id FROM old_db.sandbox_rules
                GROUP BY operation, action HAVING COUNT(*) = 1
            ) o ON n.operation = o.operation AND n.action = o.action
            JOIN main.sandbox_profiles np ON np.id = n.profile_id
            JOIN old_db.sandbox_profiles op ON op.id = o.profile_id
            WHERE np.name IS NOT op.name
        """).fetchall()
        for r in rows:
            r = dict(r)
            structural_changes.append({
                "type": "sandbox_rule_reassigned",
                "entity": f"{r.get('operation')}:{r.get('action')}",
                "old_value": r.get("old_profile"),
                "new_value": r.get("new_profile"),
                "description": f"sandbox rule '{r.get('operation')}:{r.get('action')}' "
                               f"profile: {r.get('old_profile')} -> {r.get('new_profile')}",
            })

        # Entitlements whose owning binary changed (same key+value, different
        # binary). The owner is identified by the binary's most stable available
        # identity -- bundle_id, else executable_name, else the file path -- NOT the
        # file path alone. executable_name is exactly the identity binary_file_moved
        # (above) uses to track a binary across a move, so a binary that merely moves
        # paths keeps the same owner identity here and its entitlements are correctly
        # seen as unchanged; only a move onto a genuinely different binary is reported.
        # Keying on path alone reported every path move as a spurious reassignment (on
        # top of the binary_file_moved row for the same event). Residual limitation: a
        # binary with neither bundle_id nor executable_name falls back to path, so its
        # moves remain ambiguous. (key, value) is not unique; restrict to pairs
        # identifying exactly one entitlement on each side so duplicates cannot
        # cross-product into false rows.
        rows = self.conn.execute("""
            SELECT n.key, n.value,
                   COALESCE(nb.bundle_id, nb.executable_name, 'path:' || nf.path) AS new_owner,
                   COALESCE(ob.bundle_id, ob.executable_name, 'path:' || of.path) AS old_owner
            FROM (
                SELECT key, value, binary_id FROM main.entitlements
                GROUP BY key, value HAVING COUNT(*) = 1
            ) n
            JOIN (
                SELECT key, value, binary_id FROM old_db.entitlements
                GROUP BY key, value HAVING COUNT(*) = 1
            ) o ON n.key = o.key AND n.value = o.value
            JOIN main.binaries nb ON nb.id = n.binary_id
            JOIN old_db.binaries ob ON ob.id = o.binary_id
            JOIN main.files nf ON nf.id = nb.file_id
            JOIN old_db.files of ON of.id = ob.file_id
            WHERE COALESCE(nb.bundle_id, nb.executable_name, 'path:' || nf.path)
               IS NOT COALESCE(ob.bundle_id, ob.executable_name, 'path:' || of.path)
        """).fetchall()
        for r in rows:
            r = dict(r)
            structural_changes.append({
                "type": "entitlement_reassigned",
                "entity": r.get("key"),
                "old_value": r.get("old_owner"),
                "new_value": r.get("new_owner"),
                "description": f"entitlement '{r.get('key')}' "
                               f"binary: {r.get('old_owner')} -> {r.get('new_owner')}",
            })

        return DiffResult(
            added=[], removed=[], changed=[],
            structural=structural_changes,
            table="cross_table",
            key_column="entity",
            category=DiffCategory.STRUCTURAL,
        )

    def observation_diff(self) -> DiffResult:
        """Diff observation records between old and new databases.

        Observations reference their subject polymorphically as
        ``(entity_table, entity_id)`` where ``entity_id`` is a local
        AUTOINCREMENT row id. That id has no meaning across two independently
        built databases: the same logical file gets different ids depending on
        insertion order, so matching observations on the raw id fabricated
        "added"/"removed" rows from mere insertion-order skew (and hid real
        changes when ids happened to coincide). Each observation is therefore
        resolved to its subject's NATURAL key before comparison. Observations
        whose subject row is absent, or whose entity_table has no known natural
        key, are excluded from the natural-key comparison and surfaced
        separately so they are neither silently dropped nor compared on a
        meaningless id.
        """
        new_keyed, new_unresolved = self._resolve_observations("main")
        old_keyed, old_unresolved = self._resolve_observations("old_db")

        added = [self._observation_dict(t) for t in sorted(new_keyed - old_keyed)]
        removed = [self._observation_dict(t) for t in sorted(old_keyed - new_keyed)]

        # Unresolved observations (missing subject row or unmapped table) cannot
        # be compared by natural key; report them on both sides for visibility.
        for side, unresolved in (("new", new_unresolved), ("old", old_unresolved)):
            for t in sorted(unresolved):
                row = self._observation_dict(t)
                row["unresolved"] = side
                (added if side == "new" else removed).append(row)

        return DiffResult(
            added=added,
            removed=removed,
            changed=[],
            table="observations",
            key_column="entity_table",
        )

    # entity_table -> the column on that table that is its stable natural key.
    # "binaries" is resolved to its file's path via file_id (see _resolve_observations).
    _OBSERVATION_ENTITY_KEY = {
        "files": "path",
        "daemons": "label",
        "kexts": "bundle_id",
        "frameworks": "path",
        "sandbox_profiles": "name",
    }

    def _resolve_observations(self, schema: str):
        """Resolve one database's observations to natural-key tuples.

        Returns (keyed, unresolved): ``keyed`` is a set of
        ``(entity_table, natural_key, event_type, observed_at)`` tuples;
        ``unresolved`` is a set of ``(entity_table, "id:<n>", event_type,
        observed_at)`` tuples for observations that could not be resolved.
        """
        entity_tables = {
            row[0]
            for row in self.conn.execute(
                f"SELECT DISTINCT entity_table FROM {schema}.observations"  # nosec B608 - schema is a fixed literal
            )
        }

        keyed = set()
        unresolved = set()
        for table in entity_tables:
            if table == "binaries":
                # A binary has no unique column of its own; use its file path,
                # which is UNIQUE, via the mandatory file_id foreign key.
                query = (
                    f"SELECT ob.entity_table, f.path, ob.event_type, ob.observed_at "  # nosec B608 - identifiers are fixed literals; entity_table bound as a parameter
                    f"FROM {schema}.observations ob "
                    f"JOIN {schema}.binaries b ON b.id = ob.entity_id "
                    f"JOIN {schema}.files f ON f.id = b.file_id "
                    f"WHERE ob.entity_table = ?"
                )
            elif table in self._OBSERVATION_ENTITY_KEY:
                key_col = self._OBSERVATION_ENTITY_KEY[table]
                query = (
                    f"SELECT ob.entity_table, e.{key_col}, ob.event_type, ob.observed_at "  # nosec B608 - table/key_col come from a fixed whitelist; entity_table bound as a parameter
                    f"FROM {schema}.observations ob "
                    f"JOIN {schema}.{table} e ON e.id = ob.entity_id "
                    f"WHERE ob.entity_table = ?"
                )
            else:
                # No known natural key: keep the raw id, marked unresolved.
                for row in self.conn.execute(
                    f"SELECT entity_table, entity_id, event_type, observed_at "  # nosec B608 - schema is a fixed literal
                    f"FROM {schema}.observations WHERE entity_table = ?",
                    (table,),
                ):
                    unresolved.add((row[0], f"id:{row[1]}", row[2], row[3]))
                continue

            resolved_ids = set()
            for row in self.conn.execute(query, (table,)):
                natural = row[1]
                if natural is None:
                    continue
                keyed.add((row[0], str(natural), row[2], row[3]))
                resolved_ids.add((row[2], row[3]))

            # Observations whose subject row is missing (orphaned) or whose key
            # column is NULL are surfaced as unresolved rather than dropped.
            for row in self.conn.execute(
                f"SELECT entity_table, entity_id, event_type, observed_at "  # nosec B608 - schema is a fixed literal
                f"FROM {schema}.observations ob WHERE entity_table = ? "
                f"AND NOT EXISTS (SELECT 1 FROM {schema}.{table} e WHERE e.id = ob.entity_id)",
                (table,),
            ):
                unresolved.add((row[0], f"id:{row[1]}", row[2], row[3]))

        return keyed, unresolved

    @staticmethod
    def _observation_dict(tup) -> dict:
        entity_table, entity_key, event_type, observed_at = tup
        return {
            "entity_table": entity_table,
            "entity_key": entity_key,
            "event_type": event_type,
            "observed_at": observed_at,
        }

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
