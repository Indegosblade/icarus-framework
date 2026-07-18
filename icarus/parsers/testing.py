"""ICARUS Parser Testing Harness — quality gates for parser production tier."""

import hashlib
import json
import sqlite3
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from icarus.core.schema import open_db
from icarus.parsers.base import BaseParser
from icarus.parsers.manifest import ParserManifest


@dataclass
class HarnessResult:
    test_name: str
    passed: bool
    message: str = ""
    details: dict = field(default_factory=dict)


class ParserTestHarness:
    """Four mandatory tests for parser production tier."""

    def __init__(self, parser: BaseParser, manifest: ParserManifest, fixtures_dir: Path):
        if not fixtures_dir.exists():
            raise FileNotFoundError(f"Fixtures directory not found: {fixtures_dir}")
        self.parser = parser
        self.manifest = manifest
        self.fixtures_dir = fixtures_dir

    def test_golden_output(self) -> HarnessResult:
        """Run parser on fixture; compare entity counts, a deterministic
        content fingerprint, and the golden file's own declared zero_pii /
        has_relationships / observation_count fields (checked only when the
        golden file declares them, so older golden files without those keys
        still validate on counts alone)."""
        golden_path = self.manifest.tests.get("golden_output") if self.manifest.tests else None
        if not golden_path:
            return HarnessResult("golden_output", False, "No golden_output path in manifest")

        golden_file = Path(golden_path)
        if not golden_file.is_absolute():
            golden_file = Path(__file__).parent.parent.parent / golden_path
        if not golden_file.exists():
            return HarnessResult("golden_output", False, f"Golden file not found: {golden_file}")

        golden = json.loads(golden_file.read_text())
        db_path = self._run_parser()

        try:
            conn = open_db(db_path)
            try:
                actual_counts = {}
                for table in golden.get("entity_counts", {}):
                    try:
                        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # nosec B608 - table keys come from the in-repo tests/golden/*.json fixture, not external input
                        actual_counts[table] = count
                    except sqlite3.OperationalError:
                        actual_counts[table] = 0

                expected = golden["entity_counts"]
                if actual_counts != expected:
                    return HarnessResult(
                        "golden_output", False,
                        f"Mismatch: expected {expected}, got {actual_counts}",
                        {"expected": expected, "actual": actual_counts},
                    )

                mismatches = []

                if "content_fingerprint" in golden:
                    actual_fp = self._content_fingerprint(conn, list(expected.keys()))
                    if actual_fp != golden["content_fingerprint"]:
                        mismatches.append(
                            f"content_fingerprint mismatch: expected "
                            f"{golden['content_fingerprint']}, got {actual_fp}"
                        )

                if "observation_count" in golden:
                    try:
                        actual_obs = conn.execute(
                            "SELECT COUNT(*) FROM observations"
                        ).fetchone()[0]
                    except sqlite3.OperationalError:
                        actual_obs = 0
                    if actual_obs != golden["observation_count"]:
                        mismatches.append(
                            f"observation_count mismatch: expected "
                            f"{golden['observation_count']}, got {actual_obs}"
                        )

                if "zero_pii" in golden:
                    from icarus.integrations.hygeia import verify_clean
                    actual_zero_pii = verify_clean(db_path)["passed"]
                    if actual_zero_pii != golden["zero_pii"]:
                        mismatches.append(
                            f"zero_pii mismatch: golden declares {golden['zero_pii']}, "
                            f"actual {actual_zero_pii}"
                        )

                if "has_relationships" in golden:
                    rel_stats = self.parser.extract_relationships(self.fixtures_dir, db_path)
                    actual_has_rel = bool(rel_stats.get("linked", 0))
                    if actual_has_rel != golden["has_relationships"]:
                        mismatches.append(
                            f"has_relationships mismatch: golden declares "
                            f"{golden['has_relationships']}, actual {actual_has_rel}"
                        )
            finally:
                conn.close()

            if mismatches:
                return HarnessResult("golden_output", False, "; ".join(mismatches))
            return HarnessResult(
                "golden_output", True, "Entity counts and declared fields match golden file"
            )
        finally:
            db_path.unlink(missing_ok=True)

    @staticmethod
    def _content_fingerprint(conn: sqlite3.Connection, tables: List[str]) -> str:
        """Deterministic sha256 fingerprint of row content across `tables`.

        Excludes the `id` autoincrement primary key (a storage detail, not
        content) from both the selected columns and the ordering, so the
        fingerprint reflects only actual field values and is stable
        regardless of row insertion order.
        """
        hasher = hashlib.sha256()
        for table in sorted(tables):
            try:
                cols = [
                    r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()
                    if r[1] != "id"
                ]
            except sqlite3.OperationalError:
                continue
            if not cols:
                continue
            col_list = ", ".join(cols)
            try:
                rows = conn.execute(
                    f"SELECT {col_list} FROM {table} ORDER BY {col_list}"  # nosec B608 - table/col_list sourced from golden-fixture keys and this table's own PRAGMA table_info(), not external input
                ).fetchall()
            except sqlite3.OperationalError:
                continue
            hasher.update(table.encode())
            for row in rows:
                hasher.update(repr(row).encode())
        return hasher.hexdigest()

    def test_schema_conformance(self) -> HarnessResult:
        """All emitted entities are in tables declared in manifest.produces
        .entity_types, and (when the manifest declares event_types) every
        observation.event_type produced on the fixture is one of them."""
        db_path = self._run_parser()
        try:
            conn = open_db(db_path)
            try:
                declared = set(self.manifest.entity_types)
                violations = []

                all_tables = [
                    r[0] for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                ]
                skip = {"metadata", "versions", "observations", "atoms", "bags",
                        "bag_atoms", "resolution_event_log", "match_candidates",
                        "sqlite_sequence"}
                for table in all_tables:
                    if table in skip or table.endswith("_fts") or "_fts_" in table:
                        continue
                    if table not in declared:
                        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # nosec B608 - table read directly from sqlite_master of the harness's own temp DB above
                        if count > 0:
                            violations.append(f"{table} has {count} rows but not in produces")

                declared_event_types = self.manifest.produces.get("event_types")
                if declared_event_types is not None:
                    try:
                        actual_event_types = {
                            r[0] for r in conn.execute(
                                "SELECT DISTINCT event_type FROM observations"
                            ).fetchall()
                        }
                    except sqlite3.OperationalError:
                        actual_event_types = set()
                    undeclared = actual_event_types - set(declared_event_types)
                    if undeclared:
                        violations.append(
                            "observations produced event_type(s) not in "
                            f"manifest.produces.event_types: {sorted(undeclared)}"
                        )
            finally:
                conn.close()

            if violations:
                return HarnessResult("schema_conformance", False, "; ".join(violations))
            return HarnessResult("schema_conformance", True, "All entities in declared tables")
        finally:
            db_path.unlink(missing_ok=True)

    def test_idempotency(self) -> HarnessResult:
        """Run parser twice on same fixture, second run should add 0 new rows."""
        db_path = self._run_parser()
        try:
            conn = open_db(db_path)
            try:
                counts_first = {}
                for table in self.manifest.entity_types:
                    try:
                        counts_first[table] = conn.execute(
                            f"SELECT COUNT(*) FROM {table}"  # nosec B608 - table iterates manifest.entity_types, a dev-authored in-repo YAML field, not external input
                        ).fetchone()[0]
                    except sqlite3.OperationalError:
                        counts_first[table] = 0
            finally:
                conn.close()

            self.parser.extract_entities(self.fixtures_dir, db_path)

            conn = open_db(db_path)
            try:
                counts_second = {}
                for table in self.manifest.entity_types:
                    try:
                        counts_second[table] = conn.execute(
                            f"SELECT COUNT(*) FROM {table}"  # nosec B608 - table iterates manifest.entity_types, a dev-authored in-repo YAML field, not external input
                        ).fetchone()[0]
                    except sqlite3.OperationalError:
                        counts_second[table] = 0
            finally:
                conn.close()

            if counts_first == counts_second:
                return HarnessResult("idempotency", True, "Second run added 0 entities")
            return HarnessResult(
                "idempotency", False,
                f"Counts changed: {counts_first} -> {counts_second}",
            )
        finally:
            db_path.unlink(missing_ok=True)

    def test_zero_pii(self) -> HarnessResult:
        """Run HYGEIA verify_clean() on output — must return passed: True."""
        from icarus.integrations.hygeia import verify_clean

        db_path = self._run_parser()
        try:
            result = verify_clean(db_path)
            if result["passed"]:
                return HarnessResult("zero_pii", True, "No PII detected")
            return HarnessResult(
                "zero_pii", False,
                f"{result['total_findings']} PII findings",
                {"findings": result["findings"][:5]},
            )
        finally:
            db_path.unlink(missing_ok=True)

    def run_all(self) -> List[HarnessResult]:
        results = [
            self.test_golden_output(),
            self.test_schema_conformance(),
            self.test_idempotency(),
            self.test_zero_pii(),
        ]
        for r in results:
            status = "PASS" if r.passed else "FAIL"
            print(f"  [{status}] {r.test_name}: {r.message}")
        return results

    def _run_parser(self) -> Path:
        """Run the parser on fixtures and return the DB path."""
        from icarus.core.schema import initialize_database

        f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db_path = Path(f.name)
        f.close()
        initialize_database(db_path, {"source": str(self.fixtures_dir)})
        self.parser.extract_entities(self.fixtures_dir, db_path)
        return db_path
