"""ICARUS Parser Testing Harness — quality gates for parser production tier."""

import json
import sqlite3
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

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
        """Run parser on fixture, compare entity counts and types to golden file."""
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
            conn = sqlite3.connect(str(db_path))
            try:
                actual_counts = {}
                for table in golden.get("entity_counts", {}):
                    try:
                        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                        actual_counts[table] = count
                    except sqlite3.OperationalError:
                        actual_counts[table] = 0
            finally:
                conn.close()

            expected = golden["entity_counts"]
            if actual_counts == expected:
                return HarnessResult("golden_output", True, "Entity counts match golden file")

            return HarnessResult(
                "golden_output", False,
                f"Mismatch: expected {expected}, got {actual_counts}",
                {"expected": expected, "actual": actual_counts},
            )
        finally:
            db_path.unlink(missing_ok=True)

    def test_schema_conformance(self) -> HarnessResult:
        """All emitted entities are in tables declared in manifest.produces.entity_types."""
        db_path = self._run_parser()
        try:
            conn = sqlite3.connect(str(db_path))
            try:
                declared = set(self.manifest.entity_types)
                violations = []
                for table in declared:
                    try:
                        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                        if count > 0 and table not in declared:
                            violations.append(
                                f"{table} has {count} rows but not declared in produces")
                    except sqlite3.OperationalError:
                        pass

                all_tables = [
                    r[0] for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                ]
                skip = {"metadata", "versions", "observations", "atoms", "bags",
                        "bag_atoms", "resolution_event_log", "sqlite_sequence"}
                for table in all_tables:
                    if table in skip or table.endswith("_fts") or "_fts_" in table:
                        continue
                    if table not in declared:
                        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                        if count > 0:
                            violations.append(f"{table} has {count} rows but not in produces")
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
            conn = sqlite3.connect(str(db_path))
            try:
                counts_first = {}
                for table in self.manifest.entity_types:
                    try:
                        counts_first[table] = conn.execute(
                            f"SELECT COUNT(*) FROM {table}"
                        ).fetchone()[0]
                    except sqlite3.OperationalError:
                        counts_first[table] = 0
            finally:
                conn.close()

            self.parser.extract_entities(self.fixtures_dir, db_path)

            conn = sqlite3.connect(str(db_path))
            try:
                counts_second = {}
                for table in self.manifest.entity_types:
                    try:
                        counts_second[table] = conn.execute(
                            f"SELECT COUNT(*) FROM {table}"
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
