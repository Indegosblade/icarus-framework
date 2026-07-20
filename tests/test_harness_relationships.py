"""Behavioral test for issue #27.

ParserTestHarness._run_parser() used to call only extract_entities(), so
every mandatory gate except test_golden_output's optional has_relationships
check ran against an entities-only database. Any event_type (or entity)
produced solely during extract_relationships() was invisible to
test_schema_conformance / test_idempotency / test_zero_pii — a parser could
ship declaring one set of event_types and silently emit an undeclared one
from its relationships phase with nothing catching it.

This test builds a minimal fixture parser whose relationships phase emits an
observation with an event_type the manifest does not declare, and proves
test_schema_conformance() now fails on it (it would have passed silently
before the fix, since schema_conformance only ever saw entities-phase
output).
"""

from pathlib import Path
from typing import Any, Dict

from icarus.parsers.base import BaseParser
from icarus.parsers.manifest import ParserManifest
from icarus.parsers.testing import ParserTestHarness


class _RelationshipsPhaseParser(BaseParser):
    """Toy parser: entities phase writes one file + a declared observation;
    relationships phase writes a second observation with an event_type the
    manifest never declares."""

    @property
    def name(self) -> str:
        return "test/relationships-drift"

    @property
    def description(self) -> str:
        return "Fixture parser for the #27 relationships-phase drift test"

    def identify(self, source: Path) -> bool:
        return True

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        from icarus.core.schema import open_db

        conn = open_db(db_path)
        try:
            conn.execute(
                "INSERT OR IGNORE INTO files (path,filename,size) "
                "VALUES (?,?,?)",
                ("/fixture.bin", "fixture.bin", 1),
            )
            file_id = conn.execute(
                "SELECT id FROM files WHERE path=?", ("/fixture.bin",)
            ).fetchone()[0]
            conn.execute(
                "INSERT INTO observations "
                "(entity_table,entity_id,observed_at,event_type,properties) "
                "VALUES (?,?,datetime('now'),?,?)",
                ("files", file_id, "entities_seen", None),
            )
            conn.commit()
        finally:
            conn.close()
        return {"files": 1}

    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        from icarus.core.schema import open_db

        conn = open_db(db_path)
        try:
            file_id = conn.execute(
                "SELECT id FROM files WHERE path=?", ("/fixture.bin",)
            ).fetchone()[0]
            # Undeclared: the manifest below only declares "entities_seen".
            conn.execute(
                "INSERT INTO observations "
                "(entity_table,entity_id,observed_at,event_type,properties) "
                "VALUES (?,?,datetime('now'),?,?)",
                ("files", file_id, "linked_during_relationships", None),
            )
            conn.commit()
        finally:
            conn.close()
        return {"linked": 1}


def _manifest(event_types):
    return ParserManifest(
        parser_id="test/relationships-drift",
        version="1.0.0",
        spec_version="icarus-parser/1.0",
        author="test",
        license="PolyForm-Noncommercial-1.0.0",
        quality_tier="production",
        description="fixture",
        identify={"specificity_level": 10, "markers": [], "confidence": 0.5},
        consumes=["application/octet-stream"],
        produces={"entity_types": ["files"], "event_types": event_types},
        reliability="F",
        default_confidence=0.5,
    )


def test_schema_conformance_catches_relationships_phase_event_type_drift(tmp_path):
    """#27: a manifest that only declares the entities-phase event_type must
    now fail schema_conformance, because _run_parser() runs
    extract_relationships() too and exposes the undeclared
    'linked_during_relationships' type it emits."""
    manifest = _manifest(["entities_seen"])  # missing the relationships-phase type
    harness = ParserTestHarness(_RelationshipsPhaseParser(), manifest, tmp_path)

    result = harness.test_schema_conformance()

    assert not result.passed
    assert "event_type" in result.message
    assert "linked_during_relationships" in result.message


def test_schema_conformance_passes_when_relationships_event_type_declared(tmp_path):
    """Sanity counterpart: once the manifest declares both event_types
    (entities-phase and relationships-phase), the same parser passes."""
    manifest = _manifest(["entities_seen", "linked_during_relationships"])
    harness = ParserTestHarness(_RelationshipsPhaseParser(), manifest, tmp_path)

    result = harness.test_schema_conformance()

    assert result.passed, result.message


def test_run_parser_populates_relationships_phase_output(tmp_path):
    """_run_parser()'s returned DB must already contain relationships-phase
    output (not just entities-phase) — this is the mechanism the two tests
    above rely on."""
    from icarus.core.schema import open_db

    manifest = _manifest(["entities_seen", "linked_during_relationships"])
    harness = ParserTestHarness(_RelationshipsPhaseParser(), manifest, tmp_path)

    db_path = harness._run_parser()
    try:
        conn = open_db(db_path)
        try:
            event_types = {
                r[0] for r in conn.execute(
                    "SELECT DISTINCT event_type FROM observations"
                ).fetchall()
            }
        finally:
            conn.close()
    finally:
        db_path.unlink(missing_ok=True)

    assert event_types == {"entities_seen", "linked_during_relationships"}
