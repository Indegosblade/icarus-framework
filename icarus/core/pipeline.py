"""
ICARUS Pipeline — Phase orchestrator with checkpoint/resume.

Processes data sources through a configurable sequence of phases,
saving progress at each checkpoint. Crash at phase N? Resume from phase N.
"""

import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

from icarus.core.schema import open_db


class PipelinePhase:
    """A single processing phase."""

    def __init__(self, name: str, handler: Callable, description: str = ""):
        self.name = name
        self.handler = handler
        self.description = description


class PipelineContext:
    """Shared state across pipeline phases."""

    def __init__(self, source: Path, output_db: Path, parser_name: str):
        self.source = source
        self.output_db = output_db
        self.parser_name = parser_name
        self.start_time = time.time()
        self.phase_times = {}
        self.stats = {}
        self.errors = []
        self.version_id: Optional[int] = None
        self.run_id: str = str(uuid.uuid4())

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time


class Pipeline:
    """Main pipeline orchestrator.

    Sequences phases, manages checkpoints, handles resume-from-failure.
    SQLite cache and mmap scale to available system RAM automatically.
    """

    def __init__(
        self, source: Path, output: Path, parser_name: str = "windows",
        skip_hygeia: bool = False,
    ):
        self.source = Path(source)
        self.output = Path(output)
        self.parser_name = parser_name
        self.skip_hygeia = skip_hygeia
        self.phases: List[PipelinePhase] = []
        self.checkpoint_db = self.output.parent / f".{self.output.stem}_checkpoint.db"
        self.context = PipelineContext(self.source, self.output, parser_name)

    def add_phase(self, name: str, handler: Callable, description: str = "") -> None:
        """Append a processing phase to the pipeline."""
        self.phases.append(PipelinePhase(name, handler, description))

    def get_last_checkpoint(self) -> int:
        """Return the index of the last completed phase, or -1 if none.

        A stored checkpoint is only honored when every completed phase still
        matches the current pipeline definition at that index (same
        phase_name). If the pipeline was redefined between runs — phases
        renamed or reordered — the stored indices no longer line up, so
        resuming by index would skip or mis-run phases; in that case the
        checkpoint is discarded and the pipeline re-runs from scratch (-1).
        """
        if not self.checkpoint_db.exists():
            return -1
        conn = sqlite3.connect(str(self.checkpoint_db))
        try:
            rows = conn.execute(
                "SELECT phase_index, phase_name FROM checkpoints WHERE status = 'complete'"
            ).fetchall()
        except sqlite3.OperationalError:
            return -1
        finally:
            conn.close()

        last = -1
        for phase_index, phase_name in rows:
            if phase_index >= len(self.phases) or self.phases[phase_index].name != phase_name:
                return -1
            if phase_index > last:
                last = phase_index
        return last

    def save_checkpoint(self, phase_index: int, status: str, stats: Optional[dict] = None) -> None:
        """Persist phase completion status for resume-on-crash."""
        conn = sqlite3.connect(str(self.checkpoint_db))
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                    phase_index INTEGER PRIMARY KEY,
                    phase_name TEXT,
                    status TEXT,
                    timestamp REAL,
                    stats TEXT
                )
            """)
            conn.execute(
                "INSERT OR REPLACE INTO checkpoints VALUES (?, ?, ?, ?, ?)",
                (phase_index, self.phases[phase_index].name, status,
                 time.time(), json.dumps(stats or {}))
            )
            conn.commit()
        finally:
            conn.close()

    def _clear_checkpoint(self) -> None:
        """Delete the checkpoint DB after a fully successful run.

        Checkpoints exist only to resume a crashed run. Leaving them after
        success marks every phase 'complete', so a later build to the same
        output would compute start = last + 1 > len(phases) and silently skip
        every phase (a no-op). Removing the file forces a clean re-run.
        """
        base = str(self.checkpoint_db)
        for suffix in ("", "-wal", "-shm"):
            Path(base + suffix).unlink(missing_ok=True)

    def _create_version_record(self):
        """Record this pipeline run in the versions table.

        Ensures the database and schema exist first. On a fresh build the init
        phase has not run yet when this is called, so without this guard the
        version record — and therefore all run provenance — was silently
        skipped, leaving the versions table empty on every first build.
        """
        if not self.output.exists():
            from icarus.core.schema import initialize_database
            initialize_database(self.output)
        conn = open_db(self.output)
        try:
            conn.execute("""
                INSERT OR IGNORE INTO versions (run_id, parser_name, source_path, started_at)
                VALUES (?, ?, ?, ?)
            """, (
                self.context.run_id,
                self.parser_name,
                str(self.source),
                datetime.now(timezone.utc).isoformat(),
            ))
            row = conn.execute(
                "SELECT id FROM versions WHERE run_id = ?", (self.context.run_id,)
            ).fetchone()
            if row:
                self.context.version_id = row[0]
            conn.commit()
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()

    def _finalize_version_record(self):
        """Update the version record with entity count and completion timestamp."""
        if not self.output.exists() or not self.context.version_id:
            return
        conn = open_db(self.output)
        try:
            ingest_stats = self.context.stats.get("ingest", {})
            entity_count = sum(
                v for v in ingest_stats.values() if isinstance(v, int)
            )
            conn.execute(
                "UPDATE versions SET entity_count = ?, completed_at = ? WHERE id = ?",
                (entity_count, datetime.now(timezone.utc).isoformat(),
                 self.context.version_id),
            )
            conn.commit()
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()

    def run(self, resume: bool = True, start_phase: Optional[int] = None) -> "PipelineContext":
        """Execute the pipeline.

        Args:
            resume: If True, skip completed phases (default behavior).
            start_phase: Force start from this phase index (overrides resume).
        """
        last_complete = self.get_last_checkpoint() if resume else -1
        start = start_phase if start_phase is not None else (last_complete + 1)

        self._create_version_record()

        print(f"[ICARUS] Pipeline: {len(self.phases)} phases, "
              f"source={self.source}, output={self.output}")

        if start >= len(self.phases):
            print(f"[ICARUS] All {len(self.phases)} phases already complete.")
            return self.context

        if start > 0:
            print(f"[ICARUS] Resuming from phase {start} "
                  f"({self.phases[start].name})")

        for i in range(start, len(self.phases)):
            phase = self.phases[i]
            print(f"\n[ICARUS] Phase {i}: {phase.name} — {phase.description}")
            phase_start = time.time()

            try:
                self.save_checkpoint(i, "running")
                stats = phase.handler(self.context)
                elapsed = time.time() - phase_start
                self.context.phase_times[phase.name] = elapsed
                if stats:
                    self.context.stats[phase.name] = stats
                self.save_checkpoint(i, "complete", stats)
                print(f"[ICARUS] Phase {i} complete ({elapsed:.1f}s)")
            except Exception as e:
                self.save_checkpoint(i, "failed", {"error": str(e)})
                self.context.errors.append((phase.name, str(e)))
                print(f"[ICARUS] Phase {i} FAILED: {e}")
                raise

        self._finalize_version_record()

        # Finalization writes completion metadata after the sanitize phase. A
        # second, read-only gate ensures no post-sanitize write can invalidate
        # the share-safe claim. If it fails, mark sanitize failed so resume
        # re-runs sanitization instead of skipping every completed phase.
        sanitize_indices = [
            index for index, phase in enumerate(self.phases) if phase.name == "sanitize"
        ]
        if sanitize_indices:
            from icarus.integrations.hygeia import (
                SanitizationError,
                mark_sanitization_failed,
                verify_clean,
            )

            sanitize_index = sanitize_indices[-1]
            try:
                final_gate = verify_clean(self.output)
            except Exception:
                error = SanitizationError(
                    "Final post-write sanitization gate could not complete"
                )
                mark_sanitization_failed(self.output)
                self.save_checkpoint(sanitize_index, "failed", {"error": str(error)})
                self.context.errors.append(("sanitize_final_gate", str(error)))
                raise error from None

            if not final_gate["passed"]:
                residual_types = ", ".join(final_gate["patterns_found"].keys())
                error = SanitizationError(
                    "Final post-write sanitization gate found "
                    f"{final_gate['total_findings']} residual finding(s) of type(s): "
                    f"{residual_types}"
                )
                mark_sanitization_failed(self.output)
                self.save_checkpoint(sanitize_index, "failed", {"error": str(error)})
                self.context.errors.append(("sanitize_final_gate", str(error)))
                raise error

            self.context.stats["sanitize_final_gate"] = {
                "passed": True,
                "total_findings": 0,
            }
        self._clear_checkpoint()

        total = time.time() - self.context.start_time
        print(f"\n[ICARUS] Pipeline complete. {len(self.phases)} phases in {total:.1f}s")
        return self.context


def create_default_pipeline(
    source: Path, output: Path, parser_name: str = "windows",
    skip_hygeia: bool = False, resolve: bool = False,
) -> Pipeline:
    """Create a pipeline with the standard phase sequence.

    Args:
        skip_hygeia: If True, skips HYGEIA sanitization. The output database
            will contain raw, unsanitized data. A warning is printed and
            the skip is recorded in the database metadata.
        resolve: If True, inserts an EXPERIMENTAL "resolve" phase after
            "verify" and before the sanitize/skip_hygeia_marker phase, which
            atomizes this build's own entities and runs
            ``EntityResolver.resolve_scored`` over them (see
            ``icarus.core.resolver``). Default False leaves the phase list
            unchanged from before this option existed. For cross-source
            resolution (multiple builds merged together), use the separate
            ``icarus resolve`` CLI command instead.
    """
    from icarus.core.schema import initialize_database
    from icarus.integrations.hygeia import require_hygeia, sanitize_output
    from icarus.parsers import get_parser

    pipeline = Pipeline(source, output, parser_name, skip_hygeia=skip_hygeia)
    parser = get_parser(parser_name)

    pipeline.add_phase("init", lambda ctx: initialize_database(ctx.output_db),
                       "Initialize SQLite database and schema")
    pipeline.add_phase("ingest", lambda ctx: parser.extract_entities(ctx.source, ctx.output_db),
                       "Walk source and extract entities")
    pipeline.add_phase(
        "relationships",
        lambda ctx: parser.extract_relationships(ctx.source, ctx.output_db),
        "Map relationships between entities")
    pipeline.add_phase("verify", lambda ctx: _verify_phase(ctx, parser),
                       "Quality gates and verification")

    if resolve:
        pipeline.add_phase(
            "resolve", _resolve_phase,
            "EXPERIMENTAL: entity resolution (resolve_scored)")

    if skip_hygeia:
        print("\n" + "!" * 60)
        print("WARNING: HYGEIA SANITIZATION DISABLED (--skip-hygeia)")
        print("Output database will contain raw, unsanitized data.")
        print("DO NOT share this database without manual review.")
        print("!" * 60 + "\n")
        pipeline.add_phase("skip_hygeia_marker", _mark_hygeia_skipped,
                           "Record HYGEIA skip in metadata")
    else:
        engine = require_hygeia()
        pipeline.context.stats["sanitizer"] = engine
        print(
            f"[ICARUS] Sanitizer: {engine['engine']} "
            f"v{engine['version']} ({engine['mode']})"
        )
        pipeline.add_phase("sanitize", lambda ctx: sanitize_output(ctx.output_db),
                           "HYGEIA canonical sanitizer + mandatory post-gate")

    return pipeline


def _verify_phase(ctx, parser) -> dict:
    """Run parser checks, then enforce relational integrity for every build."""
    stats = dict(parser.verify(ctx.output_db) or {})
    conn = open_db(ctx.output_db)
    try:
        violation = conn.execute("PRAGMA foreign_key_check").fetchone()
    finally:
        conn.close()

    if violation is not None:
        table, rowid, parent, constraint_index = violation
        raise ValueError(
            "Verification failed: foreign key violation "
            f"in table {table!r}, rowid {rowid!r}, parent {parent!r}, "
            f"constraint {constraint_index!r}"
        )

    stats["foreign_key_violations"] = 0
    return stats


def _resolve_phase(ctx) -> dict:
    """EXPERIMENTAL pipeline phase: atomize this build's entities and resolve them.

    Runs entirely within the build's own output database: atomizes the
    entities just produced by the "ingest"/"relationships" phases (tagged
    under this run's own ``ctx.version_id``, already populated before any
    phase runs — see ``Pipeline._create_version_record``), then runs
    ``EntityResolver.resolve_scored`` for every projected entity type. This
    resolves duplicates *within* one build; it does not merge across separate
    builds — use the ``icarus resolve`` CLI command for that.
    """
    print("[ICARUS] EXPERIMENTAL: running entity resolution (resolve_scored) "
          "— API/behavior may still change.")
    from icarus.core.atomize import ATOM_PROJECTIONS, atomize_db
    from icarus.core.resolver import EntityResolver

    with EntityResolver(str(ctx.output_db), experimental=True) as r:
        atomized = atomize_db(r.conn, r.conn, ctx.version_id)
        resolved = {et: r.resolve_scored(et) for et in ATOM_PROJECTIONS}

    return {"atomized": atomized, "resolved": resolved}


def _mark_hygeia_skipped(ctx) -> dict:
    """Record in metadata that HYGEIA was explicitly skipped."""
    conn = open_db(ctx.output_db)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO metadata VALUES (?, ?)",
            ("hygeia_skipped", "true"),
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata VALUES (?, ?)",
            ("hygeia_warning", "Output contains unsanitized data — review before sharing"),
        )
        conn.commit()
    finally:
        conn.close()
    return {"hygeia": "SKIPPED"}
