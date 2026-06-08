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
    def elapsed(self):
        return time.time() - self.start_time


class Pipeline:
    """
    Main pipeline orchestrator.

    Sequences phases, manages checkpoints, handles resume-from-failure.
    Streaming architecture: processes records one-at-a-time, 4GB RAM ceiling.
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

    def add_phase(self, name: str, handler: Callable, description: str = ""):
        self.phases.append(PipelinePhase(name, handler, description))

    def get_last_checkpoint(self) -> int:
        if not self.checkpoint_db.exists():
            return -1
        conn = sqlite3.connect(str(self.checkpoint_db))
        try:
            row = conn.execute(
                "SELECT MAX(phase_index) FROM checkpoints WHERE status = 'complete'"
            ).fetchone()
            return row[0] if row and row[0] is not None else -1
        except sqlite3.OperationalError:
            return -1
        finally:
            conn.close()

    def save_checkpoint(self, phase_index: int, status: str, stats: dict = None):
        conn = sqlite3.connect(str(self.checkpoint_db))
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
        conn.close()

    def _create_version_record(self):
        """Record this pipeline run in the versions table."""
        if not self.output.exists():
            return
        try:
            conn = sqlite3.connect(str(self.output))
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
            conn.close()
        except sqlite3.OperationalError:
            pass  # versions table may not exist yet (pre-init phase)

    def run(self, resume: bool = True, start_phase: Optional[int] = None):
        """
        Execute the pipeline.

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

        total = time.time() - self.context.start_time
        print(f"\n[ICARUS] Pipeline complete. {len(self.phases)} phases in {total:.1f}s")
        return self.context


def create_default_pipeline(
    source: Path, output: Path, parser_name: str = "windows",
    skip_hygeia: bool = False,
):
    """Create a pipeline with the standard phase sequence.

    Args:
        skip_hygeia: If True, skips HYGEIA sanitization. The output database
            will contain raw, unsanitized data. A warning is printed and
            the skip is recorded in the database metadata.
    """
    from icarus.core.schema import initialize_database
    from icarus.integrations.hygeia import sanitize_output
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
    pipeline.add_phase("verify", lambda ctx: parser.verify(ctx.output_db),
                       "Quality gates and verification")

    if skip_hygeia:
        print("\n" + "!" * 60)
        print("WARNING: HYGEIA SANITIZATION DISABLED (--skip-hygeia)")
        print("Output database will contain raw, unsanitized data.")
        print("DO NOT share this database without manual review.")
        print("!" * 60 + "\n")
        pipeline.add_phase("skip_hygeia_marker", _mark_hygeia_skipped,
                           "Record HYGEIA skip in metadata")
    else:
        pipeline.add_phase("sanitize", lambda ctx: sanitize_output(ctx.output_db),
                           "HYGEIA sanitization pass")

    return pipeline


def _mark_hygeia_skipped(ctx) -> dict:
    """Record in metadata that HYGEIA was explicitly skipped."""
    conn = sqlite3.connect(str(ctx.output_db))
    conn.execute(
        "INSERT OR REPLACE INTO metadata VALUES (?, ?)",
        ("hygeia_skipped", "true"),
    )
    conn.execute(
        "INSERT OR REPLACE INTO metadata VALUES (?, ?)",
        ("hygeia_warning", "Output contains unsanitized data — review before sharing"),
    )
    conn.commit()
    conn.close()
    return {"hygeia": "SKIPPED"}
