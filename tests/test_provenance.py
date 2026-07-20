"""Regression coverage for build-time entity provenance (#40)."""

import sqlite3
from pathlib import Path

import pytest

from icarus.core.pipeline import (
    PROVENANCE_ENTITY_TABLES,
    PipelineContext,
    _capture_provenance_watermarks,
    _run_parser_phase_with_provenance,
    _stamp_new_provenance,
    create_default_pipeline,
)
from icarus.core.schema import initialize_database

FIXTURES = Path(__file__).parent / "fixtures"


def test_real_linux_build_populates_entity_provenance(tmp_path):
    output = tmp_path / "linux.db"
    pipeline = create_default_pipeline(
        FIXTURES / "linux", output, "linux", skip_hygeia=True
    )
    context = pipeline.run(resume=False)

    conn = sqlite3.connect(str(output))
    version_id = conn.execute("SELECT id FROM versions").fetchone()[0]
    populated_tables = 0
    for table in PROVENANCE_ENTITY_TABLES:
        total = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        if total == 0:
            continue
        populated_tables += 1
        missing = conn.execute(
            f"SELECT COUNT(*) FROM {table} "
            "WHERE source_version_id IS NULL OR observed_time IS NULL"
        ).fetchone()[0]
        wrong_version = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE source_version_id != ?", (version_id,)
        ).fetchone()[0]
        assert missing == 0, table
        assert wrong_version == 0, table

    conn.close()

    assert populated_tables >= 3
    assert context.stats["ingest"]["provenance"]["total"] > 0


def test_real_cloudtrail_build_populates_observation_provenance(tmp_path):
    output = tmp_path / "cloudtrail.db"
    pipeline = create_default_pipeline(
        FIXTURES / "cloud_aws_cloudtrail",
        output,
        "cloud/aws/cloudtrail",
        skip_hygeia=True,
    )
    pipeline.run(resume=False)

    conn = sqlite3.connect(str(output))
    version_id = conn.execute("SELECT id FROM versions").fetchone()[0]
    observation_total, observation_missing = conn.execute(
        "SELECT COUNT(*), SUM(version_id IS NULL OR version_id != ?) FROM observations",
        (version_id,),
    ).fetchone()
    conn.close()

    assert observation_total > 0
    assert observation_missing == 0


def test_real_macos_build_stamps_mach_services(tmp_path):
    output = tmp_path / "macos.db"
    pipeline = create_default_pipeline(
        FIXTURES / "macos", output, "macos", skip_hygeia=True
    )
    context = pipeline.run(resume=False)

    conn = sqlite3.connect(str(output))
    version_id = conn.execute("SELECT id FROM versions").fetchone()[0]
    rows = conn.execute(
        "SELECT source_version_id, observed_time FROM mach_services"
    ).fetchall()
    conn.close()

    assert rows
    assert all(source_version_id == version_id for source_version_id, _ in rows)
    assert all(observed_time for _, observed_time in rows)
    assert context.stats["ingest"]["provenance"]["rows_stamped"]["mach_services"]


def test_stamping_does_not_claim_rows_that_predate_the_phase(tmp_path):
    output = tmp_path / "existing.db"
    initialize_database(output)
    conn = sqlite3.connect(str(output))
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, started_at) VALUES (?, ?, ?)",
        ("current-run", "test", "2026-01-01T00:00:00+00:00"),
    )
    version_id = conn.execute("SELECT id FROM versions").fetchone()[0]
    conn.execute(
        "INSERT INTO files (path, filename, file_type) VALUES (?, ?, ?)",
        ("legacy.txt", "legacy.txt", "text"),
    )
    conn.commit()
    conn.close()

    context = PipelineContext(tmp_path, output, "test")
    context.version_id = version_id
    watermarks = _capture_provenance_watermarks(output)
    conn = sqlite3.connect(str(output))
    conn.execute(
        "INSERT INTO files (path, filename, file_type) VALUES (?, ?, ?)",
        ("new.txt", "new.txt", "text"),
    )
    conn.commit()
    conn.close()

    _stamp_new_provenance(context, watermarks)

    conn = sqlite3.connect(str(output))
    legacy = conn.execute(
        "SELECT source_version_id, observed_time FROM files WHERE path = 'legacy.txt'"
    ).fetchone()
    new = conn.execute(
        "SELECT source_version_id, observed_time FROM files WHERE path = 'new.txt'"
    ).fetchone()
    conn.close()
    assert legacy == (None, None)
    assert new == (version_id, "2026-01-01T00:00:00+00:00")


def test_rows_committed_before_parser_failure_are_still_stamped(tmp_path):
    output = tmp_path / "partial.db"
    initialize_database(output)
    conn = sqlite3.connect(str(output))
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, started_at) VALUES (?, ?, ?)",
        ("partial-run", "test", "2026-02-01T00:00:00+00:00"),
    )
    version_id = conn.execute("SELECT id FROM versions").fetchone()[0]
    conn.commit()
    conn.close()

    context = PipelineContext(tmp_path, output, "test")
    context.version_id = version_id

    def partial_handler():
        handler_conn = sqlite3.connect(str(output))
        handler_conn.execute(
            "INSERT INTO files (path, filename, file_type) VALUES (?, ?, ?)",
            ("partial.txt", "partial.txt", "text"),
        )
        handler_conn.commit()
        handler_conn.close()
        raise ValueError("synthetic parser failure")

    with pytest.raises(ValueError, match="synthetic parser failure"):
        _run_parser_phase_with_provenance(context, partial_handler)

    conn = sqlite3.connect(str(output))
    provenance = conn.execute(
        "SELECT source_version_id, observed_time FROM files WHERE path = 'partial.txt'"
    ).fetchone()
    conn.close()
    assert provenance == (version_id, "2026-02-01T00:00:00+00:00")
