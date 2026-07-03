"""Tests for the top-level ``icarus`` package public API surface (Audit #123).

Previously ``icarus/__init__.py`` exported only ``__version__``, with no
``__all__`` and no re-export of ``Pipeline``, ``create_default_pipeline``,
``IcarusQuery``, ``BaseParser``, or ``initialize_database``. A caller could
not build anything against the library without reaching into private
submodule paths (``icarus.core.pipeline``, ``icarus.core.query``, ...).
"""

import sqlite3

import icarus

EXPECTED_PUBLIC_API = {
    "__version__",
    "Pipeline",
    "create_default_pipeline",
    "IcarusQuery",
    "BaseParser",
    "initialize_database",
}


def test_all_defines_exactly_the_intended_public_api():
    assert set(icarus.__all__) == EXPECTED_PUBLIC_API


def test_public_names_are_reachable_and_identical_to_source():
    """Every name in __all__ must resolve on the package and be the *same*
    object as the one defined in its real module (not a stale re-import)."""
    from icarus.core.pipeline import Pipeline, create_default_pipeline
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database
    from icarus.parsers.base import BaseParser

    assert icarus.Pipeline is Pipeline
    assert icarus.create_default_pipeline is create_default_pipeline
    assert icarus.IcarusQuery is IcarusQuery
    assert icarus.BaseParser is BaseParser
    assert icarus.initialize_database is initialize_database


def test_wildcard_import_exposes_only_the_curated_api():
    """``from icarus import *`` must bring in exactly __all__ — nothing more,
    nothing less — proving __all__ actually governs the public surface
    rather than merely existing alongside unrelated globals."""
    namespace: dict = {}
    exec("from icarus import *", namespace)
    namespace.pop("__builtins__", None)
    assert set(namespace.keys()) == EXPECTED_PUBLIC_API


def test_public_api_builds_a_working_pipeline_end_to_end(tmp_path):
    """Behavioral check: the re-exported symbols are not just importable —
    a real pipeline can be built and run using only ``icarus.*`` names,
    which is exactly the recipe the audit found undocumented/impossible."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "AGENTS.md").write_text("Pi-hole and WireGuard project.\n")
    out = tmp_path / "out.db"

    pipeline = icarus.create_default_pipeline(
        src, out, parser_name="network/privacy_stack", skip_hygeia=True
    )
    assert isinstance(pipeline, icarus.Pipeline)
    pipeline.run(resume=False)

    with icarus.IcarusQuery(str(out)) as q:
        stats = q.stats()
    assert stats.get("files", 0) >= 1
    assert stats.get("daemons", 0) >= 1

    # initialize_database is idempotent/safe to call again on the same file.
    result = icarus.initialize_database(out)
    assert result["schema_version"] == 6

    conn = sqlite3.connect(str(out))
    try:
        row = conn.execute(
            "SELECT parser_name FROM versions ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None and row[0] == "network/privacy_stack"
