"""Core tests for icarus-framework."""

import re
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    yield db_path
    db_path.unlink(missing_ok=True)


@pytest.fixture
def two_dbs():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db1 = Path(f.name)
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db2 = Path(f.name)
    yield db1, db2
    db1.unlink(missing_ok=True)
    db2.unlink(missing_ok=True)


def test_imports():
    from icarus import __version__
    from icarus.core import VALID_FTS_TABLES, VALID_TABLES
    from icarus.core.schema import SCHEMA_VERSION
    from icarus.parsers import list_parsers
    assert __version__ == "2.0.0"
    assert SCHEMA_VERSION == 4
    assert len(VALID_TABLES) == 15
    assert len(VALID_FTS_TABLES) == 3
    assert "windows" in list_parsers()
    assert "linux" in list_parsers()


def test_schema_init_and_fts(tmp_db):
    from icarus.core.schema import initialize_database

    stats = initialize_database(tmp_db, {"source": "test"})
    assert stats["schema_version"] == 4
    assert stats["tables"] > 8

    conn = sqlite3.connect(str(tmp_db))
    triggers = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger'"
    ).fetchall()
    trigger_names = {t[0] for t in triggers}
    assert "files_ai" in trigger_names
    assert "files_ad" in trigger_names
    assert "daemons_ai" in trigger_names

    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/testbinary', 'testbinary', '', 1000, 'binary')
    """)
    conn.commit()

    result = conn.execute(
        "SELECT * FROM files_fts WHERE files_fts MATCH 'testbinary'"
    ).fetchall()
    assert len(result) == 1
    conn.close()


def test_query_sql_injection(tmp_db):
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    with IcarusQuery(str(tmp_db)) as q:
        result = q.search("test", table="files")
        assert result.count == 0

        with pytest.raises(ValueError, match="Invalid"):
            q.search("test", table="files; DROP TABLE files; --")

        stats = q.stats()
        assert "files" in stats
        assert "binaries" in stats


def test_differ_sql_injection(two_dbs):
    from icarus.core.differ import IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)
    with IcarusDiffer(str(db1), str(db2)) as d:
        result = d.added_entities("files", "path")
        assert result.total_changes == 0

        with pytest.raises(ValueError):
            d.added_entities("evil_table", "path")

        with pytest.raises(ValueError):
            d.changed_entities("files", "path", "sha256; DROP TABLE files")


def test_differ_full_pipeline(two_dbs):
    from icarus.core.differ import IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    conn = sqlite3.connect(str(db2))
    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/newbinary', 'newbinary', '', 500, 'binary')
    """)
    conn.commit()
    conn.close()

    with IcarusDiffer(str(db1), str(db2)) as d:
        results = d.full_diff()
        assert results["files_added"].total_changes == 1
        assert results["files_removed"].total_changes == 0

        report = d.generate_report()
        assert "newbinary" in report
        assert "# ICARUS Version Diff" in report


def test_query_intelligence_views(tmp_db):
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    with IcarusQuery(str(tmp_db)) as q:
        assert q.root_daemons().query_name == "Root Daemons (No Sandbox)"
        assert q.service_map().query_name == "MachService Map"
        assert q.kernel_surface().query_name == "Kernel Attack Surface"
        assert q.test_binaries().query_name == "Test Binaries in Production"
        assert q.escape_surface().query_name == "Sandbox Escape Surface"
        assert q.privileged_entitlements().query_name == "Privileged Entitlements"


def test_windows_parser():
    from icarus.parsers.windows import WindowsParser

    p = WindowsParser()
    assert p.name == "windows"
    assert p.get_required_tools() == []
    assert not p.identify(Path(tempfile.gettempdir()))


def test_linux_parser():
    from icarus.parsers.linux import LinuxParser

    p = LinuxParser()
    assert p.name == "linux"
    assert "readelf" in p.get_required_tools()


def test_cli():
    from icarus.__main__ import main

    old_argv = sys.argv
    sys.argv = ["icarus", "--help"]
    try:
        main()
    except SystemExit as e:
        assert e.code == 0
    finally:
        sys.argv = old_argv


def test_hygeia_integration(tmp_db):
    from icarus.core.schema import initialize_database
    from icarus.integrations.hygeia import sanitize_output, verify_clean

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/Users/john/secret.txt', 'secret.txt', '.txt', 100, 'other')
    """)
    conn.commit()
    conn.close()

    stats = sanitize_output(tmp_db)
    assert stats["redacted"] > 0

    result = verify_clean(tmp_db)
    assert result["passed"]


def test_pipeline_checkpoint_resume():
    from icarus.core.pipeline import Pipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "source"
        src.mkdir()
        out = Path(tmpdir) / "output.db"

        p = Pipeline(src, out, parser_name="test")
        call_log = []
        p.add_phase("phase_a", lambda ctx: call_log.append("a") or {"done": True}, "First")
        p.add_phase("phase_b", lambda ctx: call_log.append("b") or {"done": True}, "Second")

        p.run(resume=False)
        assert call_log == ["a", "b"]

        call_log.clear()
        p.run(resume=True)
        assert call_log == []


def test_no_personal_data():
    personal_patterns = [
        r"[A-Z][a-z]+ [A-Z][a-z]+rada",
        r"[a-z]+akh@gmail\.com",
    ]
    root = Path(__file__).parent.parent
    violations = []
    for py_file in root.rglob("*.py"):
        if "test_" in py_file.name:
            continue
        content = py_file.read_text(errors="ignore")
        for pat in personal_patterns:
            if re.search(pat, content):
                violations.append(f"{py_file.name}: matches {pat}")
    for md_file in root.rglob("*.md"):
        content = md_file.read_text(errors="ignore")
        for pat in personal_patterns:
            if re.search(pat, content):
                violations.append(f"{md_file.name}: matches {pat}")

    assert not violations, "Personal data found:\n" + "\n".join(violations)


def test_provenance_columns_exist(tmp_db):
    from icarus.core.schema import ENTITY_TABLES, initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))

    for table in ENTITY_TABLES:
        columns = conn.execute(f"PRAGMA table_info({table})").fetchall()
        col_names = {c[1] for c in columns}
        assert "source_version_id" in col_names, f"{table} missing source_version_id"
        assert "confidence" in col_names, f"{table} missing confidence"
        assert "observed_time" in col_names, f"{table} missing observed_time"
        assert "marking" in col_names, f"{table} missing marking"

    conn.close()


def test_versions_table_exists(tmp_db):
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))

    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='versions'"
    ).fetchall()
    assert len(tables) == 1

    columns = conn.execute("PRAGMA table_info(versions)").fetchall()
    col_names = {c[1] for c in columns}
    assert "run_id" in col_names
    assert "parser_name" in col_names
    assert "started_at" in col_names
    conn.close()


def test_marking_default(tmp_db):
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))

    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/test', 'test', '', 100, 'binary')
    """)
    conn.commit()

    row = conn.execute("SELECT marking FROM files WHERE path = '/usr/bin/test'").fetchone()
    assert row[0] == "UNCLASSIFIED"
    conn.close()


def test_diff_categories_exist():
    from icarus.core.differ import DiffCategory
    assert DiffCategory.ADDITION.value == "addition"
    assert DiffCategory.DELETION.value == "deletion"
    assert DiffCategory.PROPERTY_CHANGE.value == "property_change"
    assert DiffCategory.STRUCTURAL.value == "structural"
    assert DiffCategory.RESOLUTION_CHANGE.value == "resolution_change"


def test_structural_diff(two_dbs):
    from icarus.core.differ import DiffCategory, IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    conn1 = sqlite3.connect(str(db1))
    conn1.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/test', 'test', '', 500, 'binary')
    """)
    conn1.execute("INSERT INTO binaries (file_id, executable_name) VALUES (1, 'test')")
    conn1.commit()
    conn1.close()

    conn2 = sqlite3.connect(str(db2))
    conn2.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/sbin/test', 'test', '', 500, 'binary')
    """)
    conn2.execute("INSERT INTO binaries (file_id, executable_name) VALUES (99, 'test')")
    conn2.commit()
    conn2.close()

    with IcarusDiffer(str(db1), str(db2)) as d:
        result = d.structural_diff()
        assert result.category == DiffCategory.STRUCTURAL
        assert len(result.structural) == 1
        assert result.structural[0]["type"] == "binary_file_moved"


def test_full_diff_includes_structural(two_dbs):
    from icarus.core.differ import IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    with IcarusDiffer(str(db1), str(db2)) as d:
        results = d.full_diff()
        assert "structural" in results


def test_resolution_change_never_produced(two_dbs):
    """RESOLUTION_CHANGE is reserved for Phase 2 — must never appear in v1 output."""
    from icarus.core.differ import DiffCategory, IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    conn2 = sqlite3.connect(str(db2))
    conn2.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/new', 'new', '', 100, 'binary')
    """)
    conn2.commit()
    conn2.close()

    with IcarusDiffer(str(db1), str(db2)) as d:
        results = d.full_diff()
        for diff_result in results.values():
            assert diff_result.category != DiffCategory.RESOLUTION_CHANGE


def test_skip_hygeia_metadata(tmp_db):
    from icarus.core.pipeline import _mark_hygeia_skipped
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)

    class FakeCtx:
        output_db = tmp_db

    _mark_hygeia_skipped(FakeCtx())
    conn = sqlite3.connect(str(tmp_db))
    val = conn.execute("SELECT value FROM metadata WHERE key = 'hygeia_skipped'").fetchone()
    assert val[0] == "true"
    warn = conn.execute("SELECT value FROM metadata WHERE key = 'hygeia_warning'").fetchone()
    assert "unsanitized" in warn[0]
    conn.close()


def test_observations_table_exists(tmp_db):
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='observations'"
    ).fetchall()
    assert len(tables) == 1

    columns = conn.execute("PRAGMA table_info(observations)").fetchall()
    col_names = {c[1] for c in columns}
    assert "entity_table" in col_names
    assert "entity_id" in col_names
    assert "observed_at" in col_names
    assert "event_type" in col_names
    assert "confidence" in col_names
    conn.close()


def test_observation_insert(tmp_db):
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))

    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/test', 'test', '', 100, 'binary')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type, confidence)
        VALUES ('files', 1, '2026-06-07T12:00:00Z', 'seen', 1.0)
    """)
    conn.commit()

    row = conn.execute("SELECT * FROM observations WHERE entity_id = 1").fetchone()
    assert row is not None
    conn.close()


def test_observations_for(tmp_db):
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/test', 'test', '', 100, 'binary')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type)
        VALUES ('files', 1, '2026-06-07T12:00:00Z', 'seen')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type)
        VALUES ('files', 1, '2026-06-08T12:00:00Z', 'changed')
    """)
    conn.commit()
    conn.close()

    with IcarusQuery(str(tmp_db)) as q:
        result = q.observations_for("files", 1)
        assert result.count == 2


def test_pattern_of_life(tmp_db):
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/test', 'test', '', 100, 'binary')
    """)
    for ts in ["2026-06-01T00:00:00Z", "2026-06-05T00:00:00Z", "2026-06-10T00:00:00Z"]:
        conn.execute(
            "INSERT INTO observations (entity_table, entity_id, observed_at, event_type) "
            "VALUES ('files', 1, ?, 'seen')", (ts,)
        )
    conn.commit()
    conn.close()

    with IcarusQuery(str(tmp_db)) as q:
        result = q.pattern_of_life("files", 1, "2026-06-02", "2026-06-09")
        assert result.count == 1


def _setup_resolver_db(tmp_db):
    """Helper: init DB and insert a version record for atom ingestion."""
    from icarus.core.schema import initialize_database
    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES ('test-run-1', 'test', '/test', '2026-06-07T00:00:00Z')"
    )
    conn.commit()
    conn.close()


def test_atom_immutable(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db)) as r:
        atom_id = r.ingest_atom(1, "files", "key1", {"name": "a"})
        assert atom_id == 1
        conn = sqlite3.connect(str(tmp_db))
        row = conn.execute("SELECT properties FROM atoms WHERE id = 1").fetchone()
        assert "a" in row[0]
        conn.close()


def test_atom_unique_constraint(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db)) as r:
        r.ingest_atom(1, "files", "key1", {"name": "a"})
        with pytest.raises(sqlite3.IntegrityError):
            r.ingest_atom(1, "files", "key1", {"name": "b"})


def test_bag_creation(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db)) as r:
        a1 = r.ingest_atom(1, "files", "k1", {"x": 1})
        a2 = r.ingest_atom(1, "files", "k2", {"x": 2})
        bag_id = r.create_bag("files", [a1, a2], canonical_key="merged")
        assert bag_id >= 1

        conn = sqlite3.connect(str(tmp_db))
        count = conn.execute(
            "SELECT atom_count FROM bags WHERE id = ?", (bag_id,)
        ).fetchone()[0]
        assert count == 2
        conn.close()


def test_merge_bags_logs_event(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db)) as r:
        a1 = r.ingest_atom(1, "files", "k1", {"x": 1})
        a2 = r.ingest_atom(1, "files", "k2", {"x": 2})
        a3 = r.ingest_atom(1, "files", "k3", {"x": 3})
        b1 = r.create_bag("files", [a1])
        b2 = r.create_bag("files", [a2, a3])

        surviving = r.merge_bags([b1, b2], reason="duplicate entity")
        assert surviving == b1

        conn = sqlite3.connect(str(tmp_db))
        events = conn.execute(
            "SELECT event_type, reason FROM resolution_event_log WHERE event_type = 'merge'"
        ).fetchall()
        assert len(events) == 1
        assert events[0][1] == "duplicate entity"

        atom_count = conn.execute(
            "SELECT atom_count FROM bags WHERE id = ?", (surviving,)
        ).fetchone()[0]
        assert atom_count == 3
        conn.close()


def test_split_bag_reversible(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db)) as r:
        a1 = r.ingest_atom(1, "files", "k1", {"x": 1})
        a2 = r.ingest_atom(1, "files", "k2", {"x": 2})
        a3 = r.ingest_atom(1, "files", "k3", {"x": 3})
        bag_id = r.create_bag("files", [a1, a2, a3])

        new_bag = r.split_bag(bag_id, [a3], reason="wrong merge")
        assert new_bag != bag_id

        conn = sqlite3.connect(str(tmp_db))
        orig_count = conn.execute(
            "SELECT atom_count FROM bags WHERE id = ?", (bag_id,)
        ).fetchone()[0]
        new_count = conn.execute(
            "SELECT atom_count FROM bags WHERE id = ?", (new_bag,)
        ).fetchone()[0]
        assert orig_count == 2
        assert new_count == 1

        orig_bag_exists = conn.execute(
            "SELECT id FROM bags WHERE id = ?", (bag_id,)
        ).fetchone()
        assert orig_bag_exists is not None
        conn.close()


def test_event_log_append_only(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db)) as r:
        a1 = r.ingest_atom(1, "files", "k1", {"x": 1})
        r.create_bag("files", [a1])

    conn = sqlite3.connect(str(tmp_db))
    events = conn.execute("SELECT * FROM resolution_event_log").fetchall()
    assert len(events) == 1

    event_id = events[0][0]
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO resolution_event_log (id, event_type, bag_id, atom_ids, timestamp) "
            "VALUES (?, 'test', 1, '[]', '2026-01-01')", (event_id,)
        )
    conn.close()


def test_unresolved_atoms(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db)) as r:
        a1 = r.ingest_atom(1, "files", "k1", {"x": 1})
        a2 = r.ingest_atom(1, "files", "k2", {"x": 2})
        a3 = r.ingest_atom(1, "files", "k3", {"x": 3})

        unresolved = r.unresolved_atoms("files")
        assert len(unresolved) == 3

        r.create_bag("files", [a1, a2])
        unresolved = r.unresolved_atoms("files")
        assert len(unresolved) == 1
        assert a3 in unresolved


def test_atoms_fts_trigger(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db)) as r:
        r.ingest_atom(1, "files", "server_config", {"name": "nginx.conf", "role": "webserver"})

    conn = sqlite3.connect(str(tmp_db))
    rows = conn.execute(
        "SELECT rowid FROM atoms_fts WHERE atoms_fts MATCH 'server_config'"
    ).fetchall()
    assert len(rows) == 1
    conn.close()


def test_blocking_candidates(tmp_db):
    from icarus.core.resolver import BlockingIndex, EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db)) as r:
        a1 = r.ingest_atom(
            1, "files", "nginx_config",
            {"name": "nginx.conf", "type": "config"},
        )
        r.ingest_atom(
            1, "files", "nginx_binary",
            {"name": "nginx", "type": "binary"},
        )
        r.ingest_atom(
            1, "files", "postgres_config",
            {"name": "postgres.conf", "type": "config"},
        )

    with BlockingIndex(str(tmp_db)) as bi:
        candidates = bi.candidates_for(a1)
        candidate_ids = [c[0] for c in candidates]
        assert len(candidate_ids) > 0
        assert a1 not in candidate_ids


def test_blocking_no_self_match(tmp_db):
    from icarus.core.resolver import BlockingIndex, EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db)) as r:
        a1 = r.ingest_atom(1, "files", "test_file", {"name": "test"})

    with BlockingIndex(str(tmp_db)) as bi:
        candidates = bi.candidates_for(a1)
        candidate_ids = [c[0] for c in candidates]
        assert a1 not in candidate_ids


def test_blocking_threshold(tmp_db):
    from icarus.core.resolver import BlockingIndex, EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db)) as r:
        a1 = r.ingest_atom(1, "files", "alpha_service", {"name": "alpha", "role": "primary"})
        for i in range(5):
            r.ingest_atom(1, "files", f"beta_{i}", {"name": f"beta{i}", "role": "secondary"})

    with BlockingIndex(str(tmp_db)) as bi:
        candidates = bi.candidates_for(a1, limit=3)
        assert len(candidates) <= 3


def test_blocking_rebuild(tmp_db):
    from icarus.core.resolver import BlockingIndex, EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db)) as r:
        r.ingest_atom(1, "files", "k1", {"name": "a"})
        r.ingest_atom(1, "files", "k2", {"name": "b"})
        r.ingest_atom(1, "files", "k3", {"name": "c"})

    with BlockingIndex(str(tmp_db)) as bi:
        count = bi.rebuild()
        assert count == 3


def test_cross_graph_query(tmp_db):
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/test', 'test', '', 100, 'binary')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type, observer)
        VALUES ('files', 1, '2026-06-07T00:00:00Z', 'seen', 'linux_parser')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type, observer)
        VALUES ('files', 1, '2026-06-08T00:00:00Z', 'changed', 'linux_parser')
    """)
    conn.commit()
    conn.close()

    with IcarusQuery(str(tmp_db)) as q:
        result = q.cross_graph_query("files")
        assert result.count == 2

        result_filtered = q.cross_graph_query("files", event_type="seen")
        assert result_filtered.count == 1


def test_observation_diff_query(tmp_db):
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES ('run1', 'test', '/test', '2026-06-07T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES ('run2', 'test', '/test', '2026-06-08T00:00:00Z')"
    )
    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/a', 'a', '', 100, 'binary')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type, version_id)
        VALUES ('files', 1, '2026-06-07T00:00:00Z', 'seen', 1)
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type, version_id)
        VALUES ('files', 1, '2026-06-08T00:00:00Z', 'changed', 2)
    """)
    conn.commit()
    conn.close()

    with IcarusQuery(str(tmp_db)) as q:
        result = q.observation_diff(1, 2)
        assert result.count == 1


def test_observation_diff_differ(two_dbs):
    from icarus.core.differ import IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    conn1 = sqlite3.connect(str(db1))
    conn1.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/a', 'a', '', 100, 'binary')
    """)
    conn1.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type)
        VALUES ('files', 1, '2026-06-07T00:00:00Z', 'seen')
    """)
    conn1.commit()
    conn1.close()

    conn2 = sqlite3.connect(str(db2))
    conn2.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/a', 'a', '', 100, 'binary')
    """)
    conn2.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type)
        VALUES ('files', 1, '2026-06-07T00:00:00Z', 'seen')
    """)
    conn2.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type)
        VALUES ('files', 1, '2026-06-08T00:00:00Z', 'changed')
    """)
    conn2.commit()
    conn2.close()

    with IcarusDiffer(str(db1), str(db2)) as d:
        result = d.observation_diff()
        assert len(result.added) == 1
        assert len(result.removed) == 0


def test_valid_tables_updated():
    from icarus.core import VALID_TABLES
    for table in ["observations", "atoms", "bags", "bag_atoms", "resolution_event_log"]:
        assert table in VALID_TABLES


def test_obs_fk_any_ontology_table(tmp_db):
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))

    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/a', 'a', '', 100, 'binary')
    """)
    conn.execute("""
        INSERT INTO sandbox_profiles (name) VALUES ('test_profile')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type)
        VALUES ('files', 1, '2026-06-07T00:00:00Z', 'seen')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type)
        VALUES ('sandbox_profiles', 1, '2026-06-07T00:00:00Z', 'seen')
    """)
    conn.commit()

    rows = conn.execute("SELECT COUNT(*) FROM observations").fetchone()
    assert rows[0] == 2
    conn.close()


def test_migration_v2_to_v3(tmp_db):
    from icarus.core.schema import migrate_v2_to_v3

    conn = sqlite3.connect(str(tmp_db))
    conn.executescript("""
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL UNIQUE, filename TEXT NOT NULL,
            extension TEXT, size INTEGER DEFAULT 0, file_type TEXT
        );
        CREATE TABLE IF NOT EXISTS binaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL, bundle_id TEXT
        );
        CREATE TABLE IF NOT EXISTS daemons (
            id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL UNIQUE,
            plist_path TEXT NOT NULL, program TEXT
        );
        CREATE TABLE IF NOT EXISTS entitlements (
            id INTEGER PRIMARY KEY AUTOINCREMENT, binary_id INTEGER NOT NULL,
            key TEXT NOT NULL, value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sandbox_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS sandbox_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL,
            operation TEXT NOT NULL, action TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS kexts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, bundle_id TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS frameworks (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, path TEXT NOT NULL UNIQUE
        );
        INSERT INTO metadata VALUES ('schema_version', '2');
        INSERT INTO files (path, filename, size, file_type) VALUES ('/bin/ls', 'ls', 500, 'binary');
    """)
    conn.commit()

    migrate_v2_to_v3(conn)

    version = conn.execute(
        "SELECT value FROM metadata WHERE key = 'schema_version'"
    ).fetchone()[0]
    assert version == "3"

    row = conn.execute("SELECT confidence, marking FROM files WHERE path = '/bin/ls'").fetchone()
    assert row[0] == 1.0
    assert row[1] == "UNCLASSIFIED"

    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='versions'"
    ).fetchall()
    assert len(tables) == 1

    conn.close()


def test_migration_v3_to_v4(tmp_db):
    from icarus.core.schema import migrate_v2_to_v3, migrate_v3_to_v4

    conn = sqlite3.connect(str(tmp_db))
    conn.executescript("""
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL UNIQUE, filename TEXT NOT NULL,
            extension TEXT, size INTEGER DEFAULT 0, file_type TEXT
        );
        CREATE TABLE IF NOT EXISTS binaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL, bundle_id TEXT
        );
        CREATE TABLE IF NOT EXISTS daemons (
            id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL UNIQUE,
            plist_path TEXT NOT NULL, program TEXT
        );
        CREATE TABLE IF NOT EXISTS entitlements (
            id INTEGER PRIMARY KEY AUTOINCREMENT, binary_id INTEGER NOT NULL,
            key TEXT NOT NULL, value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sandbox_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS sandbox_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL,
            operation TEXT NOT NULL, action TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS kexts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, bundle_id TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS frameworks (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, path TEXT NOT NULL UNIQUE
        );
        INSERT INTO metadata VALUES ('schema_version', '2');
        INSERT INTO files (path, filename, size, file_type) VALUES ('/bin/ls', 'ls', 500, 'binary');
    """)
    conn.commit()

    migrate_v2_to_v3(conn)
    migrate_v3_to_v4(conn)

    version = conn.execute(
        "SELECT value FROM metadata WHERE key = 'schema_version'"
    ).fetchone()[0]
    assert version == "4"

    phase2_tables = {"observations", "atoms", "bags", "bag_atoms", "resolution_event_log"}
    existing = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    for t in phase2_tables:
        assert t in existing, f"Missing table after v3->v4 migration: {t}"

    triggers = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger'"
    ).fetchall()}
    assert "atoms_ai" in triggers
    assert "atoms_ad" in triggers

    row = conn.execute("SELECT confidence, marking FROM files WHERE path = '/bin/ls'").fetchone()
    assert row[0] == 1.0
    assert row[1] == "UNCLASSIFIED"

    conn.close()
