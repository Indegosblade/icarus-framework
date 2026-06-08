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
    assert __version__ == "1.0.0"
    assert SCHEMA_VERSION == 3
    assert len(VALID_TABLES) == 10
    assert len(VALID_FTS_TABLES) == 2
    assert "ios" in list_parsers()


def test_schema_init_and_fts(tmp_db):
    from icarus.core.schema import initialize_database

    stats = initialize_database(tmp_db, {"source": "test"})
    assert stats["schema_version"] == 3
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


def test_ios_parser():
    from icarus.parsers.ios import iOSParser

    p = iOSParser()
    assert p.name == "ios"
    assert p.get_required_tools() == ["ipsw", "ldid"]
    assert not p.identify(Path(tempfile.gettempdir()))


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
        r"Kevin Estrada",
        r"estradakh@gmail\.com",
        r"\bLimen\b",
        r"\bClaude\b",
        r"\bVex\b",
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
