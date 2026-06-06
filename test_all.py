"""Full pipeline test for icarus-framework."""
import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

passed = 0
failed = 0

def test(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  PASS: {name}")
        passed += 1
    except Exception as e:
        print(f"  FAIL: {name} — {e}")
        failed += 1

# ============================================================
# Test 1: All imports work
# ============================================================
print("=== Test 1: Imports ===")

def t_imports():
    from icarus import __version__
    from icarus.core.schema import initialize_database, SCHEMA_VERSION, FTS_TRIGGERS
    from icarus.core.query import IcarusQuery, VALID_TABLES, VALID_FTS_TABLES, _validate_identifier
    from icarus.core.differ import IcarusDiffer, _validate_table, _validate_column, VALID_TABLES as DV
    from icarus.core.pipeline import Pipeline, create_default_pipeline
    from icarus.parsers.base import BaseParser
    from icarus.parsers.ios import iOSParser
    from icarus.parsers import get_parser, list_parsers
    from icarus.integrations.hygeia import sanitize_output, verify_clean
    from icarus.__main__ import main
    assert __version__ == "1.0.0"
    assert SCHEMA_VERSION == 2
    assert len(VALID_TABLES) == 10
    assert len(VALID_FTS_TABLES) == 2
    assert "ios" in list_parsers()

test("all imports", t_imports)

# ============================================================
# Test 2: Schema initialization + FTS triggers
# ============================================================
print("\n=== Test 2: Schema + FTS Triggers ===")

def t_schema():
    import sqlite3
    from icarus.core.schema import initialize_database
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    try:
        stats = initialize_database(db_path, {"source": "test"})
        assert stats["schema_version"] == 2
        assert stats["tables"] > 8

        conn = sqlite3.connect(str(db_path))
        triggers = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchall()
        trigger_names = {t[0] for t in triggers}
        assert "files_ai" in trigger_names, f"Missing files_ai trigger, got: {trigger_names}"
        assert "files_ad" in trigger_names
        assert "files_au" in trigger_names
        assert "daemons_ai" in trigger_names
        assert "daemons_ad" in trigger_names
        assert "daemons_au" in trigger_names

        # Test FTS trigger actually works: insert a file and search for it
        conn.execute("""
            INSERT INTO files (path, filename, extension, size, file_type)
            VALUES ('/usr/bin/testbinary', 'testbinary', '', 1000, 'binary')
        """)
        conn.commit()

        # FTS should have been populated by the trigger
        result = conn.execute(
            "SELECT * FROM files_fts WHERE files_fts MATCH 'testbinary'"
        ).fetchall()
        assert len(result) == 1, f"FTS search returned {len(result)} rows, expected 1"

        conn.close()
    finally:
        db_path.unlink(missing_ok=True)

test("schema init + FTS triggers", t_schema)

# ============================================================
# Test 3: SQL injection prevention in query.py
# ============================================================
print("\n=== Test 3: SQL Injection Prevention (query.py) ===")

def t_query_injection():
    import sqlite3
    from icarus.core.schema import initialize_database
    from icarus.core.query import IcarusQuery
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    try:
        initialize_database(db_path)
        with IcarusQuery(str(db_path)) as q:
            # Valid table should work
            result = q.search("test", table="files")
            assert result.count == 0

            # Invalid table should raise ValueError
            try:
                q.search("test", table="files; DROP TABLE files; --")
                assert False, "Should have raised ValueError"
            except ValueError as e:
                assert "Invalid" in str(e)

            # Stats should work (uses hardcoded valid tables)
            stats = q.stats()
            assert "files" in stats
            assert "binaries" in stats
    finally:
        db_path.unlink(missing_ok=True)

test("query.py SQL injection blocked", t_query_injection)

# ============================================================
# Test 4: SQL injection prevention in differ.py
# ============================================================
print("\n=== Test 4: SQL Injection Prevention (differ.py) ===")

def t_differ_injection():
    import sqlite3
    from icarus.core.schema import initialize_database
    from icarus.core.differ import IcarusDiffer
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db1 = Path(f.name)
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db2 = Path(f.name)
    try:
        initialize_database(db1)
        initialize_database(db2)
        with IcarusDiffer(str(db1), str(db2)) as d:
            # Valid table and column
            result = d.added_entities("files", "path")
            assert result.total_changes == 0

            # Invalid table
            try:
                d.added_entities("evil_table", "path")
                assert False, "Should have raised ValueError"
            except ValueError:
                pass

            # Invalid column
            try:
                d.changed_entities("files", "path", "sha256; DROP TABLE files")
                assert False, "Should have raised ValueError"
            except ValueError:
                pass
    finally:
        db1.unlink(missing_ok=True)
        db2.unlink(missing_ok=True)

test("differ.py SQL injection blocked", t_differ_injection)

# ============================================================
# Test 5: Differ full_diff and generate_report
# ============================================================
print("\n=== Test 5: Differ Full Pipeline ===")

def t_differ_full():
    import sqlite3
    from icarus.core.schema import initialize_database
    from icarus.core.differ import IcarusDiffer
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db1 = Path(f.name)
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db2 = Path(f.name)
    try:
        initialize_database(db1)
        initialize_database(db2)

        # Add a file to db2 that's not in db1
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
    finally:
        db1.unlink(missing_ok=True)
        db2.unlink(missing_ok=True)

test("differ full_diff + report", t_differ_full)

# ============================================================
# Test 6: Query engine intelligence queries
# ============================================================
print("\n=== Test 6: Query Intelligence Queries ===")

def t_query_intel():
    from icarus.core.schema import initialize_database
    from icarus.core.query import IcarusQuery
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    try:
        initialize_database(db_path)
        with IcarusQuery(str(db_path)) as q:
            r = q.root_daemons()
            assert r.query_name == "Root Daemons (No Sandbox)"
            r = q.service_map()
            assert r.query_name == "MachService Map"
            r = q.kernel_surface()
            assert r.query_name == "Kernel Attack Surface"
            r = q.test_binaries()
            assert r.query_name == "Test Binaries in Production"
            r = q.escape_surface()
            assert r.query_name == "Sandbox Escape Surface"
            r = q.privileged_entitlements()
            assert r.query_name == "Privileged Entitlements"
    finally:
        db_path.unlink(missing_ok=True)

test("query intelligence views", t_query_intel)

# ============================================================
# Test 7: iOS parser identification
# ============================================================
print("\n=== Test 7: iOS Parser ===")

def t_ios_parser():
    from icarus.parsers.ios import iOSParser
    p = iOSParser()
    assert p.name == "ios"
    assert p.get_required_tools() == ["ipsw", "ldid"]

    # Test identify on a non-iOS directory
    assert not p.identify(Path(tempfile.gettempdir()))

test("iOS parser basics", t_ios_parser)

# ============================================================
# Test 8: CLI entry point
# ============================================================
print("\n=== Test 8: CLI ===")

def t_cli():
    from icarus.__main__ import main
    # Just verify it parses args without crashing
    old_argv = sys.argv
    sys.argv = ["icarus", "--help"]
    try:
        main()
    except SystemExit as e:
        assert e.code == 0
    finally:
        sys.argv = old_argv

test("CLI --help", t_cli)

# ============================================================
# Test 9: HYGEIA integration
# ============================================================
print("\n=== Test 9: HYGEIA Integration ===")

def t_hygeia():
    import sqlite3
    from icarus.core.schema import initialize_database
    from icarus.integrations.hygeia import sanitize_output, verify_clean
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    try:
        initialize_database(db_path)
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            INSERT INTO files (path, filename, extension, size, file_type)
            VALUES ('/Users/john/secret.txt', 'secret.txt', '.txt', 100, 'other')
        """)
        conn.commit()
        conn.close()

        stats = sanitize_output(db_path)
        assert stats["redacted"] > 0, f"Expected redactions, got {stats}"

        result = verify_clean(db_path)
        # After sanitization, PII should be gone
        assert result["passed"], f"Verification failed: {result['findings'][:3]}"
    finally:
        try:
            db_path.unlink(missing_ok=True)
        except PermissionError:
            pass

test("HYGEIA sanitize + verify", t_hygeia)

# ============================================================
# Test 10: Pipeline checkpoint/resume
# ============================================================
print("\n=== Test 10: Pipeline ===")

def t_pipeline():
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

        # Resume should skip completed phases
        call_log.clear()
        p.run(resume=True)
        assert call_log == [], f"Expected no phases re-run, got {call_log}"

test("pipeline checkpoint/resume", t_pipeline)

# ============================================================
# Test 11: No personal data in source files
# ============================================================
print("\n=== Test 11: Personal Data Scrub ===")

def t_no_personal():
    import re
    personal_patterns = [
        r"Kevin Estrada",
        r"estradakh@gmail\.com",
        r"\bLimen\b",
        r"\bagents\b",
        r"\bVex\b",
    ]
    root = Path(__file__).parent
    violations = []
    for py_file in root.rglob("*.py"):
        if py_file.name == "test_all.py":
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
    for toml_file in root.rglob("*.toml"):
        content = toml_file.read_text(errors="ignore")
        for pat in personal_patterns:
            if re.search(pat, content):
                violations.append(f"{toml_file.name}: matches {pat}")

    # Check LICENSE separately (Kevin Estrada should be gone)
    lic = (root / "LICENSE").read_text(errors="ignore")
    if "Kevin Estrada" in lic:
        violations.append("LICENSE: still contains Kevin Estrada")
    if "estradakh" in lic:
        violations.append("LICENSE: still contains email")

    assert not violations, f"Personal data found:\n" + "\n".join(violations)

test("no personal data in source", t_no_personal)

# ============================================================
# Summary
# ============================================================
print(f"\n{'='*40}")
print(f"Results: {passed} passed, {failed} failed")
if failed:
    print("SOME TESTS FAILED")
    sys.exit(1)
else:
    print("ALL TESTS PASSED")
    sys.exit(0)
