"""Tests for Phase 3.4 — Generic fallback parsers."""

import sqlite3
import tempfile
from pathlib import Path

from icarus.core.schema import initialize_database

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _run_parser_on_fixture(parser, fixture_dir):
    db_path = Path(tempfile.mktemp(suffix=".db"))
    initialize_database(db_path, {"source": "test"})
    parser.extract_entities(fixture_dir, db_path)
    return db_path


def test_generic_json_identifies():
    from icarus.parsers.generic.json_parser import JsonParser
    p = JsonParser()
    assert p.identify(FIXTURES_DIR / "generic_json")
    with tempfile.TemporaryDirectory() as empty:
        assert not p.identify(Path(empty))


def test_generic_json_extracts():
    from icarus.parsers.generic.json_parser import JsonParser
    db = _run_parser_on_fixture(JsonParser(), FIXTURES_DIR / "generic_json")
    try:
        conn = sqlite3.connect(str(db))
        count = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        assert count == 2
        conn.close()
    finally:
        db.unlink(missing_ok=True)


def test_generic_sqlite_identifies():
    from icarus.parsers.generic.sqlite_parser import SqliteParser
    p = SqliteParser()
    assert p.identify(FIXTURES_DIR / "generic_sqlite")


def test_generic_sqlite_extracts():
    from icarus.parsers.generic.sqlite_parser import SqliteParser
    db = _run_parser_on_fixture(SqliteParser(), FIXTURES_DIR / "generic_sqlite")
    try:
        conn = sqlite3.connect(str(db))
        count = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        assert count == 1
        obs = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
        assert obs >= 1
        conn.close()
    finally:
        db.unlink(missing_ok=True)


def test_generic_specificity_loses_to_windows():
    """Windows dir: Windows parser wins over generic parsers."""
    from icarus.parsers import detect_parser
    src = Path(tempfile.mkdtemp())
    pe_data = bytearray(256)
    pe_data[0:2] = b"MZ"
    (src / "test.exe").write_bytes(bytes(pe_data))
    (src / "data.json").write_text('{"key": "value"}')
    result = detect_parser(src)
    assert result == "windows"


def test_generic_zero_pii_all():
    """HYGEIA passes on all five generic parser outputs."""
    from icarus.integrations.hygeia import verify_clean
    from icarus.parsers.generic.archive_parser import ArchiveParser
    from icarus.parsers.generic.binary_entropy_parser import BinaryEntropyParser
    from icarus.parsers.generic.json_parser import JsonParser
    from icarus.parsers.generic.sqlite_parser import SqliteParser
    from icarus.parsers.generic.xml_parser import XmlParser

    parsers = [
        (JsonParser(), "generic_json"),
        (XmlParser(), "generic_xml"),
        (SqliteParser(), "generic_sqlite"),
        (ArchiveParser(), "generic_archive"),
        (BinaryEntropyParser(), "generic_binary"),
    ]
    for parser, fixture_name in parsers:
        fixture_dir = FIXTURES_DIR / fixture_name
        db = _run_parser_on_fixture(parser, fixture_dir)
        try:
            result = verify_clean(db)
            assert result["passed"], f"{parser.name} failed zero-PII: {result['findings'][:3]}"
        finally:
            db.unlink(missing_ok=True)
