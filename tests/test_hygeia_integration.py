"""Behavioral tests for icarus.integrations.hygeia.

Covers PRODUCTION_AUDIT.md findings:

- #133: the built-in regex PII fallback in sanitize_output()/verify_clean()
  only runs when the `hygeia` package fails to import with the expected
  symbols. Whether these tests actually exercise that fallback body silently
  depends on whatever happens to be installed in the environment running
  them. Both branches (`_HAS_HYGEIA_PACKAGE` True and False) are forced here
  via monkeypatch so the fallback is deterministically covered regardless of
  environment, and the delegation branch is verified independently.
- #205: sanitize_output/verify_clean must not fetchall() whole tables into
  memory — exercised implicitly by every test below (would still pass with
  fetchall(), but confirms no behavioral regression from the cursor-based
  rewrite on realistic multi-row data).
- #220: table/column identifiers pulled from sqlite_master must be validated
  (via validate_table) and safely quoted before interpolation into SQL —
  exercised by a database containing a non-ICARUS ("rogue") table name that
  must be skipped rather than blindly interpolated.
"""

import sqlite3
import tempfile
from pathlib import Path

import pytest

from icarus.core.schema import initialize_database
from icarus.integrations import hygeia as hygeia_mod

# (stored value, expected PII_PATTERNS name, substring that must disappear on redaction)
KNOWN_PII_ROWS = [
    ("contact: alice@example.com", "email", "alice@example.com"),
    ("seen at /Users/alice/Documents/secret.txt", "username_path", "/Users/alice"),
    (r"seen at C:\Users\bob\Desktop\notes.txt", "username_path_win", r"C:\Users\bob"),
    ("ssn on file: 123-45-6789", "ssn", "123-45-6789"),
]


@pytest.fixture
def pii_db():
    """A real ICARUS-schema database with known-PII rows in a valid TEXT column."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    initialize_database(db_path, {"source": "test"})

    conn = sqlite3.connect(str(db_path))
    for i, (observer, _pattern, _needle) in enumerate(KNOWN_PII_ROWS):
        conn.execute(
            """
            INSERT INTO observations
                (entity_table, entity_id, observed_at, observer, event_type, properties)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("files", i + 1, "2026-01-01T00:00:00Z", observer, "note", "synthetic test row"),
        )
    conn.commit()
    conn.close()

    yield db_path
    db_path.unlink(missing_ok=True)


def _force_fallback(monkeypatch):
    """Force the built-in regex fallback branch regardless of environment."""
    monkeypatch.setattr(hygeia_mod, "_HAS_HYGEIA_PACKAGE", False)


def _force_delegate(monkeypatch):
    """Force the 'standalone package present' branch with controlled stand-ins.

    We monkeypatch the imported symbols themselves (not just the flag) because
    they only exist in hygeia.py's namespace when the real import succeeded —
    in an environment where it didn't, `sanitize_database`/`verify_database`
    were never bound at all, so the True branch can't be exercised without
    also supplying them.
    """
    sentinel_sanitize = {"checked_rows": -1, "redacted": -1, "patterns_found": {}}
    sentinel_verify = {"passed": True, "findings": [], "total_findings": 0}

    monkeypatch.setattr(hygeia_mod, "_HAS_HYGEIA_PACKAGE", True)
    monkeypatch.setattr(
        hygeia_mod, "sanitize_database", lambda path: dict(sentinel_sanitize), raising=False
    )
    monkeypatch.setattr(
        hygeia_mod, "verify_database", lambda path: dict(sentinel_verify), raising=False
    )
    return sentinel_sanitize, sentinel_verify


# ---------------------------------------------------------------------------
# Mode: built-in fallback forced (finding #133) — also exercises #205/#220.
# ---------------------------------------------------------------------------


def test_sanitize_output_fallback_redacts_known_pii(pii_db, monkeypatch):
    _force_fallback(monkeypatch)

    stats = hygeia_mod.sanitize_output(pii_db)

    assert stats["checked_rows"] == len(KNOWN_PII_ROWS)
    assert stats["redacted"] == len(KNOWN_PII_ROWS)
    assert stats["patterns_found"] == {
        "email": 1,
        "username_path": 1,
        "username_path_win": 1,
        "ssn": 1,
    }

    conn = sqlite3.connect(str(pii_db))
    remaining = [r[0] for r in conn.execute("SELECT observer FROM observations ORDER BY rowid")]
    conn.close()

    blob = "\n".join(remaining)
    for _observer, _pattern_name, needle in KNOWN_PII_ROWS:
        assert needle not in blob
    assert "[REDACTED_EMAIL]" in blob
    assert "[REDACTED_USERNAME_PATH]" in blob
    assert "[REDACTED_USERNAME_PATH_WIN]" in blob
    assert "[REDACTED_SSN]" in blob


def test_verify_clean_fallback_detects_pii_before_sanitize(pii_db, monkeypatch):
    _force_fallback(monkeypatch)

    result = hygeia_mod.verify_clean(pii_db)

    assert result["passed"] is False
    assert result["total_findings"] == len(KNOWN_PII_ROWS)
    found_patterns = {f["pattern"] for f in result["findings"]}
    assert found_patterns == {"email", "username_path", "username_path_win", "ssn"}
    assert all(f["table"] == "observations" for f in result["findings"])
    assert all(f["column"] == "observer" for f in result["findings"])


def test_verify_clean_fallback_passes_after_sanitize(pii_db, monkeypatch):
    _force_fallback(monkeypatch)

    hygeia_mod.sanitize_output(pii_db)
    result = hygeia_mod.verify_clean(pii_db)

    assert result["passed"] is True
    assert result["total_findings"] == 0
    assert result["findings"] == []


def test_fallback_handles_large_table_without_fetchall(monkeypatch):
    """#205: sanitize_output/verify_clean must not materialize whole tables.

    Not a memory-ceiling test (unreliable/slow in CI), but a correctness
    regression test for the cursor-based rewrite: several thousand rows,
    mixed clean/dirty, must all be visited and only the dirty ones redacted.
    """
    _force_fallback(monkeypatch)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    try:
        initialize_database(db_path)
        conn = sqlite3.connect(str(db_path))
        n = 5000
        rows = [
            (
                "files",
                i,
                "2026-01-01T00:00:00Z",
                f"user{i}@example.com" if i % 500 == 0 else f"clean observer {i}",
                "note",
                "bulk synthetic row",
            )
            for i in range(1, n + 1)
        ]
        conn.executemany(
            """
            INSERT INTO observations
                (entity_table, entity_id, observed_at, observer, event_type, properties)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
        conn.close()

        expected_dirty = len([1 for i in range(1, n + 1) if i % 500 == 0])

        stats = hygeia_mod.sanitize_output(db_path)
        assert stats["checked_rows"] == n
        assert stats["redacted"] == expected_dirty
        assert stats["patterns_found"] == {"email": expected_dirty}

        result = hygeia_mod.verify_clean(db_path)
        assert result["passed"] is True
        assert result["total_findings"] == 0
    finally:
        db_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Mode: standalone package present -> must delegate, not run the fallback body.
# ---------------------------------------------------------------------------


def test_sanitize_output_delegates_when_package_present(pii_db, monkeypatch):
    sentinel_sanitize, _ = _force_delegate(monkeypatch)

    stats = hygeia_mod.sanitize_output(pii_db)

    # Matches our fake exactly (checked_rows=-1 is impossible from a real scan),
    # proving delegation rather than a coincidental fallback result.
    assert stats == sentinel_sanitize

    # The fallback never ran, so the raw PII must still be sitting untouched.
    conn = sqlite3.connect(str(pii_db))
    remaining = [r[0] for r in conn.execute("SELECT observer FROM observations ORDER BY rowid")]
    conn.close()
    assert remaining == [observer for observer, _p, _n in KNOWN_PII_ROWS]


def test_verify_clean_delegates_when_package_present(pii_db, monkeypatch):
    _force_delegate(monkeypatch)

    # The DB still has raw, unredacted PII. The real fallback would find it
    # (passed=False, total_findings>=4). Getting a clean result instead proves
    # the call was delegated to our fake verify_database.
    result = hygeia_mod.verify_clean(pii_db)

    assert result["passed"] is True
    assert result["total_findings"] == 0
    assert result["findings"] == []


# ---------------------------------------------------------------------------
# #220: identifiers pulled from sqlite_master must be validated/quoted.
# ---------------------------------------------------------------------------


def test_rogue_table_name_is_skipped_not_interpolated(monkeypatch):
    """A table name outside icarus.core.VALID_TABLES must be skipped, not
    blindly f-string-interpolated into the sanitizer's SQL."""
    _force_fallback(monkeypatch)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    try:
        initialize_database(db_path)
        conn = sqlite3.connect(str(db_path))
        # Not in icarus.core.VALID_TABLES — must not be scanned/interpolated.
        conn.execute("CREATE TABLE rogue_table (id INTEGER PRIMARY KEY, notes TEXT)")
        conn.execute(
            "INSERT INTO rogue_table (notes) VALUES (?)", ("contact: mallory@example.com",)
        )
        conn.execute(
            """
            INSERT INTO observations
                (entity_table, entity_id, observed_at, observer, event_type, properties)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("files", 1, "2026-01-01T00:00:00Z", "contact: alice@example.com", "note", "x"),
        )
        conn.commit()
        conn.close()

        stats = hygeia_mod.sanitize_output(db_path)
        # Only the known "observations" table's row was checked/redacted.
        assert stats["checked_rows"] == 1
        assert stats["redacted"] == 1

        conn = sqlite3.connect(str(db_path))
        rogue_value = conn.execute("SELECT notes FROM rogue_table").fetchone()[0]
        conn.close()
        # Untouched: the rogue table was never a validated ICARUS table.
        assert rogue_value == "contact: mallory@example.com"
    finally:
        db_path.unlink(missing_ok=True)


def test_column_name_with_embedded_quote_is_safely_escaped(monkeypatch):
    """A validated ICARUS table can still carry an unusually-named TEXT column
    (one containing an embedded double-quote — legal in SQLite). #220 requires
    that identifier be quoted with its embedded quote escaped before
    interpolation. Unescaped, even a plain SELECT on this column raises
    sqlite3.OperationalError ("near ... syntax error"), which would crash the
    whole sanitize/verify pass instead of just skipping one odd column.
    """
    _force_fallback(monkeypatch)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    try:
        initialize_database(db_path)
        conn = sqlite3.connect(str(db_path))
        conn.execute('ALTER TABLE files ADD COLUMN "weird ""quoted"" col" TEXT')
        conn.execute(
            'INSERT INTO files (path, filename, file_type, "weird ""quoted"" col") '
            "VALUES (?, ?, ?, ?)",
            ("/tmp/report.txt", "report.txt", "text", "contact: carol@example.com"),
        )
        conn.commit()
        conn.close()

        # Must not raise — the old unquoted f-string interpolation breaks here.
        stats = hygeia_mod.sanitize_output(db_path)
        assert stats["patterns_found"].get("email") == 1

        conn = sqlite3.connect(str(db_path))
        value = conn.execute('SELECT "weird ""quoted"" col" FROM files').fetchone()[0]
        conn.close()
        assert "carol@example.com" not in value
        assert "[REDACTED_EMAIL]" in value
    finally:
        db_path.unlink(missing_ok=True)


def test_quote_ident_escapes_embedded_double_quotes():
    assert hygeia_mod._quote_ident("files") == '"files"'
    assert hygeia_mod._quote_ident('weird"name') == '"weird""name"'
