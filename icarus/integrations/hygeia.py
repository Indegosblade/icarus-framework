"""
ICARUS HYGEIA Integration — Sanitization layer for intelligence databases.

Ensures output databases contain no PII, credentials, or source-identifying
information before they leave the pipeline. Runs as a pipeline phase.

If the standalone hygeia package is installed, delegates to it.
Otherwise, uses the built-in fallback implementation.
"""

import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List

from icarus.core import validate_table
from icarus.core.schema import open_db

try:
    from hygeia import sanitize_database, verify_database
    _HAS_HYGEIA_PACKAGE = True
except ImportError:
    _HAS_HYGEIA_PACKAGE = False

PII_PATTERNS = [
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "email"),
    (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "phone"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),
    (r"\b[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\b", "uuid"),
    (r"/Users/[^/]+", "username_path"),
    (r"/home/[^/]+", "username_path"),
    (r"C:\\Users\\[^\\]+", "username_path_win"),
]


def _quote_ident(name: str) -> str:
    """Double-quote a SQL identifier for safe interpolation, escaping embedded quotes."""
    return '"' + name.replace('"', '""') + '"'


def sanitize_output(db_path: Path) -> Dict[str, Any]:
    """
    Run sanitization pass on an ICARUS database.

    If the hygeia package is installed, delegates to it. Otherwise uses
    the built-in fallback. Returns stats on what was found and cleaned.
    """
    if _HAS_HYGEIA_PACKAGE:
        try:
            return sanitize_database(str(db_path))
        except (sqlite3.IntegrityError, sqlite3.OperationalError):
            pass  # UNIQUE constraint on redacted paths — fall through to built-in

    conn = open_db(db_path)
    stats = {"checked_rows": 0, "redacted": 0, "patterns_found": {}}
    try:
        text_columns = _get_text_columns(conn)

        for table, columns in text_columns.items():
            quoted_table = _quote_ident(table)
            select_list = ", ".join(_quote_ident(c) for c in columns)
            cursor = conn.execute(
                f"SELECT rowid, {select_list} FROM {quoted_table}"  # nosec B608 - quoted_table/select_list are identifiers escaped via _quote_ident(); table pre-validated against VALID_TABLES in _get_text_columns()
            )

            for row in cursor:
                rowid = row[0]
                stats["checked_rows"] += 1

                for i, col in enumerate(columns):
                    value = row[i + 1]
                    if not value or not isinstance(value, str):
                        continue

                    cleaned, found = _redact_pii(value)
                    if found:
                        quoted_col = _quote_ident(col)
                        try:
                            conn.execute(
                                f"UPDATE {quoted_table} SET {quoted_col} = ? WHERE rowid = ?",  # nosec B608 - quoted_table/quoted_col escaped via _quote_ident(); values passed as bound ? params
                                (cleaned, rowid)
                            )
                        except sqlite3.IntegrityError:
                            conn.execute(
                                f"UPDATE {quoted_table} SET {quoted_col} = ? WHERE rowid = ?",  # nosec B608 - quoted_table/quoted_col escaped via _quote_ident(); values passed as bound ? params
                                (f"{cleaned}_{rowid}", rowid)
                            )
                        stats["redacted"] += 1
                        for pattern_name in found:
                            stats["patterns_found"][pattern_name] = (
                                stats["patterns_found"].get(pattern_name, 0) + 1
                            )

        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")
    finally:
        conn.close()

    return stats


def verify_clean(db_path: Path) -> Dict[str, Any]:
    """
    Verify that a database contains no PII.

    If the hygeia package is installed, delegates to it. Otherwise uses
    the built-in fallback. Returns verification result with any remaining findings.
    """
    if _HAS_HYGEIA_PACKAGE:
        result = verify_database(str(db_path))
        return {
            "passed": result.get("passed", len(result.get("findings", [])) == 0),
            "findings": result.get("findings", [])[:100],
            "total_findings": result.get("total_findings", len(result.get("findings", []))),
        }

    conn = open_db(db_path)
    findings = []
    try:
        text_columns = _get_text_columns(conn)

        for table, columns in text_columns.items():
            quoted_table = _quote_ident(table)
            select_list = ", ".join(_quote_ident(c) for c in columns)
            cursor = conn.execute(
                f"SELECT rowid, {select_list} FROM {quoted_table}"  # nosec B608 - quoted_table/select_list are identifiers escaped via _quote_ident(); table pre-validated against VALID_TABLES in _get_text_columns()
            )

            for row in cursor:
                for i, col in enumerate(columns):
                    value = row[i + 1]
                    if not value or not isinstance(value, str):
                        continue

                    for pattern, name in PII_PATTERNS:
                        if re.search(pattern, value):
                            findings.append({
                                "table": table,
                                "column": col,
                                "rowid": row[0],
                                "pattern": name,
                                "sample": value[:50],
                            })
    finally:
        conn.close()

    return {
        "passed": len(findings) == 0,
        "findings": findings[:100],
        "total_findings": len(findings),
    }


def using_standalone_hygeia() -> bool:
    """Check if the standalone hygeia package is being used."""
    return _HAS_HYGEIA_PACKAGE


def _get_text_columns(conn: sqlite3.Connection) -> Dict[str, List[str]]:
    """Get all TEXT columns from all user tables."""
    result = {}
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()

    all_names = {t[0] for t in tables}
    skip_tables = {"metadata"}
    for name in all_names:
        if name.endswith("_fts"):
            skip_tables.add(name)
            for suffix in ("data", "idx", "content", "docsize", "config"):
                skip_tables.add(f"{name}_{suffix}")

    for (table_name,) in tables:
        if table_name in skip_tables:
            continue
        try:
            validate_table(table_name)
        except ValueError:
            # Not a known ICARUS table (e.g. schema confusion via a crafted
            # sqlite_master entry) — skip rather than interpolate it into SQL.
            continue

        columns = conn.execute(
            f"PRAGMA table_info({_quote_ident(table_name)})"
        ).fetchall()
        text_cols = [col[1] for col in columns if col[2].upper() == "TEXT"]

        if text_cols:
            result[table_name] = text_cols

    return result


def _redact_pii(text: str) -> tuple:
    """Redact PII patterns from text. Returns (cleaned_text, list_of_found_patterns)."""
    found = []
    cleaned = text

    for pattern, name in PII_PATTERNS:
        if re.search(pattern, cleaned):
            found.append(name)
            cleaned = re.sub(pattern, f"[REDACTED_{name.upper()}]", cleaned)

    return cleaned, found
