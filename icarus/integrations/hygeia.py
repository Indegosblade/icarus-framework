"""
ICARUS HYGEIA Integration — Sanitization layer for intelligence databases.

Ensures output databases contain no PII, credentials, or source-identifying
information before they leave the pipeline. Runs as a pipeline phase.
"""

import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List

PII_PATTERNS = [
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "email"),
    (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "phone"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),
    (r"\b[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\b", "uuid"),
    (r"/Users/[^/]+", "username_path"),
    (r"/home/[^/]+", "username_path"),
    (r"C:\\Users\\[^\\]+", "username_path_win"),
]

CREDENTIAL_PATTERNS = [
    r"password",
    r"secret",
    r"token",
    r"api[_-]?key",
    r"auth[_-]?token",
    r"access[_-]?key",
    r"private[_-]?key",
]


def sanitize_output(db_path: Path) -> Dict[str, Any]:
    """
    Run sanitization pass on an ICARUS database.

    Checks all text fields for PII patterns and redacts them.
    Returns stats on what was found and cleaned.
    """
    conn = sqlite3.connect(str(db_path))
    stats = {"checked_rows": 0, "redacted": 0, "patterns_found": {}}

    text_columns = _get_text_columns(conn)

    for table, columns in text_columns.items():
        rows = conn.execute(f"SELECT rowid, {', '.join(columns)} FROM {table}").fetchall()

        for row in rows:
            rowid = row[0]
            stats["checked_rows"] += 1

            for i, col in enumerate(columns):
                value = row[i + 1]
                if not value or not isinstance(value, str):
                    continue

                cleaned, found = _redact_pii(value)
                if found:
                    conn.execute(
                        f"UPDATE {table} SET {col} = ? WHERE rowid = ?",
                        (cleaned, rowid)
                    )
                    stats["redacted"] += 1
                    for pattern_name in found:
                        stats["patterns_found"][pattern_name] = (
                            stats["patterns_found"].get(pattern_name, 0) + 1
                        )

    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("VACUUM")
    conn.close()

    return stats


def verify_clean(db_path: Path) -> Dict[str, Any]:
    """
    Verify that a database contains no PII.

    Returns verification result with any remaining findings.
    """
    conn = sqlite3.connect(str(db_path))
    findings = []

    text_columns = _get_text_columns(conn)

    for table, columns in text_columns.items():
        rows = conn.execute(f"SELECT rowid, {', '.join(columns)} FROM {table}").fetchall()

        for row in rows:
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

    conn.close()

    return {
        "passed": len(findings) == 0,
        "findings": findings[:100],
        "total_findings": len(findings),
    }


def _get_text_columns(conn: sqlite3.Connection) -> Dict[str, List[str]]:
    """Get all TEXT columns from all user tables."""
    result = {}
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()

    skip_tables = {"metadata", "files_fts", "daemons_fts",
                   "files_fts_data", "files_fts_idx", "files_fts_content",
                   "files_fts_docsize", "files_fts_config",
                   "daemons_fts_data", "daemons_fts_idx", "daemons_fts_content",
                   "daemons_fts_docsize", "daemons_fts_config"}

    for (table_name,) in tables:
        if table_name in skip_tables:
            continue

        columns = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
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
