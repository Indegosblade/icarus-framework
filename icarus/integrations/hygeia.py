"""Fail-closed HYGEIA integration for ICARUS intelligence databases.

HYGEIA is the canonical sanitization engine. ICARUS supplies an ICARUS-safe
pattern registry, records only non-reversible finding fingerprints, and runs an
independent post-sanitize gate before an output may be called clean.
"""

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Dict, List

try:
    from hygeia.patterns import PatternRegistry, get_default_registry
    from hygeia.sqlite_sanitizer import sanitize_database_generic
    from hygeia.verifier import _is_false_positive as _hygeia_is_false_positive

    _HAS_HYGEIA_PACKAGE = True
except ImportError:
    PatternRegistry = None  # type: ignore[assignment,misc]
    get_default_registry = None  # type: ignore[assignment]
    sanitize_database_generic = None  # type: ignore[assignment]
    _hygeia_is_false_positive = None  # type: ignore[assignment]
    _HAS_HYGEIA_PACKAGE = False

try:
    _HYGEIA_VERSION = version("hygeia")
except PackageNotFoundError:
    _HYGEIA_VERSION = "unavailable"


ENGINE_NAME = "hygeia.sqlite_sanitizer.sanitize_database_generic"
MAX_RECORDED_FINDINGS = 100

# HYGEIA's generic SQLite engine consumes regex_patterns, not context_patterns.
# Promote HYGEIA's self-labelled password pattern and add narrowly labelled
# ICARUS extensions for common credential formats observed in intelligence data.
_ICARUS_PATTERN_EXTENSIONS = {
    # HYGEIA's bare floating-point GPS regex also matches fractional seconds
    # in ISO timestamps. Require an explicit location label in ICARUS data.
    "gps_coord": re.compile(
        r"\b(?:latitude|longitude|lat|lng|lon|gps(?:_coord)?)\s*[:=]\s*"
        r"-?\d{1,3}\.\d{4,}",
        re.IGNORECASE,
    ),
    "uuid": re.compile(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        re.IGNORECASE,
    ),
    "username_path": re.compile(r"/(?:Users|home)/[^/\s]+"),
    "username_path_win": re.compile(r"C:\\Users\\[^\\\s]+", re.IGNORECASE),
    "aws_secret_key_kv": re.compile(
        r"\b(?:AWS_SECRET_ACCESS_KEY|aws_secret(?:_access)?_key)\s*[:=]\s*"
        r"[A-Za-z0-9/+=]{20,}",
        re.IGNORECASE,
    ),
    "private_key_kv": re.compile(
        r"\b(?:private[_ -]?key|wireguard[_ -]?key)\s*[:=]\s*"
        r"[A-Za-z0-9+/]{32,}={0,2}",
        re.IGNORECASE,
    ),
    "token_kv": re.compile(
        r"\b(?:api[_ -]?key|access[_ -]?token|auth[_ -]?token|bearer[_ -]?token|"
        r"client[_ -]?secret)\s*[:=]\s*(?:Bearer\s+)?[^\s,;]+",
        re.IGNORECASE,
    ),
    "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
}


class HygeiaUnavailableError(RuntimeError):
    """Raised when the mandatory HYGEIA dependency cannot be loaded."""


class SanitizationError(RuntimeError):
    """Raised when sanitization or its mandatory verification gate fails."""


def require_hygeia() -> Dict[str, str]:
    """Return active engine metadata or fail before a build modifies its output."""
    if (
        not _HAS_HYGEIA_PACKAGE
        or PatternRegistry is None
        or get_default_registry is None
        or sanitize_database_generic is None
        or _hygeia_is_false_positive is None
    ):
        raise HygeiaUnavailableError(
            "HYGEIA is required for sanitized builds but its canonical SQLite API "
            "could not be loaded; install the pinned dependency or explicitly use "
            "--skip-hygeia for an unsanitized output"
        ) from None
    return {"engine": ENGINE_NAME, "version": _HYGEIA_VERSION, "mode": "fail-closed"}


def _build_registry():
    """Build a HYGEIA registry that preserves ICARUS ontology column semantics."""
    require_hygeia()
    default = get_default_registry()
    regex_patterns = dict(default.regex_patterns)

    # This context regex contains its own label, so it remains self-gating when
    # promoted for the generic SQLite sanitizer.
    password_pattern = default.context_patterns.get("password_kv")
    if password_pattern is not None:
        regex_patterns["password_kv"] = password_pattern[0]
    regex_patterns.update(_ICARUS_PATTERN_EXTENSIONS)

    descriptions = dict(default.pattern_descriptions)
    descriptions.update(
        {
            name: "ICARUS labelled-secret extension"
            for name in _ICARUS_PATTERN_EXTENSIONS
        }
    )

    # HYGEIA's default sensitive-column list includes generic ontology fields
    # such as `name`. Direct-column redaction would destroy ICARUS's product
    # data, so this registry uses HYGEIA's value patterns but no whole-column or
    # whole-table deletion rules.
    return PatternRegistry(
        regex_patterns=regex_patterns,
        context_patterns={},
        sensitive_columns=set(),
        sensitive_json_keys=set(),
        pii_tables=set(),
        active_categories=set(default.active_categories),
        pattern_descriptions=descriptions,
    )


def _quote_ident(name: str) -> str:
    """Double-quote a SQL identifier and escape embedded quotes."""
    return '"' + name.replace('"', '""') + '"'


def _get_text_columns(conn: sqlite3.Connection) -> Dict[str, List[str]]:
    """Return scannable columns from every user-facing table, including metadata/FTS."""
    result: Dict[str, List[str]] = {}
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()

    fts_tables = {"files_fts", "daemons_fts", "atoms_fts"}
    fts_shadow_prefixes = tuple(f"{name}_" for name in fts_tables)
    for (table_name,) in tables:
        # The public FTS virtual table exposes the searchable content. Scanning
        # its internal shadow tables would duplicate findings and inspect BLOBs.
        if table_name.startswith(fts_shadow_prefixes):
            continue

        columns = conn.execute(
            f"PRAGMA table_info({_quote_ident(table_name)})"  # nosec B608 - identifier is double-quoted and embedded quotes are escaped
        ).fetchall()
        text_cols = []
        for col in columns:
            declared_type = (col[2] or "").upper()
            if not declared_type or any(
                text_type in declared_type for text_type in ("TEXT", "VARCHAR", "CHAR", "CLOB")
            ):
                text_cols.append(col[1])

        if text_cols:
            result[table_name] = text_cols
    return result


def _fingerprint(value: str, key: bytes) -> str:
    """Create a per-run, non-reversible fingerprint for safe correlation."""
    digest = hmac.new(key, value.encode("utf-8", "surrogatepass"), hashlib.sha256)
    return f"hmac-sha256:{digest.hexdigest()}"


def _scan_database(db_path: Path, registry, fingerprint_key: bytes) -> Dict[str, Any]:
    """Scan with HYGEIA patterns and return locations/fingerprints, never matches."""
    if not db_path.exists() or not db_path.is_file():
        raise SanitizationError("Sanitization target is not an existing database file")

    conn = sqlite3.connect(str(db_path))
    findings = []
    pattern_counts: Dict[str, int] = {}
    checked_rows = 0
    total_findings = 0
    try:
        for table, columns in _get_text_columns(conn).items():
            quoted_table = _quote_ident(table)
            select_list = ", ".join(_quote_ident(column) for column in columns)
            try:
                cursor = conn.execute(
                    f"SELECT rowid, {select_list} FROM {quoted_table}"  # nosec B608 - all identifiers are double-quoted and embedded quotes are escaped
                )
            except sqlite3.Error:
                raise SanitizationError(
                    f"Fail-closed verification could not scan table {table!r}"
                ) from None

            for row in cursor:
                checked_rows += 1
                for index, column in enumerate(columns):
                    value = row[index + 1]
                    if not isinstance(value, str) or not value:
                        continue
                    for pattern_name, pattern in registry.regex_patterns.items():
                        for match in pattern.finditer(value):
                            match_text = match.group(0)
                            location = f"{db_path.name}.{table}.{column}"
                            if _hygeia_is_false_positive(
                                location, pattern_name, match_text
                            ):
                                continue
                            total_findings += 1
                            pattern_counts[pattern_name] = pattern_counts.get(pattern_name, 0) + 1
                            if len(findings) < MAX_RECORDED_FINDINGS:
                                findings.append(
                                    {
                                        "table": table,
                                        "column": column,
                                        "rowid": row[0],
                                        "pattern": pattern_name,
                                        "fingerprint": _fingerprint(match_text, fingerprint_key),
                                    }
                                )
    finally:
        conn.close()

    return {
        "passed": total_findings == 0,
        "checked_rows": checked_rows,
        "findings": findings,
        "total_findings": total_findings,
        "findings_truncated": total_findings > len(findings),
        "patterns_found": dict(sorted(pattern_counts.items())),
    }


def _record_safe_audit(db_path: Path, engine: Dict[str, str], audit: Dict[str, Any]) -> None:
    """Persist only safe sanitizer evidence after the post-gate succeeds."""
    payload = {
        "engine": engine,
        "verified": True,
        "total_findings": audit["total_findings"],
        "patterns_found": audit["patterns_found"],
        "findings": audit["findings"],
        "findings_truncated": audit["findings_truncated"],
    }
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "DELETE FROM metadata WHERE key IN ('hygeia_skipped', 'hygeia_warning')"
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("hygeia_engine", json.dumps(engine, sort_keys=True)),
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("hygeia_audit", json.dumps(payload, sort_keys=True, separators=(",", ":"))),
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("hygeia_status", "verified"),
        )
        conn.commit()
    finally:
        conn.close()


_FTS_TABLES = ("files_fts", "daemons_fts", "atoms_fts")


def _rebuild_fts_indexes(db_path: Path) -> None:
    """Rebuild every FTS index so no secret can survive a stale FTS row.

    HYGEIA's generic sanitizer redacts content-table rows via UPDATE. Older
    ICARUS databases (schema versions built before an AFTER UPDATE trigger
    existed for a given content table) never re-sync their FTS shadow tables
    on UPDATE, so a redacted value can remain searchable in the FTS index
    regardless of how thoroughly the content table itself was cleaned. This
    runs unconditionally, after every sanitize, on every FTS table present in
    the database — it does not depend on which triggers the database has.
    Fails closed: any error rebuilding an index aborts sanitization.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        existing = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                "('files_fts', 'daemons_fts', 'atoms_fts')"
            ).fetchall()
        }
        for fts_table in _FTS_TABLES:
            if fts_table not in existing:
                continue
            quoted = _quote_ident(fts_table)
            try:
                conn.execute(f"INSERT INTO {quoted}({quoted}) VALUES('rebuild')")  # nosec B608 - identifier is from a fixed allowlist, double-quoted and escaped
            except sqlite3.Error:
                raise SanitizationError(
                    f"Fail-closed verification could not rebuild FTS index {fts_table!r}"
                ) from None
        conn.commit()
    finally:
        conn.close()


def mark_sanitization_failed(db_path: Path) -> None:
    """Invalidate prior clean markers when a later mandatory gate fails."""
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "DELETE FROM metadata WHERE key IN ('hygeia_engine', 'hygeia_audit')"
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("hygeia_status", "FAILED: output is not safe to share"),
        )
        conn.commit()
    finally:
        conn.close()


def sanitize_output(db_path: Path) -> Dict[str, Any]:
    """Sanitize an ICARUS database with HYGEIA and enforce a clean post-gate."""
    db_path = Path(db_path)
    engine = require_hygeia()
    registry = _build_registry()
    fingerprint_key = secrets.token_bytes(32)
    before = _scan_database(db_path, registry, fingerprint_key)

    try:
        result = sanitize_database_generic(db_path, registry=registry)
    except Exception:
        raise SanitizationError("HYGEIA raised an error while sanitizing the database") from None

    if not isinstance(result, dict) or result.get("error"):
        raise SanitizationError("HYGEIA reported a sanitization failure") from None
    if result.get("integrity_post") is not True:
        raise SanitizationError("HYGEIA did not verify database integrity after sanitization")

    _rebuild_fts_indexes(db_path)

    after = _scan_database(db_path, registry, fingerprint_key)
    if not after["passed"]:
        residual_types = ", ".join(after["patterns_found"].keys())
        raise SanitizationError(
            f"Post-sanitize verification found {after['total_findings']} residual "
            f"finding(s) of type(s): {residual_types}"
        )

    _record_safe_audit(db_path, engine, before)
    return {
        "engine": engine,
        "checked_rows": before["checked_rows"],
        "redacted": int(result.get("rows_redacted", 0)),
        "patterns_found": before["patterns_found"],
        "findings": before["findings"],
        "total_findings": before["total_findings"],
        "findings_truncated": before["findings_truncated"],
        "verified": True,
        "post_sanitize_findings": 0,
    }


def verify_clean(db_path: Path) -> Dict[str, Any]:
    """Verify with HYGEIA's registry without ever returning raw matched values."""
    require_hygeia()
    registry = _build_registry()
    return _scan_database(Path(db_path), registry, secrets.token_bytes(32))


def using_standalone_hygeia() -> bool:
    """Return whether HYGEIA's canonical SQLite API is available."""
    return _HAS_HYGEIA_PACKAGE
