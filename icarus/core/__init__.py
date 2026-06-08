"""ICARUS core — pipeline, schema, query, differ."""

import re

VALID_TABLES = frozenset({
    "files", "binaries", "daemons", "entitlements",
    "sandbox_profiles", "sandbox_rules", "kexts", "frameworks",
    "metadata", "versions",
})

VALID_FTS_TABLES = frozenset({"files", "daemons"})

_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def validate_table(name: str) -> str:
    if name not in VALID_TABLES:
        raise ValueError(f"Invalid table name: {name!r}")
    return name


def validate_column(name: str) -> str:
    if not _IDENTIFIER_RE.match(name):
        raise ValueError(f"Invalid column name: {name!r}")
    return name
