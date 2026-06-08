"""
ICARUS Schema Manager — SQLite database initialization and migrations.

Manages the normalized relational model: entities, relationships,
attributes, FTS5 full-text search, and materialized views.
"""

import sqlite3
from pathlib import Path
from typing import Optional

SCHEMA_VERSION = 3

ENTITY_TABLES = (
    "files", "binaries", "daemons", "entitlements",
    "sandbox_profiles", "sandbox_rules", "kexts", "frameworks",
)

CORE_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL UNIQUE,
    filename TEXT NOT NULL,
    extension TEXT,
    size INTEGER DEFAULT 0,
    permissions TEXT,
    owner TEXT,
    group_name TEXT,
    modified_time TEXT,
    sha256 TEXT,
    file_type TEXT,
    is_symlink INTEGER DEFAULT 0,
    symlink_target TEXT,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS binaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES files(id),
    bundle_id TEXT,
    executable_name TEXT,
    arch TEXT,
    min_os_version TEXT,
    sdk_version TEXT,
    code_sign_flags TEXT,
    team_id TEXT,
    linked_dylibs TEXT,
    rpaths TEXT,
    segments TEXT,
    has_restrict INTEGER DEFAULT 0,
    has_pie INTEGER DEFAULT 1,
    is_encrypted INTEGER DEFAULT 0,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS daemons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL UNIQUE,
    plist_path TEXT NOT NULL,
    program TEXT,
    program_arguments TEXT,
    user_name TEXT,
    group_name TEXT,
    run_at_load INTEGER DEFAULT 0,
    keep_alive INTEGER DEFAULT 0,
    sandbox_profile TEXT,
    mach_services TEXT,
    binary_id INTEGER REFERENCES binaries(id),
    is_disabled INTEGER DEFAULT 0,
    session_type TEXT,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS entitlements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id),
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    value_type TEXT,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS sandbox_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    profile_path TEXT,
    raw_sbpl TEXT,
    rule_count INTEGER DEFAULT 0,
    allows_network INTEGER DEFAULT 0,
    allows_mach_lookup INTEGER DEFAULT 0,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS sandbox_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL REFERENCES sandbox_profiles(id),
    operation TEXT NOT NULL,
    action TEXT NOT NULL,
    filter_type TEXT,
    filter_value TEXT,
    requires TEXT,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS kexts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle_id TEXT NOT NULL UNIQUE,
    name TEXT,
    version TEXT,
    file_id INTEGER REFERENCES files(id),
    dependencies TEXT,
    personalities TEXT,
    iokit_classes TEXT,
    has_user_client INTEGER DEFAULT 0,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS frameworks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    bundle_id TEXT,
    version TEXT,
    is_private INTEGER DEFAULT 0,
    binary_id INTEGER REFERENCES binaries(id),
    exported_symbols_count INTEGER DEFAULT 0,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL UNIQUE,
    parser_name TEXT NOT NULL,
    source_path TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    entity_count INTEGER DEFAULT 0,
    metadata TEXT
);
"""

INDEXES = """
CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
CREATE INDEX IF NOT EXISTS idx_files_extension ON files(extension);
CREATE INDEX IF NOT EXISTS idx_files_type ON files(file_type);
CREATE INDEX IF NOT EXISTS idx_files_size ON files(size DESC);
CREATE INDEX IF NOT EXISTS idx_binaries_bundle ON binaries(bundle_id);
CREATE INDEX IF NOT EXISTS idx_binaries_file ON binaries(file_id);
CREATE INDEX IF NOT EXISTS idx_daemons_label ON daemons(label);
CREATE INDEX IF NOT EXISTS idx_daemons_sandbox ON daemons(sandbox_profile);
CREATE INDEX IF NOT EXISTS idx_ent_binary ON entitlements(binary_id);
CREATE INDEX IF NOT EXISTS idx_ent_key ON entitlements(key);
CREATE INDEX IF NOT EXISTS idx_ent_key_value ON entitlements(key, value);
CREATE INDEX IF NOT EXISTS idx_sandbox_name ON sandbox_profiles(name);
CREATE INDEX IF NOT EXISTS idx_rules_profile ON sandbox_rules(profile_id);
CREATE INDEX IF NOT EXISTS idx_rules_operation ON sandbox_rules(operation);
CREATE INDEX IF NOT EXISTS idx_kexts_bundle ON kexts(bundle_id);
CREATE INDEX IF NOT EXISTS idx_frameworks_name ON frameworks(name);
"""

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(
    path, filename, file_type,
    content='files', content_rowid='id'
);

CREATE VIRTUAL TABLE IF NOT EXISTS daemons_fts USING fts5(
    label, program, mach_services, sandbox_profile,
    content='daemons', content_rowid='id'
);
"""

FTS_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS files_ai AFTER INSERT ON files BEGIN
    INSERT INTO files_fts(rowid, path, filename, file_type)
    VALUES (new.id, new.path, new.filename, new.file_type);
END;

CREATE TRIGGER IF NOT EXISTS files_ad AFTER DELETE ON files BEGIN
    INSERT INTO files_fts(files_fts, rowid, path, filename, file_type)
    VALUES ('delete', old.id, old.path, old.filename, old.file_type);
END;

CREATE TRIGGER IF NOT EXISTS files_au AFTER UPDATE ON files BEGIN
    INSERT INTO files_fts(files_fts, rowid, path, filename, file_type)
    VALUES ('delete', old.id, old.path, old.filename, old.file_type);
    INSERT INTO files_fts(rowid, path, filename, file_type)
    VALUES (new.id, new.path, new.filename, new.file_type);
END;

CREATE TRIGGER IF NOT EXISTS daemons_ai AFTER INSERT ON daemons BEGIN
    INSERT INTO daemons_fts(rowid, label, program, mach_services, sandbox_profile)
    VALUES (new.id, new.label, new.program, new.mach_services, new.sandbox_profile);
END;

CREATE TRIGGER IF NOT EXISTS daemons_ad AFTER DELETE ON daemons BEGIN
    INSERT INTO daemons_fts(daemons_fts, rowid, label, program, mach_services, sandbox_profile)
    VALUES ('delete', old.id, old.label, old.program, old.mach_services, old.sandbox_profile);
END;

CREATE TRIGGER IF NOT EXISTS daemons_au AFTER UPDATE ON daemons BEGIN
    INSERT INTO daemons_fts(daemons_fts, rowid, label, program, mach_services, sandbox_profile)
    VALUES ('delete', old.id, old.label, old.program, old.mach_services, old.sandbox_profile);
    INSERT INTO daemons_fts(rowid, label, program, mach_services, sandbox_profile)
    VALUES (new.id, new.label, new.program, new.mach_services, new.sandbox_profile);
END;
"""

VIEWS = """
CREATE VIEW IF NOT EXISTS v_sandbox_escape_surface AS
SELECT
    d.label, d.program, d.mach_services,
    d.sandbox_profile, d.user_name,
    GROUP_CONCAT(e.key, ', ') AS privileged_entitlements
FROM daemons d
JOIN binaries b ON d.binary_id = b.id
JOIN entitlements e ON e.binary_id = b.id
WHERE e.key IN (
    'com.apple.private.security.no-sandbox',
    'com.apple.private.skip-library-validation',
    'task_for_pid-allow',
    'platform-application'
)
AND d.mach_services IS NOT NULL
GROUP BY d.id;

CREATE VIEW IF NOT EXISTS v_kernel_attack_surface AS
SELECT
    k.bundle_id, k.name AS kext_name,
    k.version, k.personalities, k.iokit_classes
FROM kexts k WHERE k.has_user_client = 1;

CREATE VIEW IF NOT EXISTS v_test_binaries AS
SELECT f.path, b.bundle_id, b.executable_name
FROM binaries b
JOIN files f ON b.file_id = f.id
WHERE f.path LIKE '%/test%' OR f.path LIKE '%/debug%'
    OR b.bundle_id LIKE '%test%' OR b.bundle_id LIKE '%debug%';
"""


def migrate_v2_to_v3(conn: sqlite3.Connection) -> None:
    """Additive migration: adds versions table and provenance columns."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL UNIQUE,
            parser_name TEXT NOT NULL,
            source_path TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            entity_count INTEGER DEFAULT 0,
            metadata TEXT
        )
    """)
    for table in ENTITY_TABLES:
        for col, typedef in [
            ("source_version_id", "INTEGER"),
            ("confidence", "REAL DEFAULT 1.0"),
            ("observed_time", "TEXT"),
            ("marking", "TEXT DEFAULT 'UNCLASSIFIED'"),
        ]:
            try:
                conn.execute(f"ALTER TABLE [{table}] ADD COLUMN {col} {typedef}")
            except sqlite3.OperationalError:
                pass  # column already exists
    conn.execute(
        "INSERT OR REPLACE INTO metadata VALUES (?, ?)",
        ("schema_version", "3")
    )
    conn.commit()


def initialize_database(db_path: Path, metadata: dict = None) -> dict:
    """
    Create and initialize an ICARUS database.

    Handles fresh creation (v3) and migration from existing v2 databases.
    Returns stats dict with table count and schema version.
    """
    conn = sqlite3.connect(str(db_path))

    existing_version = None
    try:
        row = conn.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()
        if row:
            existing_version = int(row[0])
    except sqlite3.OperationalError:
        pass

    if existing_version == 2:
        migrate_v2_to_v3(conn)
    elif existing_version is None or existing_version < 2:
        conn.executescript(CORE_SCHEMA)
        conn.executescript(INDEXES)
        conn.executescript(FTS_SCHEMA)
        conn.executescript(FTS_TRIGGERS)
        conn.executescript(VIEWS)

    conn.execute(
        "INSERT OR REPLACE INTO metadata VALUES (?, ?)",
        ("schema_version", str(SCHEMA_VERSION))
    )

    if metadata:
        for k, v in metadata.items():
            conn.execute(
                "INSERT OR REPLACE INTO metadata VALUES (?, ?)", (k, str(v))
            )

    conn.commit()

    tables = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
    ).fetchone()[0]

    conn.close()
    return {"tables": tables, "schema_version": SCHEMA_VERSION}


def get_schema_version(db_path: Path) -> Optional[int]:
    """Get the schema version of an existing database."""
    try:
        conn = sqlite3.connect(str(db_path))
        row = conn.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()
        conn.close()
        return int(row[0]) if row else None
    except (sqlite3.OperationalError, TypeError):
        return None
