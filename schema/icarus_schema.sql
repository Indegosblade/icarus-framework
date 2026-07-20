-- ICARUS Database Schema (v6)
-- Modular intelligence framework for structured data analysis.
-- SQLite 3.35+ required (FTS5 support).
--
-- GENERATED REFERENCE — do not hand-edit. The authoritative schema lives in
-- icarus/core/schema.py (SCHEMA_VERSION = 6); this file is a dump of a freshly
-- initialized database for documentation and external tooling. Regenerate after
-- any schema.py change. 17 normalized tables, 3 FTS5 indexes, 3 views.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ============================================================
-- Tables
-- ============================================================
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL UNIQUE,
    parser_name TEXT NOT NULL,
    source_path TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    entity_count INTEGER DEFAULT 0,
    metadata TEXT
);

CREATE TABLE files (
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

CREATE TABLE binaries (
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

CREATE TABLE frameworks (
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

CREATE TABLE kexts (
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

CREATE TABLE daemons (
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

CREATE TABLE mach_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    daemon_id INTEGER NOT NULL REFERENCES daemons(id),
    service_name TEXT NOT NULL,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED',
    UNIQUE(daemon_id, service_name)
);

CREATE TABLE entitlements (
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

CREATE TABLE sandbox_profiles (
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

CREATE TABLE sandbox_rules (
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

CREATE TABLE observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_table TEXT NOT NULL,
    entity_id INTEGER NOT NULL,
    observed_at TEXT NOT NULL,
    observer TEXT,
    event_type TEXT NOT NULL,
    properties TEXT,
    version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0
);

CREATE TABLE atoms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_version_id INTEGER NOT NULL REFERENCES versions(id),
    entity_type TEXT NOT NULL,
    source_key TEXT NOT NULL,
    properties TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(source_version_id, entity_type, source_key)
);

CREATE TABLE bags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    canonical_key TEXT,
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    atom_count INTEGER DEFAULT 1,
    score REAL
);

CREATE TABLE bag_atoms (
    bag_id INTEGER NOT NULL REFERENCES bags(id),
    atom_id INTEGER NOT NULL REFERENCES atoms(id),
    PRIMARY KEY(bag_id, atom_id)
);

CREATE TABLE resolution_event_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    bag_id INTEGER NOT NULL REFERENCES bags(id),
    atom_ids TEXT NOT NULL,
    reason TEXT,
    confidence REAL,
    operator TEXT,
    timestamp TEXT NOT NULL
);

CREATE TABLE match_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    atom_a INTEGER NOT NULL REFERENCES atoms(id),
    atom_b INTEGER NOT NULL REFERENCES atoms(id),
    score REAL NOT NULL,
    features TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(atom_a, atom_b)
);

CREATE VIRTUAL TABLE files_fts USING fts5(
    path, filename, file_type,
    content='files', content_rowid='id'
);

CREATE VIRTUAL TABLE daemons_fts USING fts5(
    label, program, mach_services, sandbox_profile,
    content='daemons', content_rowid='id'
);

CREATE VIRTUAL TABLE atoms_fts USING fts5(
    entity_type, source_key, properties,
    content='atoms', content_rowid='id'
);

-- ============================================================
-- Views
-- ============================================================
CREATE VIEW v_kernel_attack_surface AS
SELECT
    k.bundle_id, k.name AS kext_name,
    k.version, k.personalities, k.iokit_classes
FROM kexts k WHERE k.has_user_client = 1;

CREATE VIEW v_sandbox_escape_surface AS
SELECT
    d.label, d.program, d.mach_services,
    d.sandbox_profile, d.user_name,
    GROUP_CONCAT(e.key, ', ') AS privileged_entitlements
FROM daemons d
JOIN binaries b ON d.binary_id = b.id
JOIN entitlements e ON e.binary_id = b.id
WHERE (d.sandbox_profile IS NULL OR d.sandbox_profile = '')
AND d.mach_services IS NOT NULL
GROUP BY d.id;

CREATE VIEW v_test_binaries AS
SELECT f.path, b.bundle_id, b.executable_name
FROM binaries b
JOIN files f ON b.file_id = f.id
WHERE f.path LIKE '%/test%' OR f.path LIKE '%/debug%'
    OR b.bundle_id LIKE '%test%' OR b.bundle_id LIKE '%debug%';

-- ============================================================
-- Triggers
-- ============================================================
CREATE TRIGGER atoms_ad AFTER DELETE ON atoms BEGIN
    INSERT INTO atoms_fts(atoms_fts, rowid, entity_type, source_key, properties)
    VALUES ('delete', old.id, old.entity_type, old.source_key, old.properties);
END;

CREATE TRIGGER atoms_ai AFTER INSERT ON atoms BEGIN
    INSERT INTO atoms_fts(rowid, entity_type, source_key, properties)
    VALUES (new.id, new.entity_type, new.source_key, new.properties);
END;

CREATE TRIGGER daemons_ad AFTER DELETE ON daemons BEGIN
    INSERT INTO daemons_fts(daemons_fts, rowid, label, program, mach_services, sandbox_profile)
    VALUES ('delete', old.id, old.label, old.program, old.mach_services, old.sandbox_profile);
END;

CREATE TRIGGER daemons_ai AFTER INSERT ON daemons BEGIN
    INSERT INTO daemons_fts(rowid, label, program, mach_services, sandbox_profile)
    VALUES (new.id, new.label, new.program, new.mach_services, new.sandbox_profile);
END;

CREATE TRIGGER daemons_au AFTER UPDATE ON daemons BEGIN
    INSERT INTO daemons_fts(daemons_fts, rowid, label, program, mach_services, sandbox_profile)
    VALUES ('delete', old.id, old.label, old.program, old.mach_services, old.sandbox_profile);
    INSERT INTO daemons_fts(rowid, label, program, mach_services, sandbox_profile)
    VALUES (new.id, new.label, new.program, new.mach_services, new.sandbox_profile);
END;

CREATE TRIGGER files_ad AFTER DELETE ON files BEGIN
    INSERT INTO files_fts(files_fts, rowid, path, filename, file_type)
    VALUES ('delete', old.id, old.path, old.filename, old.file_type);
END;

CREATE TRIGGER files_ai AFTER INSERT ON files BEGIN
    INSERT INTO files_fts(rowid, path, filename, file_type)
    VALUES (new.id, new.path, new.filename, new.file_type);
END;

CREATE TRIGGER files_au AFTER UPDATE ON files BEGIN
    INSERT INTO files_fts(files_fts, rowid, path, filename, file_type)
    VALUES ('delete', old.id, old.path, old.filename, old.file_type);
    INSERT INTO files_fts(rowid, path, filename, file_type)
    VALUES (new.id, new.path, new.filename, new.file_type);
END;

-- ============================================================
-- Indexes
-- ============================================================
CREATE INDEX idx_atoms_type ON atoms(entity_type);

CREATE INDEX idx_atoms_version ON atoms(source_version_id);

CREATE INDEX idx_bags_type ON bags(entity_type);

CREATE INDEX idx_binaries_bundle ON binaries(bundle_id);

CREATE INDEX idx_binaries_file ON binaries(file_id);

CREATE INDEX idx_daemons_label ON daemons(label);

CREATE INDEX idx_daemons_sandbox ON daemons(sandbox_profile);

CREATE INDEX idx_ent_binary ON entitlements(binary_id);

CREATE INDEX idx_ent_key ON entitlements(key);

CREATE INDEX idx_ent_key_value ON entitlements(key, value);

CREATE INDEX idx_files_extension ON files(extension);

CREATE INDEX idx_files_path ON files(path);

CREATE INDEX idx_files_size ON files(size DESC);

CREATE INDEX idx_files_type ON files(file_type);

CREATE INDEX idx_frameworks_name ON frameworks(name);

CREATE INDEX idx_kexts_bundle ON kexts(bundle_id);

CREATE INDEX idx_mach_daemon ON mach_services(daemon_id);

CREATE INDEX idx_mach_service ON mach_services(service_name);

CREATE INDEX idx_match_atom_a ON match_candidates(atom_a);

CREATE INDEX idx_match_entity ON match_candidates(entity_type);

CREATE INDEX idx_obs_entity ON observations(entity_table, entity_id);

CREATE INDEX idx_obs_time ON observations(observed_at);

CREATE INDEX idx_obs_type ON observations(event_type);

CREATE INDEX idx_relog_bag ON resolution_event_log(bag_id);

CREATE INDEX idx_rules_operation ON sandbox_rules(operation);

CREATE INDEX idx_rules_profile ON sandbox_rules(profile_id);

CREATE INDEX idx_sandbox_name ON sandbox_profiles(name);
