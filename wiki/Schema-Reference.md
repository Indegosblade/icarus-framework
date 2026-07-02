# Schema Reference

ICARUS uses SQLite with schema version 5. 16 normalized tables, 3 FTS5 indexes, 3 intelligence views.

## Entity Tables

All entity tables carry cell-level provenance:

| Column | Type | Description |
|--------|------|-------------|
| `source_version_id` | INTEGER | FK to versions table — which pipeline run produced this |
| `confidence` | REAL | 0.0-1.0, parser confidence in this entity |
| `observed_time` | TEXT | ISO 8601 timestamp |
| `marking` | TEXT | UNCLASSIFIED, PII, SENSITIVE, or REDACTED |

### files

Primary entity table. Every file found during extraction.

| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER | Primary key |
| path | TEXT | Relative path from source root (UNIQUE) |
| filename | TEXT | Basename |
| extension | TEXT | File extension (lowercase) |
| size | INTEGER | Bytes |
| sha256 | TEXT | SHA-256 hash (NULL for large/unreadable files) |
| file_type | TEXT | Parser-assigned type |
| + provenance columns | | |

### binaries

Executable files with architecture detection.

| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER | Primary key |
| file_id | INTEGER | FK to files |
| executable_name | TEXT | Binary name |
| arch | TEXT | x86, x86_64, arm64, aarch64, etc. |
| bundle_id | TEXT | App bundle identifier |
| + provenance columns | | |

### daemons

Services, launch daemons, systemd units, IAM identities.

| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER | Primary key |
| label | TEXT | Service identifier (NOT NULL) |
| plist_path | TEXT | Config path (NOT NULL) |
| program | TEXT | Executable path |
| program_arguments | TEXT | Command line |
| user_name | TEXT | Run-as user |
| group_name | TEXT | Run-as group |
| run_at_load | INTEGER | Auto-start flag |
| keep_alive | INTEGER | Restart flag |
| sandbox_profile | TEXT | Associated sandbox |
| mach_services | TEXT | Registered Mach services |
| binary_id | INTEGER | FK to binaries |
| is_disabled | INTEGER | Disabled flag |
| session_type | TEXT | Session type |
| + provenance columns | | |

### mach_services

Normalized launchd `MachServices`. One row per Mach service name a daemon vends — the reachability pivot from a Mach service name to the daemon that answers it. Populates a first-class join instead of parsing the serialized `daemons.mach_services` TEXT blob.

| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER | Primary key |
| daemon_id | INTEGER | FK to daemons (NOT NULL) |
| service_name | TEXT | Mach service name (NOT NULL) |
| + provenance columns | | |

`UNIQUE(daemon_id, service_name)`. Provenance `confidence` defaults to 1.0, `marking` to UNCLASSIFIED.

### entitlements, sandbox_profiles, sandbox_rules, kexts, frameworks

Similar structure — see `schema/icarus_schema.sql` for full DDL.

## Infrastructure Tables

### metadata

Key-value store for database metadata.

| Column | Type | Notes |
|--------|------|-------|
| key | TEXT | Primary key |
| value | TEXT | |

Always contains: `schema_version` (currently "5"), `source` (source path).

### versions

Pipeline run provenance. One row per `icarus build` execution.

| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER | Primary key |
| uuid | TEXT | Unique run identifier |
| parser_name | TEXT | Parser used |
| source_path | TEXT | Source directory |
| created_at | TEXT | Run start timestamp |
| completed_at | TEXT | Run completion timestamp |
| entity_count | INTEGER | Total entities ingested |

## Event Tables

### observations

Temporal events against any ontology entity. Generic foreign key pattern.

| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER | Primary key |
| entity_table | TEXT | Target table name (e.g., "daemons") |
| entity_id | INTEGER | Row ID in target table |
| observed_at | TEXT | When the event occurred |
| event_type | TEXT | Event classification |
| observer | TEXT | What produced this observation |
| properties | TEXT | JSON or text payload |

## Resolution Tables

### atoms

Immutable observations from each source. Never modified after creation.

### bags

Resolved entity groups. Atoms that represent the same real-world thing.

### bag_atoms

Junction table: atom-to-bag membership.

### resolution_event_log

Append-only audit trail of every resolution decision (create, merge, split).

## FTS5 Indexes

| Index | Source Table | Indexed Columns |
|-------|-------------|----------------|
| files_fts | files | path, filename |
| daemons_fts | daemons | label, program |
| atoms_fts | atoms | properties |

Auto-synced via INSERT/DELETE triggers.

## Intelligence Views

| View | What It Shows |
|------|--------------|
| v_sandbox_escape_surface | Daemons with Mach services but no launchd sandbox profile (daemon -> binary -> entitlements) |
| v_kernel_attack_surface | Kexts exposing a user client (has_user_client = 1) |
| v_test_binaries | Binaries with test/debug in their path or bundle ID |

## Migration Chain

v2 -> v3 -> v4 -> v5. Applied automatically when opening an older database.
