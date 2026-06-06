# ICARUS

**Modular intelligence framework for structured data analysis.**

A pipeline engine that transforms any structured data source — firmware dumps, databases, APIs, document collections — into normalized, queryable intelligence. Ingest, normalize, cross-reference, diff, query. Point it at something and ask questions.

Ships with iOS firmware analysis as the reference implementation. The architecture is source-agnostic.

---

## What It Does

```
Raw Data → Parser → Normalizer → SQLite Intelligence DB → Query Engine
                                        ↓
                              Cross-Reference / Diff
                                        ↓
                              Relationships & Anomalies
```

ICARUS turns unstructured or semi-structured data into a relational graph. Then you query it for patterns humans miss at scale — entity relationships, privilege chains, version-to-version changes, anomalous configurations, missing constraints.

---

## Architecture

```
icarus/
├── core/
│   ├── pipeline.py       # Orchestrator — phase sequencing, checkpoint/resume
│   ├── schema.py         # SQLite schema manager, migrations, FTS5 setup
│   ├── query.py          # Query engine — SQL, full-text search, views
│   └── differ.py         # Cross-version diffing engine
├── parsers/
│   ├── base.py           # Abstract parser interface
│   ├── ios.py            # iOS firmware parser (reference implementation)
│   └── ...               # Swap in your own
├── integrations/
│   └── hygeia.py         # HYGEIA sanitization (PII removal before output)
└── __init__.py
```

| Component | Role |
|-----------|------|
| **Pipeline** | Phase sequencing with checkpoint/resume. Streaming — processes records one-at-a-time, 4GB RAM ceiling. |
| **Schema** | Normalized relational model. Entities, relationships, attributes. FTS5 full-text search. Materialized views. |
| **Query Engine** | SQL interface + pre-built intelligence queries. Attack surface views, anomaly detection, privilege graphs. |
| **Differ** | Cross-version comparison. What changed, what was added, what was removed, what was silently modified. |
| **Parsers** | Pluggable data source modules. Each parser knows how to extract entities from one source type. |
| **HYGEIA** | Sanitization layer — ensures output databases contain no PII, credentials, or identifying information. |

---

## Parser Architecture

The framework is source-agnostic. Each parser implements a simple interface:

```python
from icarus.parsers.base import BaseParser

class MyParser(BaseParser):
    """Extract entities from your data source."""

    def identify(self, path):
        """Return True if this parser handles this source."""
        ...

    def extract_entities(self, source, db):
        """Walk the source, yield normalized entities to the database."""
        ...

    def extract_relationships(self, source, db):
        """Map relationships between entities."""
        ...
```

### Reference: iOS Firmware Parser

The included iOS parser handles IPSW rootfs dumps:

| Phase | What It Extracts |
|-------|-----------------|
| Filesystem | Every file: path, size, permissions, type, hash |
| Binaries | Mach-O metadata: arch, code signatures, linked dylibs, segments |
| Entitlements | Key-value pairs per binary (ldid/ipsw extraction) |
| Services | LaunchDaemons → MachServices → binary → entitlement graph |
| Kernel | IOKit class hierarchy, UserClient enumeration, kext personalities |
| Sandbox | .sb profile reversal, permission rules per operation |
| Frameworks | System/Private framework inventory |

### Swap the Parser

| Data Source | Parser Extracts | Intelligence You Get |
|-------------|----------------|---------------------|
| **iOS IPSW** | Binaries, entitlements, services, sandbox | Privilege graphs, attack surface, silent patches |
| **Android OTA** | APKs, permissions, intents, SELinux | Permission escalation paths, exposed components |
| **Linux rootfs** | ELF binaries, systemd units, capabilities, AppArmor | Privilege boundaries, setuid surface, capability abuse |
| **Windows image** | PE binaries, registry hives, services, ACLs | Service misconfigurations, unquoted paths, weak ACLs |
| **Network scan** | Hosts, ports, banners, certificates | Topology mapping, version clustering, exposure |
| **API schema** | Endpoints, auth requirements, data models | Missing auth, over-exposed internal routes |
| **Document corpus** | Entities, dates, relationships, references | Org charts, dependency graphs, timeline reconstruction |

---

## Database Schema

8 core tables, 3 materialized views, FTS5 full-text search.

```sql
-- Core entity tables
files           -- Complete inventory of source artifacts
binaries        -- Executable metadata and signatures  
daemons         -- Services, their configurations, and privilege levels
entitlements    -- Normalized permission/capability pairs per entity
sandbox_profiles -- Security boundary definitions
sandbox_rules   -- Individual allow/deny rules within boundaries
kexts           -- Kernel-level components
frameworks      -- Libraries and their relationships

-- Intelligence views
v_sandbox_escape_surface  -- High-privilege entities reachable from low-privilege
v_kernel_attack_surface   -- Kernel-reachable entry points
v_test_binaries           -- Debug/test artifacts in production
```

---

## Processing Pipeline

9 phases, checkpoint/resume capable. Crash at phase 6? Resume from phase 6.

| Phase | Duration | What Happens |
|-------|----------|-------------|
| 0 | Varies | Source ingestion (filesystem walk, API crawl, DB import) |
| 1 | 5-10 min | Sanitization pass (HYGEIA — remove PII before processing) |
| 2 | Varies | Entity extraction (parser-specific) |
| 3 | 2-5 min | Verification and quality gates |
| 4-5 | 30-60 min | Relationship mapping |
| 6-7 | 20-30 min | Deep analysis (kernel components, security boundaries) |
| 8 | 30-45 min | Security policy reversal |
| 9 | 5 min | Report generation |

---

## Cross-Version Diffing

The real power. Run ICARUS on version N and version N+1. Diff them.

```python
from icarus.core.differ import IcarusDiffer

diff = IcarusDiffer("v1.db", "v2.db")

# What binaries changed? (silent patches)
changed = diff.changed_entities(table="binaries", key="path", compare="sha256")

# What permissions were added?
new_perms = diff.added_entities(table="entitlements", key=["binary_id", "key"])

# What services were removed? (attack surface reduction)
removed = diff.removed_entities(table="daemons", key="label")

# What security boundaries changed?
boundary_changes = diff.changed_entities(table="sandbox_rules", key=["profile_id", "operation"])
```

---

## Quick Start

### Requirements

- Python 3.9+
- SQLite 3.35+ (FTS5 support)
- Parser-specific tools (iOS: `ipsw`, `ldid`; Linux: `readelf`; etc.)

### iOS Example (reference implementation)

```bash
# Extract rootfs from IPSW
ipsw extract --dmg fs firmware.ipsw
ipsw fw aea *.aea && 7z x *.dmg -o rootfs/

# Build intelligence database
python -m icarus --parser ios --source ./rootfs --output intel.db

# Query it
python -m icarus query intel.db "SELECT * FROM v_sandbox_escape_surface"
python -m icarus query intel.db --search "backboardd"

# Diff two versions
python -m icarus diff old.db new.db --report changes.md
```

---

## Other Uses

ICARUS is an intelligence engine. The iOS firmware pipeline is one application of a general pattern: **ingest structured data, normalize it into entities and relationships, then query for things humans miss at scale.**

The same architecture applies to:

- **Organizational intelligence** — map reporting structures, access patterns, role relationships across large datasets
- **Infrastructure auditing** — normalize network topology, service dependencies, and permission graphs into queryable form
- **Compliance analysis** — cross-reference policy documents against actual configurations, flag drift
- **Dependency mapping** — trace relationships between components across systems, identify single points of failure
- **Historical analysis** — version-diff any system over time, detect silent changes that weren't announced

The framework doesn't care what the entities are. It cares about the pattern: things exist, things have attributes, things relate to other things, and those relationships reveal what's hidden.

---

## HYGEIA Integration

Every ICARUS pipeline includes a sanitization pass via [HYGEIA](https://github.com/Indegosblade/HYGEIA). Before any data is written to the output database:

- PII is detected and removed (7 pattern families)
- SQLite WAL files are checkpointed and vacuumed (no recoverable deleted records)
- Credentials in configuration files are redacted
- Output is verified clean before the pipeline reports success

This ensures intelligence databases are safe to share, store, and query without leaking source-identifying information.

---

## Design Principles

- **Streaming** — process records one-at-a-time, never load full dataset into RAM
- **4GB ceiling** — runs on commodity hardware, no GPU required
- **SQLite core** — single-file database, portable, queryable, zero infrastructure
- **Checkpoint/resume** — every phase saves progress, resume on crash
- **Parser-agnostic** — the framework doesn't know or care about your data source
- **Sanitization-first** — HYGEIA runs before output, not after
- **Diffing as a first-class operation** — cross-version analysis is built into the core, not bolted on

---

## Project Structure

```
ICARUS-PUBLIC/
├── README.md
├── LICENSE                    # PolyForm Noncommercial 1.0.0
├── .gitignore
├── schema/
│   └── icarus_schema.sql     # Complete database schema
├── icarus/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── pipeline.py       # Phase orchestrator
│   │   ├── schema.py         # Database schema manager
│   │   ├── query.py          # Query engine
│   │   └── differ.py         # Cross-version differ
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── base.py           # Abstract parser interface
│   │   └── ios.py            # iOS reference parser
│   └── integrations/
│       ├── __init__.py
│       └── hygeia.py         # HYGEIA sanitization layer
├── examples/
│   ├── ios_quickstart.py     # Full iOS pipeline example
│   └── custom_parser.py     # How to write your own parser
└── about/
    ├── ARCHITECTURE.md       # Deep dive on component design
    └── PARSERS.md            # Parser development guide
```

---

## License

PolyForm Noncommercial 1.0.0 — free for research, education, and personal use. No commercial use. See [LICENSE](LICENSE).

## Authors

[@Indegosblade](https://github.com/Indegosblade)
