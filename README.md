# ICARUS

[![CI](https://github.com/Indegosblade/icarus-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/Indegosblade/icarus-framework/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat)
![License: PolyForm NC](https://img.shields.io/badge/license-PolyForm%20NC-orange?style=flat)

ICARUS extracts entities from structured data sources, maps their relationships into a queryable SQLite database, diffs across versions, and sanitizes the output for sharing.

```
Source directory --> Parser --> Entity graph --> SQLite database
                                                     |
                                     +---------------+---------------+
                                     |               |               |
                                  Differ          HYGEIA          STIX
                               (versions)     (sanitization)    (export)
```

---

## Quick Start

```bash
pip install git+https://github.com/Indegosblade/icarus-framework.git

# Scan a directory — parser auto-detected
icarus build --source /path/to/data --output intel.db

# Query
icarus query intel.db --search "nginx"
icarus query intel.db --stats

# Diff two versions
icarus diff v1.db v2.db -o report.md

# Export diff as STIX 2.1
icarus diff v1.db v2.db --stix bundle.json

# List registered parsers
icarus parser list
```

---

## Features

### Extract

8 parsers, auto-detected from source contents. A registry contest picks the most specific match.

| Parser | Specificity | What It Extracts |
|--------|:-----------:|-----------------|
| `cloud/aws/cloudtrail` | 5 | IAM identities, API events, error patterns |
| `windows` | 20 | PE/DLL binaries, configs, frameworks, file metadata |
| `linux` | 20 | ELF binaries, systemd services, shared libraries, capabilities |
| `generic/json` | 100 | JSON file catalog with top-level key extraction |
| `generic/xml` | 100 | XML file catalog |
| `generic/sqlite` | 100 | SQLite file catalog with schema discovery |
| `generic/archive` | 100 | Archive catalog (.zip/.tar/.gz) with contents listing |
| `generic/binary` | 100 | Catch-all for any directory |

Lower specificity wins. If no specific parser matches, a generic fallback catches it.

### Query

```python
from icarus.core.query import IcarusQuery

with IcarusQuery("intel.db") as q:
    q.root_daemons()           # Services running as root, no sandbox
    q.service_map()            # Service -> binary -> permission map
    q.kernel_surface()         # Kernel-reachable entry points
    q.test_binaries()          # Debug/test binaries left in production
    q.escape_surface()         # High-privilege reachable from low-privilege
    q.privileged_entitlements() # Permission distribution across binaries
```

6 pre-built intelligence views, or write raw SQL against the database directly.

### Diff

Run ICARUS on version N and version N+1. Diff the databases.

```python
from icarus.core.differ import IcarusDiffer

with IcarusDiffer("v1.db", "v2.db") as d:
    results = d.full_diff()           # Files, daemons, kexts + structural
    structural = d.structural_diff()  # Topology changes only
    report = d.generate_report()      # Markdown
```

| Category | Description |
|----------|-------------|
| ADDITION | Entity exists in new, not old |
| DELETION | Entity exists in old, not new |
| PROPERTY_CHANGE | Same entity, different attribute |
| STRUCTURAL | Relationship topology changed |
| RESOLUTION_CHANGE | Entity resolved differently |

### Resolve

Entities from different sources may refer to the same thing under different identifiers. The resolver groups them.

```python
from icarus.core.resolver import EntityResolver

with EntityResolver("intel.db") as r:
    a1 = r.ingest_atom(version_id=1, entity_type="daemon",
                       source_key="config", properties={"name": "nginx", "port": 80})
    a2 = r.ingest_atom(version_id=2, entity_type="daemon",
                       source_key="binary", properties={"name": "nginx", "path": "/usr/sbin/nginx"})
    r.resolve("daemon", blocking_keys=["name"])
```

**Atoms** are immutable observations. **Bags** group atoms into resolved entities. **Event log** records every resolution decision. FTS5 blocking index generates candidates without O(n^2) comparison.

### Sanitize

[HYGEIA](https://github.com/Indegosblade/HYGEIA) strips PII before the database is marked complete. Usernames, emails, credentials, device identifiers.

```python
from icarus.integrations.hygeia import sanitize_output, verify_clean

stats = sanitize_output(db_path)
result = verify_clean(db_path)
```

### Export

STIX 2.1 interoperability. Entities map to SCOs/SDOs. Diffs map to note bundles.

```python
from icarus.integrations.stix_export import export_to_stix, diff_to_stix

export_to_stix(db_path, output_path)
diff_to_stix(old_db, new_db, output_path)
```

---

## Database Schema

15 normalized tables. 3 FTS indexes. 3 intelligence views. Schema v4.

```sql
-- Ontology
files, binaries, daemons, entitlements,
sandbox_profiles, sandbox_rules, kexts, frameworks

-- Infrastructure
metadata, versions

-- Events
observations

-- Entity resolution
atoms, bags, bag_atoms, resolution_event_log

-- Full-text search (auto-synced via triggers)
files_fts, daemons_fts, atoms_fts

-- Intelligence views
v_sandbox_escape_surface, v_kernel_attack_surface, v_test_binaries
```

Every entity row carries provenance: `source_version_id`, `confidence`, `observed_time`, `marking`.

---

## Parser Ecosystem

Each parser ships with a YAML manifest validated by JSON Schema at load time. Manifests declare identity, quality tier, specificity, reliability grade, and test configuration.

```bash
icarus parser list
icarus parser validate icarus/parsers/windows.yaml
icarus parser test windows
```

Writing a new parser:

```python
from icarus.parsers.base import BaseParser

class MyParser(BaseParser):
    name = "my_source"

    def identify(self, path):
        """Return True if this parser handles this source."""

    def extract_entities(self, source, db):
        """Walk source, write to database tables."""

    def extract_relationships(self, source, db):
        """Link entities together."""
```

Add a YAML manifest, register it, and the full engine is available: pipeline, diffing, resolution, sanitization, STIX export, CLI.

See [about/PARSERS.md](about/PARSERS.md) for the development guide.

---

## Pipeline

Streaming extraction with checkpoint/resume. Crash at phase N, resume from phase N.

```python
from icarus.core.pipeline import create_default_pipeline

p = create_default_pipeline(source, output, parser_name="linux")
p.run()                # Full run
p.run(resume=True)     # Resume from last checkpoint
```

| Property | Detail |
|----------|--------|
| Memory | Streaming — processes records individually, never loads full dataset |
| Storage | SQLite, single portable file |
| Resume | Checkpoint per phase |
| Search | FTS5 full-text with auto-sync triggers |
| Traversal | `os.walk` with error callbacks for broken symlinks and permission errors |
| Parsers | 8 production, auto-detected via registry contest |
| Tests | 77 across 8 test modules |
| CI | pytest (3.10/3.12/3.13 x ubuntu/windows/macos), ruff, mypy, bandit |

---

## Install

```bash
pip install git+https://github.com/Indegosblade/icarus-framework.git
```

From source:
```bash
git clone https://github.com/Indegosblade/icarus-framework.git
cd icarus-framework
pip install .
```

Development:
```bash
pip install -e ".[dev]"
```

**Requirements:** Python 3.10+, SQLite 3.35+ (FTS5), [HYGEIA](https://github.com/Indegosblade/HYGEIA), PyYAML >=6.0, jsonschema >=4.20.

---

## Project Layout

```
icarus-framework/
|-- icarus/
|   |-- core/
|   |   |-- __init__.py       # Shared validation, constants
|   |   |-- pipeline.py       # Phase orchestrator, checkpoint/resume
|   |   |-- schema.py         # SQLite schema v4, FTS5, migrations
|   |   |-- query.py          # Query engine, 6 intelligence views
|   |   |-- differ.py         # Cross-version diff engine
|   |   |-- resolver.py       # Entity resolution (Atom/Bag/EventLog)
|   |   +-- registry.py       # Parser registry, most-specific-wins contest
|   |-- parsers/
|   |   |-- base.py           # Abstract parser interface
|   |   |-- manifest.py       # YAML manifest loader + JSON Schema validation
|   |   |-- testing.py        # Test harness (golden, idempotency, schema, PII)
|   |   |-- windows.py        # Windows parser (PE/DLL)
|   |   |-- linux.py          # Linux parser (ELF/systemd)
|   |   |-- cloud/            # Cloud parsers (cloudtrail.py)
|   |   |-- generic/          # Fallback parsers (json, xml, sqlite, archive, binary)
|   |   |-- catalog/          # Two-tier catalog (production + candidate)
|   |   +-- schema/           # Parser manifest JSON Schema
|   +-- integrations/
|       |-- hygeia.py         # HYGEIA sanitization layer
|       +-- stix_export.py    # STIX 2.1 export
|-- tests/
|-- examples/
|-- schema/
|-- about/
|-- wiki/
|-- .github/workflows/ci.yml
|-- LICENSE
+-- pyproject.toml
```

---

## Changelog

### v3.0.0
- Parser ecosystem: YAML manifests, JSON Schema validation, registry with most-specific-wins detection, two-tier catalog, test harness with 4 quality gates
- 8 production parsers: Windows, Linux, CloudTrail, JSON, XML, SQLite, Archive, Binary
- CloudTrail parser for AWS audit logs
- Generic fallback parsers at specificity 100
- STIX 2.1 export for entities and diffs
- `icarus parser` CLI subcommands: `validate`, `list`, `test`

### v2.0.0
- Entity resolution with Atom/Bag/EventLog pattern and FTS5 blocking index
- Observations: temporal event layer with generic FK
- Two-graph architecture: ontology + event graph
- Schema v4: 5 new tables, 7 new indexes, migration chain v2->v3->v4

### v1.2.0
- Linux parser: ELF detection, architecture classification, systemd parsing

### v1.1.0
- 5-category diff engine: ADDITION, DELETION, PROPERTY_CHANGE, STRUCTURAL, RESOLUTION_CHANGE
- HYGEIA as a pipeline dependency with `--skip-hygeia` flag
- Windows parser: PE/DLL detection

### v1.0.0
- Core framework: pipeline, schema with FTS5, query engine, cross-version differ
- HYGEIA integration, cell-level provenance, CI

---

## License

[PolyForm Noncommercial 1.0.0](LICENSE)

## Author

[@Indegosblade](https://github.com/Indegosblade)
