# ICARUS

[![CI](https://github.com/Indegosblade/icarus-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/Indegosblade/icarus-framework/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat)
![License: PolyForm NC](https://img.shields.io/badge/license-PolyForm%20NC-orange?style=flat)

**Point it at data. It maps what's inside, how it connects, and what changed.**

ICARUS extracts entities from structured data sources, resolves them into a queryable graph, diffs across versions, and sanitizes the output. One command in, one SQLite database out.

```
Source directory --> Parser --> Entity graph --> SQLite database
                                                     |
                                     +---------------+---------------+
                                     |               |               |
                                  Differ          HYGEIA          STIX
                               (versions)     (sanitization)    (export)
```

**2,099,505 entities extracted from a single machine. 24,822 PII findings caught and redacted. Zero residual. That's the v3 validation run.**

---

## Quick Start

```bash
pip install git+https://github.com/Indegosblade/icarus-framework.git

# Scan a directory — parser auto-detected
icarus build --source /path/to/data --output intel.db

# Query it
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

## What It Does

### Extract

8 production parsers. Auto-detected from source contents via a registry contest — most specific parser wins.

| Parser | Specificity | What It Extracts |
|--------|:-----------:|-----------------|
| `cloud/aws/cloudtrail` | 5 | IAM identities, API events, error patterns |
| `windows` | 20 | PE/DLL binaries, configs, frameworks, file metadata |
| `linux` | 20 | ELF binaries, systemd services, shared libraries, capabilities |
| `generic/json` | 100 | JSON file catalog + top-level key extraction |
| `generic/xml` | 100 | XML file catalog |
| `generic/sqlite` | 100 | SQLite file catalog + schema discovery |
| `generic/archive` | 100 | Archive catalog (.zip/.tar/.gz) + contents listing |
| `generic/binary` | 100 | Catch-all: any directory with files |

Lower specificity wins. CloudTrail at 5 beats Windows at 20 beats generic at 100. If no specific parser matches, a generic always catches it.

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

6 pre-built intelligence views. Or write raw SQL — it's just SQLite.

### Diff

Run ICARUS on version N and version N+1. Diff them.

```python
from icarus.core.differ import IcarusDiffer

with IcarusDiffer("v1.db", "v2.db") as d:
    results = d.full_diff()           # Files, daemons, kexts + structural
    structural = d.structural_diff()  # Topology changes only
    report = d.generate_report()      # Markdown
```

| Category | What It Catches |
|----------|----------------|
| ADDITION | Entity exists in new, not old |
| DELETION | Entity exists in old, not new |
| PROPERTY_CHANGE | Same entity, different attribute |
| STRUCTURAL | Relationship topology changed |
| RESOLUTION_CHANGE | Entity resolved differently |

### Resolve

Same entity, different sources. ICARUS groups them.

```python
from icarus.core.resolver import EntityResolver

with EntityResolver("intel.db") as r:
    a1 = r.ingest_atom(version_id=1, entity_type="daemon",
                       source_key="config", properties={"name": "nginx", "port": 80})
    a2 = r.ingest_atom(version_id=2, entity_type="daemon",
                       source_key="binary", properties={"name": "nginx", "path": "/usr/sbin/nginx"})
    r.resolve("daemon", blocking_keys=["name"])
```

**Atoms** are immutable observations. **Bags** group atoms into resolved entities (merge/split with full reversibility). **Event log** records every decision. FTS5 blocking index generates candidates in linear time.

### Sanitize

[HYGEIA](https://github.com/Indegosblade/HYGEIA) strips PII before the database is marked complete. Usernames in paths, emails, credentials, device identifiers — caught and redacted.

```python
from icarus.integrations.hygeia import sanitize_output, verify_clean

stats = sanitize_output(db_path)   # {'redacted': 24822, ...}
result = verify_clean(db_path)     # {'passed': True, 'findings': 0}
```

### Export

STIX 2.1 interoperability. Entities map to SCOs/SDOs. Diffs map to note bundles.

```python
from icarus.integrations.stix_export import export_to_stix, diff_to_stix

export_to_stix(db_path, output_path)               # Full entity export
diff_to_stix(old_db, new_db, output_path)           # Diff as STIX bundle
```

```bash
icarus diff old.db new.db --stix changes.json
```

---

## Real-World Validation

Every number below comes from a real run, not a benchmark.

### v3.0.0 — Full Machine Scan

| Metric | Value |
|--------|------:|
| Source | `C:\Users\Kevin` (full user profile) |
| Files cataloged | **2,045,000** |
| Binaries detected | **29,427** |
| Frameworks | **25,078** |
| **Total entities** | **2,099,505** |
| Database size | **20.5 GB** |
| PII findings (pre-sanitize) | 24,822 |
| PII findings (post-sanitize) | **0** |
| HYGEIA verdict | **PASS** |
| Parser | Windows (auto-detected) |
| Install | Fresh `pip install` from GitHub |

### v2.0.0 — Multi-Source Validation

| Dataset | Platform | Entities | Data | Binaries | PII | HYGEIA |
|---------|----------|------:|-----:|---------:|:---:|:------:|
| Full user profile | Windows | 116,002 | 244 GB | 399 PE | **0** | **PASS** |
| Python 3.12 | Windows | 55,346 | 2,079 MB | 150 PE | **0** | **PASS** |
| Chrome profile | Windows | 25,916 | 3,249 MB | 3 PE | **0** | **PASS** |
| Ubuntu /usr | Linux (WSL2) | 96,181 | 12,834 MB | 1,111 ELF | **0** | **PASS** |

---

## Database Schema

15 normalized tables. 3 FTS indexes. 3 intelligence views. Schema v4.

```sql
-- Ontology: entities with cell-level provenance
files, binaries, daemons, entitlements,
sandbox_profiles, sandbox_rules, kexts, frameworks

-- Infrastructure
metadata, versions

-- Events
observations          -- temporal events against any entity

-- Entity resolution
atoms, bags, bag_atoms, resolution_event_log

-- Full-text search (auto-synced triggers)
files_fts, daemons_fts, atoms_fts

-- Intelligence views
v_sandbox_escape_surface, v_kernel_attack_surface, v_test_binaries
```

Every entity row carries provenance: `source_version_id`, `confidence` (0.0-1.0), `observed_time`, `marking` (UNCLASSIFIED/PII/SENSITIVE/REDACTED).

---

## Parser Ecosystem

Each parser ships with a YAML manifest validated by JSON Schema at load time. The manifest declares identity, quality tier, specificity, reliability grade (Admiralty A-F), and test configuration.

```bash
# Registry listing
icarus parser list

# Manifest validation
icarus parser validate icarus/parsers/windows.yaml

# Test harness: golden output, idempotency, schema conformance, zero-PII
icarus parser test windows
```

**Writing a new parser:**

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

Add a YAML manifest, register it, and the full engine is behind it — pipeline, diffing, resolution, sanitization, STIX export, CLI.

See [about/PARSERS.md](about/PARSERS.md) for the full development guide.

---

## Pipeline

Streaming. Checkpoint/resume. Scales to millions of entities without loading the dataset into memory.

```python
from icarus.core.pipeline import create_default_pipeline

p = create_default_pipeline(source, output, parser_name="linux")
p.run()                # Full run
p.run(resume=True)     # Resume from last checkpoint
```

| Property | Value |
|----------|-------|
| Memory | Streaming — never loads full dataset |
| Storage | SQLite (single file, portable, zero infrastructure) |
| Resume | Checkpoint per phase — crash at 6, resume at 6 |
| Search | FTS5 full-text with auto-sync triggers |
| Traversal | `os.walk` with error callbacks — handles broken symlinks, permission errors, WSL artifacts |
| Provenance | Auto-finalized version records with entity count + completion timestamp |
| Parsers | 8 production, auto-detected via registry contest |
| Tests | 77 — schema, query, diff, pipeline, HYGEIA, parsers, resolution, observations, manifest, registry, harness, generics, CloudTrail, STIX |
| CI | GitHub Actions: pytest (3.10/3.12/3.13 x ubuntu/windows/macos), ruff, mypy, bandit |

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

**Dependencies:**
- Python 3.10+
- SQLite 3.35+ (FTS5)
- [HYGEIA](https://github.com/Indegosblade/HYGEIA) (auto-installed)
- [PyYAML](https://pyyaml.org/) >=6.0
- [jsonschema](https://python-jsonschema.readthedocs.io/) >=4.20

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
|   |   |-- catalog/          # Two-tier catalog (production + candidate JSON)
|   |   +-- schema/           # Parser manifest JSON Schema
|   +-- integrations/
|       |-- hygeia.py         # HYGEIA sanitization layer
|       +-- stix_export.py    # STIX 2.1 export (entities + diffs)
|-- tests/                    # 77 tests
|-- examples/                 # Custom parser template
|-- schema/                   # Standalone SQL reference
|-- about/                    # Architecture + parser development docs
|-- wiki/                     # GitHub wiki source
|-- .github/workflows/ci.yml  # CI matrix
|-- LICENSE                   # PolyForm Noncommercial 1.0.0
+-- pyproject.toml
```

---

## Changelog

### v3.0.0
- **Parser ecosystem** — YAML manifest format validated by JSON Schema, parser registry with most-specific-wins detection contest, two-tier catalog (production + candidate), parser test harness with 4 quality gates (golden output, idempotency, schema conformance, zero-PII)
- **8 production parsers** — Windows, Linux, CloudTrail, JSON, XML, SQLite, Archive, Binary. All manifested, registered, tested.
- **CloudTrail parser** — maps IAM identities to daemons, API events to observations. Admiralty grade A, specificity 5.
- **Generic fallback parsers** — 5 catch-all parsers at specificity 100. Any directory with files gets cataloged.
- **STIX 2.1 export** — `export_to_stix()` and `diff_to_stix()`. CLI: `icarus diff old.db new.db --stix output.json`
- **CLI: `icarus parser`** — `validate`, `list`, `test` subcommands
- **2,099,505-entity validation** — full machine scan, 24,822 PII redactions, HYGEIA clean pass
- **77 tests** across 8 test modules

### v2.0.0
- **Entity resolution** — Atom/Bag/EventLog pattern with FTS5 blocking index
- **Observations** — temporal event layer with generic FK to any ontology entity
- **Two-graph architecture** — ontology graph + event graph in the same database
- **Schema v4** — 5 new tables, 7 new indexes, migration chain v2->v3->v4
- **Safe traversal** — `os.walk(onerror=...)`, `try/finally` connection cleanup
- **43 tests**, macOS CI added

### v1.2.0
- **Linux parser** — ELF detection, architecture classification, systemd parsing
- **177,443 entities** validated across 3 datasets

### v1.1.0
- **5-category diff** — ADDITION, DELETION, PROPERTY_CHANGE, STRUCTURAL, RESOLUTION_CHANGE
- **Structural diffing** — relationship topology change detection
- **HYGEIA as dependency** — `--skip-hygeia` flag
- **Windows parser** — PE/DLL detection

### v1.0.0
- Core framework: pipeline, schema with FTS5, query engine, cross-version differ
- HYGEIA integration, cell-level provenance, CI

---

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — free for research, education, and personal use.

## Author

[@Indegosblade](https://github.com/Indegosblade)
