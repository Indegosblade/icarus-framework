# ICARUS

[![CI](https://github.com/Indegosblade/icarus-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/Indegosblade/icarus-framework/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat)
![License: PolyForm NC](https://img.shields.io/badge/license-PolyForm%20NC-orange?style=flat)

A modular framework for extracting entities from structured data sources, resolving them across versions, and producing queryable intelligence databases. One command in, one SQLite database out.

```
Source directory --> Parser --> Entity graph --> SQLite database
                                                     |
                                     +---------------+---------------+
                                     |               |               |
                                  Differ          HYGEIA          STIX
                               (versions)     (sanitization)    (export)
```

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Parsers](#parsers)
- [Schema](#schema)
- [Architecture](#architecture)
- [Development](#development)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [Changelog](#changelog)
- [License](#license)

---

## Quick Start

```bash
pip install git+https://github.com/Indegosblade/icarus-framework.git

icarus build --source /path/to/data --output intel.db
icarus query intel.db --stats
icarus diff v1.db v2.db -o report.md
```

---

## Installation

### Requirements

| Dependency | Version | Purpose |
|-----------|---------|---------|
| Python | >= 3.10 | Runtime. Tested on 3.10, 3.12, 3.13. |
| SQLite | >= 3.35 | FTS5 full-text search support. Ships with Python on all platforms. |
| [HYGEIA](https://github.com/Indegosblade/HYGEIA) | v3.14.0 | PII detection and sanitization. Auto-installed as a dependency. |
| [PyYAML](https://pyyaml.org/) | >= 6.0 | Parser manifest loading. |
| [jsonschema](https://python-jsonschema.readthedocs.io/) | >= 4.20 | Parser manifest validation against JSON Schema. |

No native extensions. No database server. No system-level dependencies beyond Python.

### Install from GitHub

```bash
pip install git+https://github.com/Indegosblade/icarus-framework.git
```

### Install from source

```bash
git clone https://github.com/Indegosblade/icarus-framework.git
cd icarus-framework
pip install .
```

### Development install

Includes pytest, ruff, mypy, and bandit:

```bash
pip install -e ".[dev]"
```

---

## Usage

### CLI

```bash
# Build — auto-detects the best parser from source contents
icarus build --source /path/to/data --output intel.db

# Build — specify parser explicitly
icarus build --source /var/log/cloudtrail --output trail.db --parser cloud/aws/cloudtrail

# Build — skip PII sanitization (raw output, not safe to share)
icarus build --source /data --output raw.db --skip-hygeia

# Query — full-text search
icarus query intel.db --search "nginx"

# Query — table stats
icarus query intel.db --stats

# Query — raw SQL
icarus query intel.db --sql "SELECT path, size FROM files WHERE size > 100000000 ORDER BY size DESC LIMIT 20"

# Diff — compare two databases
icarus diff v1.db v2.db -o report.md

# Diff — export as STIX 2.1 bundle
icarus diff v1.db v2.db --stix bundle.json

# Parsers — list, validate, test
icarus parser list
icarus parser validate icarus/parsers/windows.yaml
icarus parser test windows
```

### Python API

```python
from pathlib import Path
from icarus.core.pipeline import create_default_pipeline
from icarus.core.query import IcarusQuery
from icarus.core.differ import IcarusDiffer
from icarus.core.resolver import EntityResolver
from icarus.integrations.stix_export import export_to_stix

# Build a database
pipeline = create_default_pipeline(
    source=Path("/path/to/data"),
    output=Path("intel.db"),
    parser_name="windows",
)
ctx = pipeline.run()

# Query
with IcarusQuery("intel.db") as q:
    q.root_daemons()              # Services running as root without sandbox
    q.service_map()               # Service -> binary -> permission mapping
    q.kernel_surface()            # Kernel-reachable entry points
    q.escape_surface()            # Privilege escalation paths
    results = q.search("config", table="daemons")

# Diff two versions
with IcarusDiffer("v1.db", "v2.db") as d:
    diff = d.full_diff()          # All categories: add/delete/change/structural
    report = d.generate_report()  # Markdown

# Resolve entities across sources
with EntityResolver("intel.db") as r:
    r.ingest_atom(version_id=1, entity_type="daemon",
                  source_key="config", properties={"name": "nginx", "port": 80})
    r.ingest_atom(version_id=2, entity_type="daemon",
                  source_key="binary", properties={"name": "nginx", "path": "/usr/sbin/nginx"})
    r.resolve("daemon", blocking_keys=["name"])

# Export to STIX 2.1
export_to_stix(Path("intel.db"), Path("bundle.json"))
```

---

## Parsers

8 production parsers. Auto-detection runs each parser's `identify()` method against the source; the most specific match wins.

| Parser | Specificity | Description |
|--------|:-----------:|-------------|
| `cloud/aws/cloudtrail` | 5 | AWS CloudTrail JSON audit logs — IAM identities, API events, error patterns |
| `windows` | 20 | Windows directories — PE/DLL binaries, services, frameworks, file metadata |
| `linux` | 20 | Linux rootfs — ELF binaries, systemd units, shared libraries, capabilities |
| `generic/json` | 100 | JSON file catalog with top-level key extraction |
| `generic/xml` | 100 | XML file catalog |
| `generic/sqlite` | 100 | SQLite database catalog with schema discovery |
| `generic/archive` | 100 | Archive catalog (.zip/.tar/.gz) with contents listing |
| `generic/binary` | 100 | Catch-all — catalogs any directory with files |

Lower specificity wins. CloudTrail (5) beats Windows (20) beats generic (100). If no specific parser matches, a generic fallback always catches it.

Each parser ships with a YAML manifest validated by JSON Schema at load time. Manifests declare quality tier, specificity, [Admiralty reliability grade](https://en.wikipedia.org/wiki/Admiralty_code), and test configuration. A 4-gate test harness enforces golden output, idempotency, schema conformance, and zero-PII verification before a parser reaches production tier.

See [about/PARSERS.md](about/PARSERS.md) for the parser development guide.

---

## Schema

15 normalized tables, 3 FTS5 full-text indexes, 3 intelligence views. Schema version 4 with automatic migration from v2 and v3.

| Layer | Tables |
|-------|--------|
| Ontology | `files`, `binaries`, `daemons`, `entitlements`, `sandbox_profiles`, `sandbox_rules`, `kexts`, `frameworks` |
| Infrastructure | `metadata`, `versions` |
| Events | `observations` |
| Resolution | `atoms`, `bags`, `bag_atoms`, `resolution_event_log` |
| Search | `files_fts`, `daemons_fts`, `atoms_fts` |
| Views | `v_sandbox_escape_surface`, `v_kernel_attack_surface`, `v_test_binaries` |

Every entity row carries cell-level provenance: `source_version_id` (FK to pipeline run), `confidence` (0.0-1.0), `observed_time` (ISO 8601), and `marking` (UNCLASSIFIED / PII / SENSITIVE / REDACTED).

See [wiki/Schema-Reference](wiki/Schema-Reference.md) for full column definitions.

---

## Architecture

**Streaming extraction** — parsers process records individually with periodic batch commits. Source data is never loaded as a whole. SQLite memory-mapped I/O and page cache scale to available system RAM automatically.

**Checkpoint/resume** — the pipeline saves progress after each phase. If it crashes at phase 4, it resumes from phase 4.

**Two-graph model** — a single database holds an ontology graph (entities and relationships, structural) and an event graph (observations and resolution decisions, temporal). Cross-graph joins connect them.

**Entity resolution** — the Atom/Bag/EventLog pattern groups observations from different sources that refer to the same real-world entity. Atoms are immutable. Bags merge and split with full reversibility. An append-only event log records every resolution decision. FTS5 blocking index generates candidate pairs without O(n^2) comparison.

**Diff categories** — ADDITION, DELETION, PROPERTY_CHANGE, STRUCTURAL, RESOLUTION_CHANGE. The differ attaches two databases and runs set-difference queries directly in SQLite.

**PII sanitization** — [HYGEIA](https://github.com/Indegosblade/HYGEIA) runs as a pipeline phase. PII is stripped before the database is marked complete, not as a separate post-processing step.

**STIX 2.1 export** — entities map to STIX Cyber Observable Objects and Domain Objects. Diffs map to STIX Note objects. Deterministic IDs make bundles diffable.

See [about/ARCHITECTURE.md](about/ARCHITECTURE.md) for design decisions and extension points.

---

## Development

### Run tests

```bash
pytest tests/ -x -q
```

77 tests across 8 modules covering schema, queries, diffing, pipeline, entity resolution, observations, parsers, manifests, registry, test harness, generic fallbacks, CloudTrail, and STIX export.

CI runs the full test matrix on every push:

| | ubuntu | windows | macos |
|---|:---:|:---:|:---:|
| **Python 3.10** | x | x | x |
| **Python 3.12** | x | x | x |
| **Python 3.13** | x | x | x |

### Lint

```bash
ruff check .
```

Configured for Python 3.10 target, 100-character line length. Rules: `E` (pycodestyle errors), `F` (pyflakes), `W` (pycodestyle warnings), `I` (isort).

### Type check

```bash
mypy icarus/
```

### Security scan

```bash
bandit -r icarus/ -c pyproject.toml
```

Runs [Bandit](https://bandit.readthedocs.io/) static analysis. Excluded rules are documented in `pyproject.toml` with rationale (e.g., B101 assert in tests, B608 SQL string formatting in parameterized queries).

### Writing a parser

Implement `BaseParser`, add a YAML manifest, register it in `icarus/parsers/__init__.py`:

```python
from icarus.parsers.base import BaseParser
from pathlib import Path

class MyParser(BaseParser):
    @property
    def name(self) -> str:
        return "my_source"

    @property
    def description(self) -> str:
        return "One-line description"

    def identify(self, source: Path) -> bool:
        """Return True if this parser handles the source."""

    def extract_entities(self, source: Path, db_path: Path) -> dict:
        """Walk source, write entities to database."""

    def extract_relationships(self, source: Path, db_path: Path) -> dict:
        """Link entities together."""
```

A working example is in [`examples/custom_parser.py`](examples/custom_parser.py). The full parser development guide is in [about/PARSERS.md](about/PARSERS.md).

---

## Project Structure

```
icarus-framework/
├── icarus/
│   ├── __main__.py               CLI entry point
│   ├── core/
│   │   ├── pipeline.py           Phase orchestrator with checkpoint/resume
│   │   ├── schema.py             SQLite schema v4, FTS5, migrations
│   │   ├── query.py              Query engine with 6 intelligence views
│   │   ├── differ.py             Cross-version diff engine
│   │   ├── resolver.py           Entity resolution (Atom/Bag/EventLog)
│   │   └── registry.py           Parser registry and detection contest
│   ├── parsers/
│   │   ├── base.py               Abstract parser interface
│   │   ├── manifest.py           YAML manifest loader + JSON Schema validation
│   │   ├── testing.py            4-gate test harness
│   │   ├── windows.py            Windows parser (PE/DLL)
│   │   ├── linux.py              Linux parser (ELF/systemd)
│   │   ├── cloud/                Cloud parsers
│   │   ├── generic/              Fallback parsers (json, xml, sqlite, archive, binary)
│   │   ├── catalog/              Two-tier parser catalog
│   │   └── schema/               Manifest JSON Schema
│   └── integrations/
│       ├── hygeia.py             PII sanitization
│       └── stix_export.py        STIX 2.1 export
├── tests/                        77 tests
├── examples/                     Custom parser template
├── schema/                       Standalone SQL reference
├── about/                        Architecture and parser docs
├── wiki/                         GitHub wiki source
├── .github/workflows/ci.yml      CI: 9-job matrix + lint + security
├── pyproject.toml
└── LICENSE
```

---

## Documentation

| Document | Contents |
|----------|----------|
| [about/ARCHITECTURE.md](about/ARCHITECTURE.md) | Design decisions, component map, extension points |
| [about/PARSERS.md](about/PARSERS.md) | Parser development guide, manifest format, registration |
| [wiki/Getting-Started.md](wiki/Getting-Started.md) | Installation and first scan walkthrough |
| [wiki/CLI-Reference.md](wiki/CLI-Reference.md) | All commands and flags |
| [wiki/Schema-Reference.md](wiki/Schema-Reference.md) | Full table and column definitions |
| [wiki/Query-Reference.md](wiki/Query-Reference.md) | Intelligence views, FTS search, SQL patterns |
| [wiki/Parser-Ecosystem.md](wiki/Parser-Ecosystem.md) | Manifests, registry, test harness, quality tiers |
| [wiki/STIX-Export.md](wiki/STIX-Export.md) | STIX 2.1 mapping, custom extensions, bundle format |
| [wiki/Validation-Results.md](wiki/Validation-Results.md) | Test run data from real pipeline executions |

---

## Changelog

### v1.1.1 (2026-06-08) — Final release

Everything shipped in one sprint. This is the first and current stable release.

- **Core:** Pipeline with checkpoint/resume, schema v4 with FTS5 full-text search, query engine with 6 intelligence views, cross-version differ
- **Parsers:** 8 production parsers (Windows, Linux, CloudTrail, JSON, XML, SQLite, Archive, Binary) with YAML manifests, JSON Schema validation, registry detection contest, two-tier catalog, 4-gate test harness
- **Entity resolution:** Atom/Bag/EventLog pattern with FTS5 blocking index, merge/split with full reversibility
- **Observations:** Temporal event layer with generic foreign keys, two-graph architecture (ontology + events)
- **Integrations:** HYGEIA PII sanitization as a pipeline phase, STIX 2.1 export for entities and diffs
- **CLI:** `build`, `query`, `diff`, `parser list/validate/test`
- **Quality:** 77 tests, 9-job CI matrix (3 OS x 3 Python versions), ruff + mypy + bandit

---

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — free for research, education, and personal use.

## Author

[@Indegosblade](https://github.com/Indegosblade)
