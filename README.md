# ICARUS

![v1.1.0](https://img.shields.io/badge/version-1.1.0-blue) ![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-green) ![License: PolyForm NC](https://img.shields.io/badge/license-PolyForm%20NC-orange)

**An ontology framework that maps hidden relationships in structured data.**

Things exist. Things have attributes. Things relate to other things. Those relationships — when normalized, cross-referenced, and diffed across time — reveal what's hidden.

ICARUS is an intelligence engine. Point it at any structured data source. It extracts entities, maps their relationships, and builds a queryable graph. Then it asks the questions humans miss at scale: what changed between versions? What's reachable from where? What shouldn't be there?

The iOS firmware pipeline is the reference implementation. The architecture doesn't care what the entities are.

---

## The Dual Nature

ICARUS is two things at the same time.

**Without HYGEIA**, it is a raw intelligence engine — a data mapping tool that reveals privilege chains, hidden relationships, and silent changes in any system it's pointed at. In the wrong hands, this is a threat vector. It maps exactly what an attacker needs to know.

**With [HYGEIA](https://github.com/Indegosblade/HYGEIA)**, it becomes a responsible intelligence framework. The sanitization layer strips PII, credentials, and identifying information before output. This is the architectural decision that makes the difference between a weapon and a research tool.

HYGEIA is not a feature. It is the ethical boundary. The same engine, the same power, with guardrails that make responsible disclosure possible.

```
                    ┌─────────────────┐
                    │   Raw Source     │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │    Parser        │  ← source-agnostic
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Entity Graph    │  ← ontology: entities + relationships
                    └────────┬────────┘
                             │
               ┌─────────────┼─────────────┐
               │                           │
      ┌────────▼────────┐        ┌────────▼────────┐
      │  WITHOUT HYGEIA  │        │   WITH HYGEIA    │
      │                  │        │                  │
      │  Raw graph.      │        │  Sanitized.      │
      │  Full paths.     │        │  PII-free.       │
      │  Real names.     │        │  Shareable.      │
      │  Threat vector.  │        │  Research tool.  │
      └──────────────────┘        └──────────────────┘
```

---

## What It Finds

```python
from icarus.core.query import IcarusQuery

with IcarusQuery("intel.db") as q:
    # Daemons running as root with no sandbox
    q.root_daemons()

    # Full MachService → binary → entitlement map
    q.service_map()

    # Kernel-reachable entry points from userland
    q.kernel_surface()

    # Test/debug binaries left in production builds
    q.test_binaries()

    # High-privilege entities reachable from low-privilege
    q.escape_surface()

    # Dangerous entitlements and who holds them
    q.privileged_entitlements()
```

These are not queries you write. They are intelligence views baked into the schema — materialized answers to questions security researchers ask repeatedly.

---

## Cross-Version Diffing

Run ICARUS on version N and version N+1. Diff them. Find what changed silently.

Five diff categories, classified automatically:

| Category | What It Catches |
|----------|----------------|
| **ADDITION** | Entity exists in new version, not in old |
| **DELETION** | Entity exists in old version, not in new |
| **PROPERTY_CHANGE** | Same entity, different attribute (e.g., binary hash changed) |
| **STRUCTURAL** | Relationship topology changed — edges moved, not just nodes |
| **RESOLUTION_CHANGE** | Reserved for Phase 2 entity resolution |

```python
from icarus.core.differ import IcarusDiffer, DiffCategory

with IcarusDiffer("ios_18.0.db", "ios_18.1.db") as d:
    # Full diff: files, daemons, kexts + structural analysis
    results = d.full_diff()

    # Structural changes: binaries that moved, entitlements reassigned
    structural = d.structural_diff()
    for change in structural.structural:
        print(f"{change['type']}: {change['description']}")

    # What new entitlements appeared?
    d.entitlement_diff(dangerous_keys=[
        "com.apple.private.security.no-sandbox",
        "com.apple.rootless.storage.elevated",
        "platform-application",
    ])

    # Markdown report
    report = d.generate_report()
```

Silent patches. New privileges granted. Services removed or added between builds. Binaries that moved to new locations. Entitlements reassigned to different holders. The differ answers: *what did they change that they didn't tell you about?*

---

## Parser Architecture

The framework is source-agnostic. Swap the parser, keep the engine.

```python
from icarus.parsers.base import BaseParser

class MyParser(BaseParser):
    name = "my_source"

    def identify(self, path):
        """Return True if this parser handles this source."""

    def extract_entities(self, source, db):
        """Walk the source, yield normalized entities."""

    def extract_relationships(self, source, db):
        """Map relationships between entities."""

    def verify(self, db):
        """Quality gates — validate extraction completeness."""
```

| Data Source | What You Map | What You Find |
|-------------|-------------|---------------|
| **iOS IPSW** | Binaries, entitlements, services, sandbox | Privilege chains, attack surface, silent patches |
| **Android OTA** | APKs, permissions, intents, SELinux | Escalation paths, exposed components |
| **Linux rootfs** | ELF binaries, systemd, capabilities | Setuid surface, capability abuse |
| **Windows image** | PE binaries, registry, services, ACLs | Misconfigurations, weak ACLs |
| **Network topology** | Hosts, ports, banners, certs | Exposure mapping, version clustering |
| **API schema** | Endpoints, auth, data models | Missing auth, over-exposed routes |
| **Document corpus** | Entities, dates, references | Org charts, dependency graphs, timeline |
| **Cloud infrastructure** | IAM, resources, policies, logs | Lateral movement paths, stale permissions |

---

## Pipeline

Streaming. Checkpoint/resume. 4GB RAM ceiling.

```bash
# Build intelligence database from iOS rootfs
icarus build --source ./rootfs --output intel.db --parser ios

# Build without HYGEIA (raw output — unsanitized, loud warning)
icarus build --source ./rootfs --output raw.db --parser ios --skip-hygeia

# Query it
icarus query intel.db --search "backboardd"
icarus query intel.db "SELECT * FROM v_sandbox_escape_surface"

# Diff two versions
icarus diff old.db new.db --report changes.md
```

```python
from icarus.core.pipeline import Pipeline

p = Pipeline(source, output, parser_name="ios")
p.run()          # full run
p.run(resume=True)  # resume from last checkpoint
```

| Property | Value |
|----------|-------|
| Memory ceiling | 4 GB (streaming, never loads full dataset) |
| Storage | SQLite (single file, portable, zero infrastructure) |
| Resume | Checkpoint per phase — crash at phase 6, resume at phase 6 |
| Search | FTS5 full-text with auto-sync triggers |
| Extensibility | Drop in a parser, get the full engine |
| Test suite | 20 tests — schema, query, diff, pipeline, HYGEIA, provenance, security |
| CI | GitHub Actions: pytest (3.10/3.12/3.13 x ubuntu/windows), ruff, mypy, bandit |

---

## Database Schema

10 normalized tables. 2 FTS indexes. 3 intelligence views. Cell-level provenance on every entity.

```sql
-- Entities (all carry provenance: source_version_id, confidence, observed_time, marking)
files, binaries, daemons, entitlements,
sandbox_profiles, sandbox_rules, kexts, frameworks

-- Infrastructure
metadata, versions

-- Full-text search (auto-synced via triggers)
files_fts, daemons_fts

-- Intelligence views
v_sandbox_escape_surface
v_kernel_attack_surface
v_test_binaries
```

Every entity has typed attributes, foreign-key relationships, and provenance metadata. The schema is the ontology — entities don't float free, they connect. Every datum traces to the ingest run that produced it.

---

## HYGEIA: The Architectural Decision

[HYGEIA](https://github.com/Indegosblade/HYGEIA) is a core dependency — installed automatically with ICARUS. It is not a post-processing step. It is integrated into the pipeline itself.

```python
from icarus.integrations.hygeia import sanitize_output, verify_clean

# Sanitize the output database
stats = sanitize_output(db_path)
# {'redacted': 47, 'tables_scanned': 8, 'patterns': 7}

# Verify — hard gate, not optional
result = verify_clean(db_path)
assert result["passed"]
```

To skip HYGEIA (raw output — you take responsibility):
```python
Pipeline(source, output, parser_name="ios", skip_hygeia=True)
```
```bash
icarus build --source ./rootfs --output raw.db --parser ios --skip-hygeia
```
Skipping logs `hygeia_skipped=true` to the database metadata and prints a loud warning. The output is unsanitized — do not share without manual review.

What it removes:
- Filesystem paths containing usernames
- Email addresses, phone numbers, credentials
- Device identifiers and serial numbers
- Hostnames and internal network references
- Any pattern matching 7 regex families

What it guarantees:
- Output databases contain zero PII
- WAL files checkpointed and vacuumed (no recoverable deleted records)
- Verification pass confirms clean before pipeline reports success

This is what makes ICARUS publishable. Without it, every output database is a dossier. With it, it's research.

---

## Real-World Validation

ICARUS pointed at a Chrome user profile (2.3 GB, live browser data). No configuration, no prep — raw pipeline execution.

| Metric | Result |
|--------|--------|
| Entities mapped | 25,162 files |
| Data catalogued | 2,339 MB |
| File types identified | JSON configs (523), logs (186), JS (361), LevelDB (120), HTML, CSS, SVG |
| Runtime | 153 seconds (full pipeline including HYGEIA) |
| PII in output | **0** |
| HYGEIA verification | **PASS — zero residual findings** |

The parser normalized 25,162 paths at extraction time (stripping absolute filesystem prefixes), then HYGEIA verified no PII leaked through. Defense in depth: normalize at ingest, verify at output.

Same engine, same power, responsible output. That's the point.

---

## Install

```bash
pip install -e .

# With development tools
pip install -e ".[dev]"
```

**Requirements:**
- Python 3.10+
- SQLite 3.35+ (FTS5 support)
- [HYGEIA](https://github.com/Indegosblade/HYGEIA) (installed automatically as a dependency)

Parser-specific tools: iOS requires `ipsw` and `ldid`. Other parsers specify their own via `get_required_tools()`.

---

## Design Principles

| Principle | Why |
|-----------|-----|
| **Ontology-first** | Entities and relationships are the product. Everything else is infrastructure. |
| **Provenance on every cell** | Every datum carries source, confidence, observation time, and access marking. Trace anything to the run that produced it. |
| **Sanitization-first** | HYGEIA runs before output, not after. Clean by default. |
| **Streaming** | Process records one-at-a-time. Never load full dataset into RAM. |
| **Source-agnostic** | The framework doesn't know what your entities are. It knows they relate. |
| **Diffing as primitive** | Cross-version analysis is core, not bolted on. |
| **Single-file output** | SQLite. Portable. Queryable. Zero infrastructure. |
| **Checkpoint/resume** | Every phase saves progress. Crash-tolerant by design. |

---

## Project Layout

```
icarus-framework/
├── icarus/
│   ├── core/
│   │   ├── __init__.py       # Shared validation, constants
│   │   ├── pipeline.py       # Phase orchestrator, checkpoint/resume
│   │   ├── schema.py         # SQLite schema, FTS5, migrations
│   │   ├── query.py          # Query engine, intelligence views
│   │   └── differ.py         # Cross-version diff engine
│   ├── parsers/
│   │   ├── base.py           # Abstract parser interface
│   │   ├── ios.py            # iOS reference parser (7-phase)
│   │   └── windows.py        # Windows application/directory parser
│   └── integrations/
│       └── hygeia.py         # HYGEIA sanitization layer
├── tests/                    # Pytest suite
├── examples/                 # Quickstart + custom parser template
├── schema/                   # Standalone SQL reference
├── about/                    # Architecture + parser development docs
├── .github/workflows/ci.yml  # CI: test matrix + lint + security
├── LICENSE                   # PolyForm Noncommercial 1.0.0
└── pyproject.toml
```

---

## Changelog

### v1.1.0 (latest)
- **Five-category diff classification** — `DiffCategory` enum: ADDITION, DELETION, PROPERTY_CHANGE, STRUCTURAL, RESOLUTION_CHANGE (reserved)
- **Structural diffing** — `structural_diff()` detects relationship topology changes (binaries moved, entitlements reassigned, sandbox rules shifted)
- **`full_diff()` calls `structural_diff()` automatically** — structural analysis included in every full diff
- **HYGEIA as core dependency** — real package import, installed automatically via `pip install -e .`
- **`--skip-hygeia` flag** — CLI and API. Logs skip to metadata, prints loud warning
- **Windows parser** — PE binary detection, arch classification (x86/x64/arm64), DLL cataloguing
- **Real-world validation** — 25,162 entities from a live Chrome profile, zero PII residual
- **20 tests** — up from 15. New coverage: diff categories, structural diff, resolution_change guard, skip-hygeia metadata
- Python 3.10+ (bumped from 3.9)

### v1.0.0
- Core framework: pipeline orchestrator, SQLite schema with FTS5, query engine (6 intelligence views), cross-version differ
- iOS reference parser (7-phase extraction)
- HYGEIA integration layer (sanitize + verify)
- Cell-level provenance (source_version_id, confidence, observed_time, marking)
- Schema migration chain (v2 -> v3)
- CI: GitHub Actions (pytest matrix, ruff, mypy, bandit)

---

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — free for research, education, and personal use.

## Author

[@Indegosblade](https://github.com/Indegosblade)
