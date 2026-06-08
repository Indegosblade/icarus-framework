# ICARUS Architecture

## Design Philosophy

ICARUS is built on one observation: structured data sources contain implicit relationships that are invisible at the individual-file level but obvious at the relational-query level. The framework's job is to make those relationships queryable.

---

## Component Map

```
+-------------------------------------------------------------------+
|                          PIPELINE                                  |
|  Phase orchestrator, checkpoint/resume, streaming                  |
+-------------------------------------------------------------------+
|         |              |              |               |            |
|    +----v----+    +----v----+    +----v----+    +----v----+        |
|    | PARSER  |    | SCHEMA  |    |  QUERY  |    |RESOLVER |        |
|    |Registry |    | Manager |    | Engine  |    | Entity  |        |
|    |8 parsers|    |         |    |         |    | Resolve |        |
|    +----+----+    +----+----+    +----+----+    +----+----+        |
|         |              |              |              |              |
|         +------- ------+---------- ---+--------------+             |
|                        |              |                            |
|                   +----v----+    +----v--------+                   |
|                   | SQLite  |    | TWO-GRAPH   |                   |
|                   |  + FTS5 |    | Ontology +  |                   |
|                   +----+----+    | Event Graph |                   |
|                        |         +-------------+                   |
|              +---------+---------+                                 |
|              |         |         |                                 |
|         +----v----+ +--v-----+ +v--------+                        |
|         | DIFFER  | | HYGEIA | |  STIX   |                        |
|         | Cross-  | |Sanitize| | Export  |                        |
|         | version | | Output | | 2.1     |                        |
|         +---------+ +--------+ +---------+                        |
+-------------------------------------------------------------------+
```

---

## Data Flow

```
Source --> Parser.identify() --> Parser.extract_entities() --> SQLite
                                                                |
                              Parser.extract_relationships() <--+
                                                                |
                                           Schema.verify() <----+
                                                                |
                                     HYGEIA.sanitize_output() <-+
                                                                |
                                            QueryEngine <-------+
                                                 |
                                    +------------+------------+
                                    |            |            |
                                  SQL      FTS5 Search     Views
```

---

## Core Design Decisions

### 1. SQLite, Not Postgres

Single-file database. No server. No configuration. Copy the .db file anywhere and query it. The only dependency is Python's built-in sqlite3 module. A v3 validation run produced a 20.5 GB database with 2 million entities in a single file.

### 2. Streaming, Not Batch

Every extraction phase processes records one-at-a-time with periodic commits. A 2-million-file source never loads more than one file's metadata into RAM at a time. SQLite memory-mapped I/O and page cache scale to available system RAM for speed — the streaming design is about correctness (never requiring all data in memory simultaneously), not about restricting memory use.

### 2b. Safe Traversal

Parsers use `os.walk(onerror=lambda e: None)` instead of `pathlib.rglob()`. This handles broken symlinks (e.g., WSL `.venv/lib64` on Windows), inaccessible system paths, and permission-denied directories without crashing the pipeline. Connection cleanup uses `try/finally` — if extraction crashes mid-walk, the SQLite connection is always released.

### 3. Parser Ecosystem

The framework doesn't know what a Windows ACL or a Linux capability is. The parser knows. v3 ships 8 production parsers — each with a YAML manifest (validated by JSON Schema), quality tier, specificity level, and Admiralty reliability grade. A registry contest auto-selects the best parser for any source. Generic fallback parsers ensure every directory gets cataloged.

**Parser test harness** enforces 4 quality gates on every parser: golden output match, idempotency (second run adds zero entities), schema conformance (only writes to declared tables), and zero-PII (HYGEIA verify passes).

### 4. Diffing Is First-Class

Not an afterthought. The differ attaches two databases and runs set-difference queries. What was added? Removed? Silently modified? Single-version analysis finds what exists; cross-version analysis finds what changed. Five diff categories — from simple additions to structural topology changes.

### 5. Built-in Sanitization

HYGEIA runs as a pipeline phase, not a post-processing step. PII is stripped before the database is marked complete. In the v3 validation run: 24,822 PII findings detected and redacted from 2 million entities. Post-sanitize: zero residual.

### 6. Cell-Level Provenance

Every entity row carries four provenance fields:
- `source_version_id` — which ingest run produced this datum (FK to `versions` table)
- `confidence` — 0.0-1.0, how certain the parser is about this entity
- `observed_time` — ISO 8601 timestamp of when this was observed
- `marking` — access classification: `UNCLASSIFIED`, `PII`, `SENSITIVE`, `REDACTED`

The `versions` table records every pipeline run: UUID, parser name, source path, timestamps, entity count. Any row in any entity table traces back to the run that created it.

### 7. Two-Graph Architecture

A single ICARUS database contains two complementary graphs:

- **Ontology graph** — entities (files, binaries, daemons, kexts, frameworks) and their relationships. Slow-moving, structural. The "what exists" layer.
- **Event graph** — observations (temporal events on any entity) and resolution decisions (atoms grouped into bags). Fast-moving, temporal. The "what happened" layer.

Cross-graph queries join them: "which daemons that changed permissions also have new observations?"

### 8. Entity Resolution (Atom/Bag/EventLog)

When the same entity appears in different sources under different identifiers, the resolver groups them:

- **Atoms** — immutable property bundles. One per observation, per source. Never modified after creation.
- **Bags** — resolved entity groups. Each bag contains one or more atoms that represent the same real-world thing. Merge/split with full reversibility.
- **Event log** — append-only record of every resolution decision. Records reason, confidence, operator, and full atom list.

The `BlockingIndex` uses FTS5 to generate candidate pairs in linear time — avoiding O(n^2) comparison.

### 9. STIX 2.1 Interoperability

ICARUS entities map to STIX 2.1 objects for interoperability with threat intelligence platforms:
- `files` -> STIX File SCO
- `binaries` -> STIX File SCO with extensions
- `daemons` -> STIX Infrastructure SDO
- `entitlements` -> STIX Course of Action SDO
- `observations` -> STIX Observed Data SDO

Diffs export as STIX Note objects with addition/deletion classification.

---

## Schema (v4)

15 normalized tables. 3 FTS indexes. 3 intelligence views.

| Layer | Tables |
|-------|--------|
| Ontology | files, binaries, daemons, entitlements, sandbox_profiles, sandbox_rules, kexts, frameworks |
| Infrastructure | metadata, versions |
| Events | observations |
| Resolution | atoms, bags, bag_atoms, resolution_event_log |
| Search | files_fts, daemons_fts, atoms_fts |
| Views | v_sandbox_escape_surface, v_kernel_attack_surface, v_test_binaries |

Migration chain: v2 -> v3 -> v4. Automatic on database open.

---

## Extension Points

| What | How | Example |
|------|-----|---------|
| New data source | Implement `BaseParser` + YAML manifest | Android OTA, Docker image, Kubernetes, network scan |
| New entity type | Add table to schema + parser extraction | Containers, network hosts, API endpoints |
| New intelligence query | Add method to `IcarusQuery` | Custom privilege chains, anomaly detection |
| New sanitization rule | Add pattern to HYGEIA integration | Domain-specific PII (medical, financial) |
| New diff dimension | Add method to `IcarusDiffer` | Semantic diffing, custom comparison keys |
| New export format | Add module to `integrations/` | MISP, OpenIOC, SARIF |

---

## Validation History

| Version | Entities | Datasets | PII Residual |
|---------|----------|----------|:------------:|
| v3.0.0 | 2,099,505 | Full machine scan (Windows) | **0** |
| v2.0.0 | 293,445 | 4 datasets (Windows + Linux) | **0** |
| v1.2.0 | 177,443 | 3 datasets (Windows + Linux) | **0** |
