# ICARUS Architecture

## Design Philosophy

ICARUS is built on one observation: structured data sources contain implicit relationships that are invisible at the individual-file level but obvious at the relational-query level. The framework's job is to make those relationships queryable.

---

## Component Map

```
┌───────────────────────────────────────────────────────────────────┐
│                         PIPELINE                                   │
│  Phase orchestrator, checkpoint/resume, streaming                 │
├───────────────────────────────────────────────────────────────────┤
│         │              │              │               │            │
│    ┌────▼────┐    ┌────▼────┐    ┌────▼────┐    ┌────▼────┐     │
│    │ PARSER  │    │ SCHEMA  │    │  QUERY  │    │RESOLVER │     │
│    │ (plug)  │    │ Manager │    │ Engine  │    │ Entity  │     │
│    └────┬────┘    └────┬────┘    └────┬────┘    │ Resolve │     │
│         │              │              │          └────┬────┘     │
│         └──────────────┼──────────────┼──────────────┘           │
│                        │              │                           │
│                   ┌────▼────┐    ┌────▼────────┐                 │
│                   │ SQLite  │    │ TWO-GRAPH   │                 │
│                   │  + FTS5 │    │ Ontology +  │                 │
│                   └────┬────┘    │ Event Graph │                 │
│                        │         └─────────────┘                 │
│              ┌─────────┼─────────┐                               │
│              │                   │                               │
│         ┌────▼────┐        ┌────▼────┐                          │
│         │ DIFFER  │        │ HYGEIA  │                          │
│         │ Cross-  │        │ Sanitize│                          │
│         │ version │        │ Output  │                          │
│         └─────────┘        └─────────┘                          │
└───────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

```
Source → Parser.identify() → Parser.extract_entities() → SQLite
                                                            │
                           Parser.extract_relationships() ←─┘
                                                            │
                                        Schema.verify() ←───┘
                                                            │
                                  HYGEIA.sanitize_output() ←┘
                                                            │
                                         QueryEngine ←──────┘
                                              │
                                    ┌─────────┼─────────┐
                                    │         │         │
                                  SQL    FTS5 Search   Views
```

---

## Core Design Decisions

### 1. SQLite, Not Postgres

Single-file database. No server. No configuration. Copy the .db file anywhere and query it. Share it via USB drive if you want. The only dependency is Python's built-in sqlite3 module.

### 2. Streaming, Not Batch

Every extraction phase processes records one-at-a-time with periodic commits. A 500K-file source never loads more than one file's metadata into RAM at a time. Hard ceiling: 4GB RAM regardless of source size.

### 2b. Safe Traversal

Parsers use `os.walk(onerror=lambda e: None)` instead of `pathlib.rglob()`. This handles broken symlinks (e.g., WSL `.venv/lib64` on Windows), inaccessible system paths, and permission-denied directories without crashing the pipeline. Connection cleanup uses `try/finally` — if extraction crashes mid-walk, the SQLite connection is always released. No database lock cascade.

### 3. Parsers Are Plugins, Not Core

The framework doesn't know what a Windows ACL or a Linux capability is. The parser knows. The framework knows how to orchestrate extraction, store normalized entities, and query relationships. Two parsers ship out of the box — Windows (PE binaries, DLLs) and Linux (ELF binaries, shared libraries, systemd services). Swap parsers or write new ones without touching core.

### 4. Diffing Is First-Class

Not an afterthought. The differ attaches two databases and runs set-difference queries. What was added? Removed? Silently modified? This is where the real intelligence lives — single-version analysis finds what exists; cross-version analysis finds what changed.

### 5. Sanitization Before Output

HYGEIA runs as a pipeline phase, not a post-processing step. The database is never "done" with PII in it — sanitization is part of completion. If HYGEIA fails, the pipeline fails.

### 6. Cell-Level Provenance

Every entity row carries four provenance fields:
- `source_version_id` — which ingest run produced this datum (FK to `versions` table)
- `confidence` — 0.0–1.0, how certain the parser is about this entity
- `observed_time` — ISO 8601 timestamp of when this was observed
- `marking` — access classification: `UNCLASSIFIED`, `PII`, `SENSITIVE`, `REDACTED`

The `versions` table records every pipeline run: UUID, parser name, source path, timestamps, entity count. The pipeline auto-finalizes each version record on completion — `entity_count` is summed from ingest stats, `completed_at` is timestamped. Any row in any entity table traces back to the run that created it.

HYGEIA can update markings after sanitization: `PII` → `REDACTED`. The marking lifecycle is: default UNCLASSIFIED → scanner flags PII → HYGEIA sanitizes → marking updated to REDACTED.

### 7. Two-Graph Architecture

A single ICARUS database contains two complementary graphs:

- **Ontology graph** — entities (files, binaries, daemons, kexts, frameworks) and their relationships. Slow-moving, structural. This is the "what exists" layer.
- **Event graph** — observations (temporal events on any entity) and resolution decisions (atoms grouped into bags). Fast-moving, temporal. This is the "what happened" layer.

Cross-graph queries join them: "which daemons that changed permissions also have new observations?" The ontology graph answers *what*; the event graph answers *when* and *how*.

### 8. Entity Resolution (Atom/Bag/EventLog)

When the same entity appears in different sources under different identifiers, the resolver groups them:

- **Atoms** — immutable property bundles. One per observation, per source. Never modified after creation.
- **Bags** — resolved entity groups. Each bag contains one or more atoms that represent the same real-world thing. Bags support merge (combine two bags) and split (move atoms to a new bag).
- **Event log** — append-only record of every resolution decision: creation, merge, split. Records reason, confidence, operator, and full atom list. Never updated or deleted.

The `BlockingIndex` uses FTS5 to generate candidate pairs in linear time — tokenize atom properties, match via full-text search, score by relevance. This avoids the O(n²) comparison that makes naive entity resolution impractical at scale.

---

## Extension Points

| What | How | Example |
|------|-----|---------|
| New data source | Implement `BaseParser` | Android OTA, Docker image, API schema, network scan |
| New entity type | Add table to schema + parser extraction | Network hosts, containers, permissions |
| New intelligence query | Add method to `IcarusQuery` | Custom privilege chains, anomaly patterns |
| New sanitization rule | Add pattern to HYGEIA integration | Domain-specific PII (medical, financial) |
| New diff dimension | Add method to `IcarusDiffer` | Custom comparison keys, semantic diffing |
