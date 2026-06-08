# ICARUS Architecture

## Design Philosophy

ICARUS is built on one observation: structured data sources contain implicit relationships that are invisible at the individual-file level but obvious at the relational-query level. The framework's job is to make those relationships queryable.

---

## Component Map

```
┌──────────────────────────────────────────────────────┐
│                    PIPELINE                            │
│  Phase orchestrator, checkpoint/resume, streaming     │
├──────────────────────────────────────────────────────┤
│         │              │              │               │
│    ┌────▼────┐    ┌────▼────┐    ┌────▼────┐        │
│    │ PARSER  │    │ SCHEMA  │    │  QUERY  │        │
│    │ (plug)  │    │ Manager │    │ Engine  │        │
│    └────┬────┘    └────┬────┘    └────┬────┘        │
│         │              │              │               │
│         └──────────────┼──────────────┘               │
│                        │                              │
│                   ┌────▼────┐                         │
│                   │ SQLite  │  Single-file DB         │
│                   │  + FTS5 │  Full-text search       │
│                   └────┬────┘                         │
│                        │                              │
│              ┌─────────┼─────────┐                    │
│              │                   │                    │
│         ┌────▼────┐        ┌────▼────┐               │
│         │ DIFFER  │        │ HYGEIA  │               │
│         │ Cross-  │        │ Sanitize│               │
│         │ version │        │ Output  │               │
│         └─────────┘        └─────────┘               │
└──────────────────────────────────────────────────────┘
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

Every extraction phase processes records one-at-a-time with periodic commits. A 500K-file rootfs never loads more than one file's metadata into RAM at a time. Hard ceiling: 4GB RAM regardless of source size.

### 3. Parsers Are Plugins, Not Core

The framework doesn't know what an iOS entitlement is. The iOS parser knows. The framework knows how to orchestrate extraction, store normalized entities, and query relationships. Swap parsers without touching core.

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

The `versions` table records every pipeline run: UUID, parser name, source path, timestamps, entity count. Any row in any entity table traces back to the run that created it.

HYGEIA can update markings after sanitization: `PII` → `REDACTED`. The marking lifecycle is: default UNCLASSIFIED → scanner flags PII → HYGEIA sanitizes → marking updated to REDACTED.

---

## Extension Points

| What | How | Example |
|------|-----|---------|
| New data source | Implement `BaseParser` | Android OTA, Windows image, API schema |
| New entity type | Add table to schema + parser extraction | Network hosts, containers, permissions |
| New intelligence query | Add method to `IcarusQuery` | Custom privilege chains, anomaly patterns |
| New sanitization rule | Add pattern to HYGEIA integration | Domain-specific PII (medical, financial) |
| New diff dimension | Add method to `IcarusDiffer` | Custom comparison keys, semantic diffing |
