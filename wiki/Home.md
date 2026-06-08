# ICARUS Wiki

**ICARUS** is a modular intelligence framework that extracts entities from structured data, maps their relationships, diffs across versions, and sanitizes the output. Point it at data, get a queryable graph.

## v3.0.0 Highlights

- **2,099,505 entities** extracted from a single machine
- **8 production parsers** with manifest-driven ecosystem
- **24,822 PII findings** caught and redacted (zero residual)
- **STIX 2.1 export** for threat intelligence interoperability
- **77 tests** across schema, query, diff, pipeline, parsers, resolution, STIX

## Pages

- [[Getting Started]] — Installation, first scan, basic queries
- [[CLI Reference]] — All commands and flags
- [[Parser Development]] — Writing and registering custom parsers
- [[Parser Ecosystem]] — Manifests, registry, testing harness, catalog
- [[Schema Reference]] — Database tables, views, FTS indexes
- [[Query Reference]] — Intelligence views, FTS search, SQL patterns
- [[Diffing]] — Cross-version analysis, structural diffs
- [[Entity Resolution]] — Atom/Bag/EventLog pattern
- [[STIX Export]] — STIX 2.1 mapping and CLI usage
- [[HYGEIA Integration]] — PII sanitization pipeline
- [[Observations]] — Temporal event tracking
- [[Validation Results]] — Real-world test data and numbers
