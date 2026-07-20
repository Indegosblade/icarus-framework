# ICARUS Public-Release Audit — Findings Ledger

Canonical, deduplicated ledger. Every entry is reproduced or proven from code and
(where high/blocker) independently skeptic-verified. Status legend: **MERGED** = on
`main` and integrated-CI verified; **open** = not yet implemented (the governing owner
decision, where one applies, is noted).

Severity uses the skeptic-corrected value where it differs from first report.

## Blockers

| ID | Issue | Title | Status |
|---|---|---|---|
| PKG-01 | #32 | Wheel/sdist omit all parser manifests, JSON Schema, catalogs | **MERGED** (#37, `fbd2fca`) |
| SAN-01/02/03 | #41 | Sanitized output still contains secrets (HYGEIA never wired; fallback has no credential patterns) | **MERGED** (#59, `7ecc7a8`; HYGEIA canonical + fail-closed, credential patterns, no raw-secret retention) |

**Both release blockers are now closed** (PKG-01 #37, SAN-01 #59).

## High

| ID | Issue | Title | Status |
|---|---|---|---|
| DIFF-01 | #33 | Cross-DB diff compared local autoincrement ids → false/hidden moves | **MERGED** (#38, `39f3b11`; structural **and** observation diff) |
| STIX-01…08 | #21 | STIX export not spec-valid (non-UUID ids, dangling refs, invalid diff Notes/timestamps) | open (escalated) |
| DM-03 | #45 | Resume with changed `--source`/`--parser` → wrong database | open — D2 decided, fix pending |
| PARSER-01/02 | #43 | Parsers dereference in-root symlinks → read outside the source tree | **MERGED** (#62, `31338cd`; symlinks cataloged, never dereferenced) |
| PROV-01 (DM-01) | #40 | Provenance NULL on every entity despite finalized versions row | open |
| SCHEMA-01 (DM-05) | #39 | `initialize_database` silently relabels a future schema to v6 | **MERGED** (#53, `1abbeb2`) |
| ER-01…10 | #46 | Entity-resolver invariants unsound (experimental) | open (epic) — D3: excluded from beta promise |

## Medium

| ID | Issue | Title |
|---|---|---|
| CLI-01 | #34 | `query` is read-write + arbitrary `--sql`; no schema check; weak exit codes *(owner decision)* |
| DIFF-02 | #35 | `full_diff` incomplete; NULL-hash blind spot; report not escaped |
| BUILD-01 (DM-04) | #36 | Existing-output reuse/union; `--fresh` misnomer; no atomic write *(owner decision)* |
| SAN-04/05/07-10 | #42 | Sanitization coverage/verification gaps (metadata skipped, no post-gate, verifier echoes secret) — **MERGED** (#59: mandatory post-sanitize gate, metadata/FTS tables scanned, verifier returns fingerprints not matches) |
| DM-02 | #44 | FK enforcement OFF on all parser/pipeline write paths — **MERGED** (#54, `f1db5ac`; verify-phase `foreign_key_check` gate) |
| PARSER-03/04/05, PHI-01/02 | #47 | Hostile-input: FIFO hang, non-UTF-8 abort, JSON RecursionError, gzip-tar decompression, invalid IPs — **MERGED** (#62, `31338cd`) |
| CI-REL-01 | #49 | CI editable-only, mutable action pins, no dependency scan — **fixed/merged** (#37/#52) |
| DOC-REL-01/03 | #29 | schema.sql (v4) / ARCHITECTURE (v5) stale; version identity incoherent |
| DM-06 | #51 | Fresh-vs-migrated schema divergence: migrated v6 entity tables lack the `source_version_id`→`versions(id)` FK (ALTER can't add REFERENCES) |

## Low / informational

| ID | Issue | Title |
|---|---|---|
| SAN-06 | #22 | Lowercase UUIDs survive (uppercase-only regex) |
| DOC-REL-02/04 | #29 | README stale counts; `readelf` claim vs unused declaration |
| POSTURE-REL-01/02 | #48 | Missing SECURITY/CONTRIBUTING/CHANGELOG; Production/Stable classifier *(owner decision)* |
| STIX-07 | #21 | Ids keyed on rowids, not content |
| ER-09/10 | #46 | Single-link bridge merges; no same-source guard |

## Prior-session issues (still open, corroborated where noted)

#23 linux systemd dirs · #24 macOS duplicate daemon Label · #25 cloudtrail
`identify()` size cap (+ PHI-01 RecursionError) · #26 inflated entity counts · #27
test harness skips relationships · #28 json_parser properties / windows PE-magic ·
#30 hygiene (merge_bags PK = ER-02, threshold = ER-07) · #31 privacy_stack stores raw
credential (root cause = #41) — **resolved by deletion** in merged PR #55 (decision D8).

## Rejected / re-scoped leads

- **"HYGEIA cannot be installed at all / repo is private"** — REJECTED. The HYGEIA
  repo is **public**; `v3.14.0` is a real release; the git-URL dependency installs on
  a clean machine. It remains a PyPI-distribution and reproducibility concern (git
  dep, movable tag), **not** a hard install blocker. (The real HYGEIA problem was #41:
  ICARUS imported the wrong API and never actually called HYGEIA — **fixed in #59**,
  which wires HYGEIA's canonical SQLite sanitizer and fails closed if it can't load.)
- **"Binary STIX ids are non-deterministic across builds"** — partially rejected: ids
  are rowid-derived and *are* identical across two identical builds; they are simply
  not content-addressed (STIX-07, low). The blocker is that they aren't valid UUIDs at
  all (STIX-02).
- Per-agent rejected leads are recorded in the workflow journal
  (the workflow journal in the session subagents directory).

## Note on prior audit claims

`README.md` and the historical `PRODUCTION_AUDIT` describe a "provenance fix" as
landed. That fix added **run-level** tracking (the `versions` row) only; **entity-level**
provenance (`source_version_id`/`observed_time`) is still NULL on real output (#40).
Do not treat the historical claim as satisfying the provenance guarantee.
