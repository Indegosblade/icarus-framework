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
| STIX-01…08 | #21 | STIX export not spec-valid (non-UUID ids, dangling refs, invalid diff Notes/timestamps) | **MERGED** (#61, `ab26f1d`; deterministic RFC-4122 `uuid5` ids, valid refs/timestamps) |
| DM-03 | #45 | Resume with changed `--source`/`--parser` → wrong database | **MERGED** (#68, D2; strict resume fingerprint fails loudly on source/parser/config mismatch) |
| PARSER-01/02 | #43 | Parsers dereference in-root symlinks → read outside the source tree | **MERGED** (#62, `31338cd`; symlinks cataloged, never dereferenced) |
| PROV-01 (DM-01) | #40 | Provenance NULL on every entity despite finalized versions row | **MERGED** (#60, `d6eb08e`; pipeline back-fills `source_version_id`/`observed_time` on parser output) |
| SCHEMA-01 (DM-05) | #39 | `initialize_database` silently relabels a future schema to v6 | **MERGED** (#53, `1abbeb2`) |
| ER-01…10 | #46 | Entity-resolver invariants unsound (experimental) | open (epic) — D3: excluded from beta promise |

## Medium

| ID | Issue | Title |
|---|---|---|
| CLI-01 | #34 | `query` is read-write + arbitrary `--sql`; no schema check; weak exit codes — **MERGED** (#66, D1; read-only by default + `query_only`, explicit `exec` for writes, clean exit codes) |
| DIFF-02 | #35 | `full_diff` incomplete; NULL-hash blind spot; report not escaped — **MERGED** (#70; full_diff covers every table + real resolution diff, NULL-hash size compare, `_md_sanitize` neutralizes hostile report values) |
| BUILD-01 (DM-04) | #36 | Existing-output reuse/union; `--fresh` misnomer; no atomic write — **MERGED** (#68, D2; refuse-existing-by-default, atomic `--fresh` via temp + `os.replace`) |
| SAN-04/05/07-10 | #42 | Sanitization coverage/verification gaps (metadata skipped, no post-gate, verifier echoes secret) — **MERGED** (#59 post-gate + metadata/FTS scanning + fingerprint-only verifier; #67 closes the SAN-09 residual: `atoms_au` update trigger + unconditional FTS-index rebuild after sanitize) |
| DM-02 | #44 | FK enforcement OFF on all parser/pipeline write paths — **MERGED** (#54, `f1db5ac`; verify-phase `foreign_key_check` gate) |
| PARSER-03/04/05, PHI-01/02 | #47 | Hostile-input: FIFO hang, non-UTF-8 abort, JSON RecursionError, gzip-tar decompression, invalid IPs — **MERGED** (#62, `31338cd`) |
| CI-REL-01 | #49 | CI editable-only, mutable action pins, no dependency scan — **fixed/merged** (#37/#52) |
| DOC-REL-01/03 | #29 | schema.sql (v4) / ARCHITECTURE (v5) stale; version identity incoherent |
| DM-06 | #51 | Fresh-vs-migrated schema divergence: migrated v6 entity tables lack the `source_version_id`→`versions(id)` FK (ALTER can't add REFERENCES) |

## Low / informational

| ID | Issue | Title |
|---|---|---|
| SAN-06 | #22 | Lowercase UUIDs survive (uppercase-only regex) — **RESOLVED/CLOSED** (already handled by #59: the ICARUS `uuid` pattern is `re.IGNORECASE`, matches both cases) |
| DOC-REL-02/04 | #29 | README stale counts; `readelf` claim vs unused declaration |
| POSTURE-REL-01/02 | #48 | Missing SECURITY/CONTRIBUTING/CHANGELOG; Production/Stable classifier *(owner decision)* |
| STIX-07 | #21 | Ids keyed on rowids, not content |
| ER-09/10 | #46 | Single-link bridge merges; no same-source guard |

## Prior-session issues

**MERGED (polish batch):** #23 linux systemd unit dirs (usr-merged/etc), #24 macOS
duplicate-Label MachService misattribution, #26 inflated entity counts (rowcount-gated),
#28 json_parser properties-as-JSON + windows `.dll` PE-magic — all **#71**. #27 test
harness now runs the relationships phase + #30 hygiene (merge_bags shared-atom, `--threshold`
range check, resolver test-warning noise, real Shannon entropy) — **#74**.

**Still open:** #25 cloudtrail `identify()` size cap (+ PHI-01 RecursionError, low). #31
privacy_stack stores raw credential (root cause = #41) — **resolved by deletion** in merged
PR #55 (D8). Broader migration-completeness gap surfaced while fixing #51 — filed as **#73**
(migrated DBs lack FTS/views/indexes/`atoms_au`; medium, not a beta blocker).

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

The historical `PRODUCTION_AUDIT` "provenance fix" added only **run-level** tracking
(the `versions` row); **entity-level** provenance (`source_version_id`/`observed_time`)
was left NULL on real output. That entity-level gap is now genuinely closed in **#60**
(`d6eb08e`): a pipeline phase back-fills both columns on parser output after extraction.
