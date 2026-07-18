# ICARUS Public-Release Audit — Executive Summary

**Audit baseline:** `main` @ `eab33b5` (tree clean). Repository **private**. License
**PolyForm-Noncommercial-1.0.0** (source-available, *not* OSI open source).
**Method:** Phase-0 baseline + 7 parallel specialist passes + adversarial skeptic
re-verification (27 agents, 0 errors). Every accepted finding is reproduced or
proven from code.

## What ICARUS is

A modular intelligence framework that ingests structured data sources and filesystem
trees (macOS/iOS, Linux, Windows, CloudTrail, generic JSON/XML/SQLite/archives, and
personal network infra) into a normalized SQLite schema (v6, 17 tables, FTS5), with
cross-version diffing, an experimental entity resolver, HYGEIA sanitization, and STIX
2.1 export. ~8k LOC source, 232 passing tests.

## What is genuinely strong

- **Diff opens both databases immutable read-only** (`mode=ro&immutable=1`) — untrusted
  exports can't be mutated by a diff.
- **Hashing refuses to dereference symlinks** (`base._safe_hash`), and the Mach-O magic
  read is symlink-guarded — the containment *pattern* exists in the codebase.
- **SQL built with allowlist `validate_table`/`validate_column` + bound params**, with
  justified `# nosec B608` at the safe sites.
- **Checkpoint/resume, parser-manifest architecture, most-specific-wins detection, and
  the two-graph (ontology + event) model** are thoughtfully designed.
- **Green gates:** 232 tests pass; ruff/mypy/bandit clean.

The audit's core message: **a green suite is not sufficient.** The clean run masks an
installed package that loses its parser layer, "sanitized" output that still contains
secrets, cross-database diffs built on meaningless local ids, provenance columns that
are never populated, and STIX that no strict parser will accept.

## Release verdict: **NO-GO** (today)

Path to **CONDITIONAL GO for a public *beta*** once the blockers below are fixed or
explicitly removed from the release promise. **Production/Stable is not warranted** —
recommend a Beta classifier and excluding the experimental resolver from the beta
promise.

### Release-blocking findings (must fix, accept as residual risk, or drop from scope)

| Issue | Blocker | Status |
|---|---|---|
| **#32** | Wheel/sdist omit all parser manifests/schema/catalogs → installed package broken | **Fixed** in draft PR **#37** |
| **#41** | "Sanitized" output still contains secrets: real HYGEIA never wired, fallback has no credential patterns | open |
| **#21** | STIX export is not spec-valid (non-UUID ids, dangling refs, invalid diff Notes/timestamps) | open (escalated) |
| **#45** | Resume with a changed `--source` silently yields the *wrong* database | open |
| **#43** | Parsers dereference in-root symlinks → read files outside the source tree | open |
| **#40** | Provenance (`source_version_id`/`observed_time`) NULL on every entity | open |
| **#39** | `initialize_database` silently relabels a future schema to v6 | open |
| **#33** | Cross-DB diff compared local autoincrement ids → false/hidden "moves" | **Fixed** in draft PR **#38** |

### High / medium (should fix for beta)

FK enforcement off on write paths (#44), diff completeness + report escaping (#35),
build-output reuse/`--fresh` (#36), sanitization coverage/verification gaps (#42),
hostile-input hardening (#47), query mutability + exit codes (#34), CI hardening (#49),
docs/schema drift (#29). Full ledger in `FINDINGS.md`.

## Owner decisions required (see `DECISIONS_REQUIRED.md`)

Default query mutability (#34); existing-output/`--fresh` semantics (#36); resolver
policy + beta inclusion (#46); license positioning + maturity classifier + governance
files (#48); secret-retention/data-minimization policy (#41/#42); distribution channel
(the HYGEIA git-URL dependency blocks PyPI); version numbering (#29).

## Operational blocker (account, not code)

New GitHub Actions runs on the private repo currently fail at startup —
*"recent account payments have failed or your spending limit needs to be increased"*
(Billing & plans). CI cannot verify PRs until this is resolved; it is unrelated to any
code change. All PR verification in this audit was done locally.

## Bottom line

A stranger today **cannot** safely install (packaging), **cannot** trust the output
(false diffs, NULL provenance, invalid STIX), and **cannot** safely share it (secrets
survive sanitization). Two of these (packaging, diff) already have verified draft
fixes. The rest are filed, reproduced, and dependency-ordered. **Do not represent
ICARUS as public-ready, open-source, or Production/Stable until the blocker set is
closed.**
