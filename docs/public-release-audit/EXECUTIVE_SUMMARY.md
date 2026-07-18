# ICARUS Public-Release Audit — Executive Summary

**Audit baseline:** `main` @ `eab33b5` (tree clean). Repository **private**. License
**PolyForm-Noncommercial-1.0.0** (source-available, *not* OSI open source).
**Method:** Phase-0 baseline + 7 parallel specialist passes + adversarial skeptic
re-verification (27 agents, 0 errors). Every accepted finding is reproduced or
proven from code.

**Remediation status (updated):** owner decisions D1–D9 are now **answered** (see
`DECISIONS_REQUIRED.md`). The packaging blocker **#37 is merged** to `main`
(`fbd2fca`, CI-green while the repo was briefly public); the diff blocker (#38),
schema-refusal (#53 → #39), foreign-key enforcement (#54 → #44), CI hardening (#52),
and the personal-parser removal (#55 → #31/D8) are reviewed, locally verified, and
staged as draft PRs awaiting CI. A second independent implementer (Sol / OpenAI
Codex) authored #52/#53/#54; each was re-reviewed and reproduced here before being
accepted.

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
| **#32** | Wheel/sdist omit all parser manifests/schema/catalogs → installed package broken | **Merged** (#37, `fbd2fca`) |
| **#41** | "Sanitized" output still contains secrets: real HYGEIA never wired, fallback has no credential patterns | open (D4 decided; fix pending) |
| **#21** | STIX export is not spec-valid (non-UUID ids, dangling refs, invalid diff Notes/timestamps) | open (escalated) |
| **#45** | Resume with a changed `--source` silently yields the *wrong* database | open (D2 decided; fix pending) |
| **#43** | Parsers dereference in-root symlinks → read files outside the source tree | open |
| **#40** | Provenance (`source_version_id`/`observed_time`) NULL on every entity | open |
| **#39** | `initialize_database` silently relabels a future schema to v6 | **Fixed**, staged PR **#53** (verified) |
| **#33** | Cross-DB diff compared local autoincrement ids → false/hidden "moves" | **Fixed** (`structural_diff` **and** `observation_diff`), staged PR **#38** |

### High / medium (should fix for beta)

FK enforcement off on write paths (#44), diff completeness + report escaping (#35),
build-output reuse/`--fresh` (#36), sanitization coverage/verification gaps (#42),
hostile-input hardening (#47), query mutability + exit codes (#34), CI hardening (#49),
docs/schema drift (#29). Full ledger in `FINDINGS.md`.

## Owner decisions — now answered (see `DECISIONS_REQUIRED.md`)

All nine gating decisions have been made: query read-only-by-default (D1), atomic
`--fresh` + strict resume fingerprint (D2), resolver excluded from the beta promise
(D3), HYGEIA-canonical fail-closed sanitization with no raw-secret retention (D4),
Beta + source-available positioning (D5), GitHub-release-wheel distribution (D6),
monotonic `4.0.0b1` versioning (D7), delete the personal network parsers (D8), and
opt-in-only third-party plugin loading (D9). These now gate *implementation*, not
further debate.

## Operational blocker (repository visibility, not code)

CI runs on GitHub Actions only while the repository is **public** (private-repo
Actions are billing-gated on this account). The repo was made public long enough for
every PR to record a green matrix, then **reverted to private**, so new runs now
no-start (*"recent account payments have failed or your spending limit needs to be
increased"*). This is a visibility/billing setting, unrelated to any code change; all
verification in this audit was reproduced locally. **Merging the staged PRs requires
the repo to be public (or private-Actions billing restored) so CI can re-run.**

## Bottom line

Verdict remains **NO-GO** for public release today, but the blocker set is closing.
**Install is fixed and merged** (#37). **Output-trust** is materially improved: the
false-diff blocker is fully fixed (structural **and** observation diff, #38), a future
schema is now refused (#39/#53), and foreign keys are enforced on every write path
(#44/#54) — all staged and locally verified. Still open and gating a beta: **secret
survival in "sanitized" output** (#41, the top confidentiality blocker), **NULL entity
provenance** (#40), **invalid STIX** (#21), **symlink read-out** (#43), and
**resume-with-changed-source** (#45). The personal network parsers are being removed
(#55/D8). **Do not represent ICARUS as public-ready, open-source, or Production/Stable
until the remaining blockers close; the current public visibility is a CI expedient,
not a release.**
