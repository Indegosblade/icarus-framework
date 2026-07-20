# ICARUS Public-Release Audit — Executive Summary

**Audit baseline:** `main` @ `eab33b5` (tree clean). **Current remediated
baseline:** `main` @ `8e553c1`, temporarily public for CI. License
**PolyForm-Noncommercial-1.0.0** (source-available, *not* OSI open source).
**Method:** Phase-0 baseline + 7 parallel specialist passes + adversarial skeptic
re-verification (27 agents, 0 errors). Every accepted finding is reproduced or
proven from code.

**Remediation status (updated):** owner decisions D1–D9 are now **answered** (see
`DECISIONS_REQUIRED.md`). Packaging (#37), diff correctness (#38), schema refusal
(#53), foreign-key enforcement (#54), CI hardening (#52), personal-parser removal
(#55), and the audit documents (#50) are all **merged** to `main`. The integrated
baseline passed all 13 GitHub Actions jobs (run `29666394072`) and an independent
local verification: 242 tests plus ruff, mypy, and bandit. A second independent
implementer (Sol / OpenAI Codex) authored #52/#53/#54; each was re-reviewed and
reproduced before acceptance.

## What ICARUS is

A modular intelligence framework that ingests structured data sources and filesystem
trees (macOS/iOS, Linux, Windows, CloudTrail, and generic JSON/XML/SQLite/archives)
into a normalized SQLite schema (v6, 17 tables, FTS5), with
cross-version diffing, an experimental entity resolver, HYGEIA sanitization, and STIX
2.1 export. ~8k LOC source, 242 passing tests.

## What is genuinely strong

- **Diff opens both databases immutable read-only** (`mode=ro&immutable=1`) — untrusted
  exports can't be mutated by a diff.
- **Hashing refuses to dereference symlinks** (`base._safe_hash`), and the Mach-O magic
  read is symlink-guarded — the containment *pattern* exists in the codebase.
- **SQL built with allowlist `validate_table`/`validate_column` + bound params**, with
  justified `# nosec B608` at the safe sites.
- **Checkpoint/resume, parser-manifest architecture, most-specific-wins detection, and
  the two-graph (ontology + event) model** are thoughtfully designed.
- **Green gates:** 242 tests pass; ruff/mypy/bandit clean; the integrated main branch
  passed its 13-job package, security, dependency, lint, and multi-platform matrix.

The audit's core message stands as a caution: **a green suite is not sufficient.** The
findings it surfaced — packaging, cross-database identity, secret sanitization, entity
provenance, and STIX validity — are now fixed and merged. The remaining beta gates are
behavioral (read-only `query`, safe resume) rather than "the clean run hides a defect."

## Release verdict: **all release-blockers cleared** — owner GO/NO-GO on remaining polish

**Every finding in the release-blocking table below is now merged to `main`**, and all
nine owner decisions (D1–D9) are implemented. The path to a public *beta* is no longer
gated by a blocker; what remains is **should-fix polish**, not release-blocking:
diff-report escaping of hostile values (#35), fresh-vs-migrated FK parity (#51), and the
lower-severity parser-accuracy items (#22–#30). The experimental resolver stays excluded
from the beta promise (D3). ICARUS ships as **Beta** (never Production/Stable). The final
GO is the owner's call on whether the remaining polish is in- or out-of-scope for `4.0.0b1`.

### Release-blocking findings (must fix, accept as residual risk, or drop from scope)

| Issue | Blocker | Status |
|---|---|---|
| **#32** | Wheel/sdist omit all parser manifests/schema/catalogs → installed package broken | **Merged** (#37, `fbd2fca`) |
| **#41** | "Sanitized" output still contains secrets: real HYGEIA never wired, fallback has no credential patterns | **Merged** (#59, `7ecc7a8`; HYGEIA canonical + fail-closed + credential patterns) |
| **#21** | STIX export is not spec-valid (non-UUID ids, dangling refs, invalid diff Notes/timestamps) | **Merged** (#61, `ab26f1d`) |
| **#45** | Resume with a changed `--source` silently yields the *wrong* database | **Merged** (#68, D2; strict resume fingerprint) |
| **#43** | Parsers dereference in-root symlinks → read files outside the source tree | **Merged** (#62, `31338cd`) |
| **#40** | Provenance (`source_version_id`/`observed_time`) NULL on every entity | **Merged** (#60, `d6eb08e`) |
| **#39** | `initialize_database` silently relabels a future schema to v6 | **Merged** (#53, `1abbeb2`) |
| **#33** | Cross-DB diff compared local autoincrement ids → false/hidden "moves" | **Merged** (#38, `39f3b11`; structural **and** observation diff) |

### High / medium (should fix for beta)

Diff completeness + report escaping (#35), build-output reuse/`--fresh` (#36), query
mutability + exit codes (#34), and docs/schema drift (#29). Sanitization coverage/gaps
(#42), hostile-input hardening (#47), FK enforcement (#44), and CI hardening (#49) are
merged. Full ledger in `FINDINGS.md`.

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
Actions are billing-gated on this account). The repository is currently public for
an active remediation/CI window. The fully integrated `8e553c1` baseline passed all
13 jobs in run `29666394072`; the same gates were reproduced locally. Re-privatizing
before the remediation batch finishes will return new runs to the billing no-start
state (*"recent account payments have failed or your spending limit needs to be
increased"*).

## Bottom line

**The release-blocker set is now empty.** **Install is fixed and merged** (#37). **Output-trust** is materially improved: the
false-diff blocker is fully fixed (structural **and** observation diff, #38), a future
schema is now refused (#39/#53), and foreign keys are enforced on every write path
(#44/#54) — all merged and integrated-CI verified. The top confidentiality blocker is
now closed too: **secret survival in "sanitized" output is fixed** (#41 → #59, HYGEIA
canonical + fail-closed + post-sanitize gate), along with **symlink read-out** (#43 →
#62) and **hostile-input hardening** (#47 → #62). Entity provenance is now back-filled
(#40 → #60) and STIX bundles are spec-valid (#21 → #61). The last three blockers are now
closed too: **read-only `query`** (#34/D1 → #66), **safe resume** (#45/D2 → #68), and the
**sanitization residual** (#42/SAN-09 → #67). The personal network parsers have been
removed (#55/D8). **Represent ICARUS as Beta and source-available (never Production/Stable
or OSI open-source); the remaining should-fix items (#35, #51) and optional hardening are
the owner's scope call for `4.0.0b1`. The current public visibility is a CI expedient,
not a release.**
