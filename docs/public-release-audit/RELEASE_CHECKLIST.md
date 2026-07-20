# ICARUS Release Checklist

Gates to move from **private development → public beta → stable**. Prefer
machine-verifiable evidence. A box is checked only with reproducible proof, not a
green legacy suite.

## Public-beta gates (all required, or explicitly dropped from the promise)

### Install & package integrity
- [x] `python -m build` produces wheel+sdist containing every parser `*.yaml`,
      `schema/parser_manifest.schema.json`, and `catalog/*.json`. *(#32 — **#37 merged**;
      now 9 manifests after #55/D8)*
- [x] Clean-venv install of the **wheel**: `icarus parser list` shows real tiers;
      `icarus parser validate` passes; `build`/`query` complete. *(#32 — **#37 merged**)*
- [x] CI has a job that builds+installs the **wheel** (not editable) and smoke-tests it.
      *(#49 — **#37/#52 merged**)*
- [x] Distribution channel decided: GitHub-release wheels for the first beta, HYGEIA
      pinned by commit, no PyPI until the HYGEIA git dep is resolved. *(D6)*

### Correct & trustworthy output
- [x] Cross-database diffs use **natural keys**, never local row ids — both
      `structural_diff` **and** `observation_diff`, plus a stable entitlement-owner
      identity. *(#33 — **#38 merged**, integrated CI green)*
- [ ] Provenance populated: every entity row has `source_version_id` + `observed_time`.
      *(#40 — open)*
- [x] `initialize_database` **refuses** a forward/newer/malformed/incomplete schema and
      no longer restamps. *(#39 — **#53 merged**, integrated CI green)*
- [ ] Fresh-vs-migrated parity verified at `sqlite_master` (tables/indexes/triggers/
      views). *(#29/DM-06 — open)*
- [ ] Resume only on exact fingerprint match, else fail loud; existing-output refused;
      atomic `--fresh` (temp + replace). *(D2 decided; #45/#36 — fix pending)*
- [x] FK enforcement ON for every write path; verify-phase `foreign_key_check` gate.
      *(#44 — **#54 merged**, integrated CI green)*

### Hostile-input safety
- [x] In-root symlinks are never read through to external targets, across all reader
      families. *(#43 — **#62 merged**)*
- [x] FIFO/special files, non-UTF-8 names, deeply-nested JSON, and compression bombs are
      skipped-with-warning, not hang/abort/unbounded. *(#47 — **#62 merged**; residual: #25)*
- [ ] Diff report escapes hostile values. *(#35)*

### Sanitization (confidentiality)
- [x] The sanitizer actually removes credentials/secrets (HYGEIA canonical + fail-closed
      + credential patterns). *(#41 — **#59 merged**)*
- [x] Mandatory **post-sanitize verification gate** fails the build on any residual.
      *(#42 — **#59 merged**)*
- [x] The verifier never emits raw secret values; `metadata` and `*_fts` are covered.
      *(#42 — **#59 merged**; HMAC-SHA256 fingerprints only)*

### Interop
- [ ] Strict `stix2.parse` accepts entity **and** diff bundles; no dangling refs / dup
      ids; valid UTC timestamps. *(#21)*

### Experimental surface
- [ ] Resolver invariants enforced **or** the resolver is clearly excluded from the beta
      promise (documented). *(#46)*

### Honesty & governance
- [ ] README measurable claims (test count, modules, CI matrix, schema version) match
      reality; `schema.sql`/ARCHITECTURE regenerated to v6. *(#29)*
- [ ] Trove classifier reflects maturity (Beta); license positioned as source-available
      (not OSI). *(#48)*
- [ ] `SECURITY.md` with an approved disclosure channel; CONTRIBUTING/CHANGELOG present.
      *(#48)*
- [x] CI actions SHA-pinned + Dependabot-managed; dependency scan (`pip-audit`) runs;
      read-only token; full failure surface. *(#49 — **#52 merged**, integrated CI green)*

### Operational
- [x] Repository **public** for the active remediation/CI window. Integrated `main`
      passed all 13 jobs in run `29666394072`; private-repo Actions remain billing-gated.
      *(visibility/billing setting — restore privacy after the batch)*
- [x] Personal network parsers removed from the distribution. *(#31/D8 — **#55 merged**)*

## Stable gates (in addition)

- [ ] Soak time with real external users and cross-release upgrade evidence.
- [ ] Experimental resolver API graduated or removed; resolution evaluated on
      collision-heavy/multi-version corpora (purity + recall).
- [ ] All blocker/high issues closed (not merely worked around).
- [ ] Reproducible builds (pin HYGEIA by commit, not a movable tag).

## How to verify (evidence, not vibes)

Each box maps to an issue with a reproduction and acceptance criteria. "Done" =
that reproduction now yields the acceptance outcome **on the built artifact**, plus a
regression test, plus a green CI matrix. Checked remediation boxes above are merged to
`main` and passed the fully integrated public run `29666394072`. A green matrix is
necessary, not sufficient — negative paths and semantics were reviewed by hand.
