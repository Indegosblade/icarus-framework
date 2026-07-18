# ICARUS Release Checklist

Gates to move from **private development → public beta → stable**. Prefer
machine-verifiable evidence. A box is checked only with reproducible proof, not a
green legacy suite.

## Public-beta gates (all required, or explicitly dropped from the promise)

### Install & package integrity
- [ ] `python -m build` produces wheel+sdist containing all 11 parser `*.yaml`,
      `schema/parser_manifest.schema.json`, and `catalog/*.json`. *(#32 — PR #37)*
- [ ] Clean-venv install of the **wheel**: `icarus parser list` shows real tiers;
      `icarus parser validate` passes; `build`/`query` complete. *(#32 — PR #37)*
- [ ] CI has a job that builds+installs the **wheel** (not editable) and smoke-tests it.
      *(#49 — PR #37 adds it)*
- [ ] Distribution channel decided (PyPI needs the HYGEIA git dep resolved). *(decision)*

### Correct & trustworthy output
- [ ] Cross-database diffs use **natural keys**, never local row ids
      (`structural_diff` **and** `observation_diff`). *(#33 — PR #38 partial)*
- [ ] Provenance populated: every entity row has `source_version_id` + `observed_time`.
      *(#40)*
- [ ] `initialize_database` **refuses** a forward/newer schema version. *(#39)*
- [ ] Fresh-vs-migrated parity verified at `sqlite_master` (tables/indexes/triggers/
      views). *(#29/DM-06)*
- [ ] Resume with a changed `--source`/`--parser` re-runs or errors — never silently
      wrong. *(#45)*; existing-output semantics defined + atomic write. *(#36)*
- [ ] FK enforcement ON for every write path; verify-phase `foreign_key_check` gate.
      *(#44)*

### Hostile-input safety
- [ ] In-root symlinks are never read through to external targets, across all reader
      families. *(#43)*
- [ ] FIFO/special files, non-UTF-8 names, deeply-nested JSON, and compression bombs are
      skipped-with-warning, not hang/abort/unbounded. *(#47, #25)*
- [ ] Diff report escapes hostile values. *(#35)*

### Sanitization (confidentiality)
- [ ] The sanitizer actually removes credentials/secrets (real HYGEIA wired **or**
      hardened fallback). *(#41)*
- [ ] Mandatory **post-sanitize verification gate** fails the build on any residual.
      *(#42)*
- [ ] The verifier never emits raw secret values; `metadata` and `*_fts` are covered.
      *(#42)*

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
- [ ] CI actions SHA-pinned or Dependabot-managed; dependency scan runs. *(#49)*

### Operational
- [ ] GitHub Actions billing restored so CI can actually run (account setting).

## Stable gates (in addition)

- [ ] Soak time with real external users and cross-release upgrade evidence.
- [ ] Experimental resolver API graduated or removed; resolution evaluated on
      collision-heavy/multi-version corpora (purity + recall).
- [ ] All blocker/high issues closed (not merely worked around).
- [ ] Reproducible builds (pin HYGEIA by commit, not a movable tag).

## How to verify (evidence, not vibes)

Each box maps to an issue with a reproduction and acceptance criteria. "Done" =
that reproduction now yields the acceptance outcome **on the built artifact**, plus a
regression test, plus (once billing is restored) a green CI wheel job.
