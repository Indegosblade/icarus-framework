# ICARUS — Decisions Required from the Owner

These cannot be resolved mechanically; each changes public behavior, policy, or
positioning. Independent code fixes proceed without them; these gate the *design*.

## D1 — Default query mutability *(#34)*
`icarus query` opens the DB read-write and runs arbitrary `--sql`, so a "query" can
`DELETE`/`DROP`. **Decision:** make `query` read-only by default and move mutation
behind an explicit `--write`/`exec` command? (Recommended: yes.)

## D2 — Existing-output & `--fresh` semantics *(#36, #45)*
Building to an existing `--output` currently unions old+new data; `--fresh` only
discards checkpoints; there is no atomic write. **Decision:** refuse non-empty output
without `--force`? make `--fresh` recreate the DB? build to temp + `os.replace`?
(Recommended: temp+replace, and `--fresh` means fresh.)

## D3 — Experimental resolver: fix or exclude *(#46)*
The resolver has unsound invariants (append-only log rewritten, non-atomic mutations,
weak-evidence merges) but is off by default. **Decision:** fix the set before
advertising resolution, or explicitly exclude the resolver from the public-beta
promise? Also ratify resolver identity policy: clustering linkage (single vs complete),
threshold semantics, and whether same-source atoms may merge.

## D4 — Secret-retention / data-minimization policy *(#41, #42, #31)*
**Decision:** adopt the rule that secret detectors store *type + location + safe
fingerprint*, never the raw value; and that the pipeline must fail closed
(post-sanitize gate) rather than report success. (Recommended: yes — this is the
blocker's real fix.) Also: wire the real HYGEIA API vs. harden the built-in fallback?

## D5 — License positioning & maturity classifier *(#48)*
License is PolyForm-Noncommercial (source-available, **not** OSI). **Decision:** state
this explicitly; never describe ICARUS as "open source." Drop the Trove classifier from
`Production/Stable` to `Beta` until blockers close and the resolver graduates?

## D6 — Distribution channel *(#32, #49)*
The HYGEIA **git-URL** dependency blocks a PyPI upload (PyPI rejects direct-URL deps)
and uses a movable tag. **Decision:** publish HYGEIA to PyPI (or vendor it / pin by
commit) if PyPI distribution of ICARUS is intended; otherwise document "install from
git" as the supported channel.

## D7 — Version numbering *(#29 / DOC-REL-01)*
`pyproject` = 1.4.0; git tags reach v3.0.0 then fall back to v1.1.1; Releases stop at
v1.1.0. **Decision:** pick the real next version, delete/deprecate the abandoned
v2.0.0/v3.0.0 tags, and align tags ↔ releases ↔ `pyproject`.

## D8 — Personal / network parsers *(#31)*
The maintainer already flagged `network/privacy_stack` and `network/deploy_scripts` as
targeting personal infrastructure and is leaning toward deletion. **Decision:** delete
them from the public release (removing the credential-storage surface and the personal
IPs) or harden them? (Deleting also shrinks the sanitization blast radius.)

## D9 — Entry-point plugin trust *(threat model AC8)*
Any installed distribution advertising the `icarus.parsers` group is imported at
`import icarus.parsers`. **Decision:** document this as expected Python behavior, or
gate third-party plugin loading behind an opt-in flag?
