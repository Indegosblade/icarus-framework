# ICARUS — Owner Decisions (now answered)

These nine decisions could not be resolved mechanically; each changed public
behavior, policy, or positioning. **The owner has now answered all nine.** They are
recorded here as the ratified basis for implementation. Independent code fixes
proceed under these rulings; where a fix is still pending, the governing decision is
noted on the corresponding issue.

## D1 — Default query mutability *(#34)* — **DECIDED**
`icarus query` becomes **read-only by default**. Mutation moves behind an
unmistakable explicit interface (`icarus exec` and/or `query --write`). Tests must
prove `INSERT`/`UPDATE`/`DELETE`/`DROP`, ATTACH-based writes, and writable pragmas
cannot mutate through the default query path. *(fix pending)*

## D2 — Existing output, `--fresh`, and resume *(#36, #45)* — **DECIDED**
Refuse an existing output database by default. `--fresh` builds into a sibling temp
DB, runs all verification gates there, and **atomically** replaces the destination
only on success (previous destination untouched on failure). Resume is allowed
**only** when source, parser, parser version/implementation, and normalized effective
config exactly match the recorded fingerprint; any mismatch fails loudly. *(fix pending)*

## D3 — Experimental resolver *(#46)* — **DECIDED**
The resolver is **excluded** from the public-beta compatibility/correctness promise.
It stays available behind its existing experimental acknowledgement gate while its
invariants are repaired. Docs, metadata, help output, and release notes must not imply
resolution is production-ready.

## D4 — HYGEIA & secret retention *(#41, #42, #31)* — **DECIDED**
HYGEIA is the **canonical** sanitizer. Never silently fall back to a weaker built-in;
**fail closed** if HYGEIA cannot load. Detectors store type + location + a safe,
non-reversible fingerprint — **never the raw secret**, and never emit raw matches in
logs, exceptions, reports, tests, or issues. Add post-sanitization verification that
tests real credential classes, not just the old PII patterns. Pin HYGEIA to the
verified immutable commit (`518e55b…`, to be independently confirmed). *(fix pending — top blocker)*

## D5 — License & maturity *(#48)* — **DECIDED**
ICARUS is **Beta** and **source-available/noncommercial** under PolyForm-Noncommercial
— **not** OSI open source. Correct the README, package metadata, Trove classifiers
(drop `Production/Stable` → `Beta`), audit docs, and release language accordingly. *(fix pending)*

## D6 — Distribution *(#32, #49)* — **DECIDED**
First beta ships via **GitHub release wheels**, with HYGEIA pinned to the verified
immutable commit. **No PyPI** until HYGEIA's distribution/dependency situation is
resolved (PyPI rejects the direct-URL dependency).

## D7 — Version history *(#29)* — **DECIDED**
Do **not** delete historical tags. Document the historical tag/release/`pyproject`
confusion and move forward **monotonically to `4.0.0b1`**. Do not create the tag or
publish the release until the beta-blocker checklist is actually satisfied. *(fix pending)*

## D8 — Personal / network parsers *(#31)* — **DECIDED & IMPLEMENTED**
**Delete** `network/privacy_stack` and `network/deploy_scripts` and their entire
tracked surface from the public distribution (not moved into another tracked "private"
dir). Implemented in **PR #55** (`chore/remove-personal-network-parsers`): modules,
manifests, catalog entries, fixtures, golden files, tests, and doc references removed;
parser count now 9; wheel ships 9 manifests; suite green locally. History remediation
(scrubbing prior commits) remains a separate explicit decision, not taken here.

## D9 — Entry-point plugin trust *(threat model AC8)* — **DECIDED**
Built-in parsers keep loading normally. **Third-party `icarus.parsers` entry points are
disabled by default** and require explicit opt-in via a clearly named CLI/config
setting. Document that enabling plugins executes installed third-party code; test that
importing ICARUS does not auto-execute an untrusted entry point. *(fix pending)*
