# Resolver Threshold Calibration

How the scored entity resolver's `threshold` is measured rather than guessed, what the measurements say, and why the default is what it is.

## The problem

`EntityResolver.resolve_scored(..., threshold=0.85)` merges two atoms when their similarity score clears `threshold`. That `0.85` — and the per-field weights in `matching.SCORING_SPECS` — were hand-set priors. Hand-set priors are fine as a starting point but indefensible without evidence: is `0.85` too strict (missing real matches) or too loose (merging distinct entities)? You cannot answer that without precision/recall on known-answer data.

## The measuring stick — `icarus/core/resolver_eval.py`

A **measurement-only** harness. It runs the real `resolve_scored` unchanged and scores its output; it never imports or reimplements any scoring/blocking/clustering logic.

1. **Perturb.** Take real atoms from a built database and clone them into a second "source" with *labeled* mutations whose ground-truth identity is known by construction:
   - `identical` / `move` (path only) / `recompile` (content hash only) / `rename` (name+key) — each is the **same** entity as its base (a true match to recover).
   - `new` — an all-distinct atom that is nobody.
   - `confusable` (**weak** hard negative) — copies a base's *name* only, at a different location: a different entity that shares just a name (two unrelated files both called `config`).
   - `confusable_strong` (**strong** hard negative) — copies a base's name **and** path, differing only in content hash: a different entity that is **feature-identical to a `recompile`**.
2. **Sweep.** For each threshold, reset resolution state, run `resolve_scored`, and score the bags: pairwise **precision / recall / F1**, per-mutation recall, and a count of hard negatives wrongly merged.
3. **Recommend.** `recommend_threshold` maximizes F1; `calibrate_threshold(results, min_precision=0.95)` returns the **lowest** threshold that still holds precision ≥ the floor — the precision-first operating point.

Run it on any built database:

```bash
python -m icarus.core.resolver_eval your.db --entity-type binaries
```

## Why the hard negatives matter

An earlier version of the harness had only the all-distinct `new` negative. An all-distinct atom can never be wrongly merged, so **precision read a trivial 1.0 at every threshold** — the precision axis was never under test, and a naive "maximize F1" recommender would happily descend to a reckless threshold. The `confusable` negatives fix that: they are genuine candidates (they share a blocking bucket) that *must not* merge, so below their score they produce real false positives.

The **`confusable_strong` negative encodes the core tension**: a different binary at the same name and path, differing only in content, is **indistinguishable on features from a recompiled version of the same binary**. They score identically. Therefore you cannot lower the threshold to recover `recompile` recall without simultaneously admitting these false positives. The threshold is the dial on that trade-off; there is no setting that gets both.

## Measured findings (27 real Linux binaries, synthetic perturbations)

| threshold | precision | recall | F1 | notes |
|----------:|----------:|-------:|----:|-------|
| 0.50 | 0.84 | 0.96 | 0.89 | max-F1, but strong confusables merged (precision damage) |
| **0.60** | **1.00** | **0.73** | 0.84 | **calibrated** — precision-first floor; recovers `rename` recall |
| 0.85 (default) | 1.00 | 0.59 | 0.74 | precision-safe but conservative; misses `recompile` + `rename` |

- **Precision is intact (1.0) at the default 0.85** against every hard negative tested — the default is validated as *precision-safe*.
- It is also *conservative*: on this dataset ~0.60 keeps precision 1.0 while recovering `rename` recall (0.73 vs 0.59). Going below ~0.55 admits the strong confusables (precision falls to ~0.84).
- Per-mutation recall at a moderate threshold: `identical`/`move` 1.0, `rename` ~0.75, `recompile` recoverable only below ~0.54 (where precision starts to pay).

## Decision

**Keep `threshold=0.85` as the default.** It is measured-precision-safe and robust — it sits well above any realistic confusable score, so it does not depend on the particular scores of one dataset's negatives. Lowering the global default to the calibrated `~0.60` would overfit to a single dataset's synthetic perturbations; the calibrated value depends on how the hard negatives happen to score, which varies by corpus.

The heuristic weights are likewise **kept** — the measurements show them producing precision 1.0 with sensible recall degradation exactly where the features genuinely stop distinguishing entities (recompiles). That "we kept the heuristics" is itself a measured, defensible result, not an untested guess. Learned weights (Fellegi-Sunter m/u or logistic regression over the per-field features already persisted in `match_candidates.features`) remain a data-driven option **if** a future corpus's measurements show the heuristics leaving accuracy on the table.

**Operators who need more recall** should not blindly lower the default — they should run `resolver_eval` on their own corpus and pick the `calibrate_threshold` value for it, then pass `--threshold` (CLI) or `threshold=` (`resolve_scored`). The precision floor is a policy choice; make it with numbers.

## Limitations

- Measured on *synthetic* perturbations of one real dataset. The mutation model is deliberate and labeled, but it is not a substitute for genuinely different real dumps — that is the next validation (two adjacent OS versions / two host scans), tracked separately.
- The `confusable_strong` negative is the hardest the harness plants; a real corpus may contain negatives that score even higher (more shared fields), which would raise the precision-safe floor. Calibrate per corpus.
