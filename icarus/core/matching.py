"""ICARUS Matching — the block + score half of the scored entity resolver.

The scored resolver is a four-stage pipeline: **block -> score -> cluster ->
merge**. This module owns the first two stages over the immutable ``atoms``
table (raw per-source observations projected by :mod:`icarus.core.atomize`):

* **block** (:func:`candidate_pairs`) — cheaply generate a small set of atom
  pairs that are *plausibly* the same entity, so scoring never has to compare
  every atom against every other. Two mechanisms are unioned: normalized
  blocking-key buckets, and (optionally) an FTS5 token search over each atom's
  ``source_key``. This is the real successor to the deleted exact-key blocking
  index class; it deliberately does not reuse that old name.
* **score** (:func:`score_pair`) — turn a candidate pair into a similarity in
  ``[0, 1]`` via a per-entity-type set of weighted :class:`FieldRule` field
  comparators, returning the aggregate score plus the per-field feature values
  (useful for explainability and thresholding downstream).

Everything here is stdlib-only (``difflib``, ``re``, ``json``, ``sqlite3``,
``dataclasses``, ``typing``) and side-effect-free with respect to the database
(reads only). It has no consumer yet: the upcoming ``resolve_scored`` (the next
increment) is what will call :func:`candidate_pairs` then :func:`score_pair`,
cluster the high-scoring pairs, and merge them into bags.
"""

import difflib
import json
import re
import sqlite3
import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set, Tuple

# ── Normalization + tokenization ──────────────────────────────────────────


def normalize(s: str) -> str:
    """Lowercase and strip surrounding whitespace."""
    return s.lower().strip()


def tokens(s: str) -> Set[str]:
    """Split into a set of lowercase alphanumeric tokens (blanks dropped)."""
    return {t for t in re.split(r"[^a-z0-9]+", s.lower()) if t}


# ── Field comparators ─────────────────────────────────────────────────────
#
# Each comparator maps two optional strings to a similarity in [0, 1] and
# returns 0.0 if either argument is None (a missing field can never be a match).


def cmp_exact(a: Optional[str], b: Optional[str]) -> float:
    """1.0 iff the raw strings are byte-for-byte equal, else 0.0."""
    if a is None or b is None:
        return 0.0
    return 1.0 if a == b else 0.0


def cmp_norm_equal(a: Optional[str], b: Optional[str]) -> float:
    """1.0 iff the strings are equal after :func:`normalize` (case/whitespace)."""
    if a is None or b is None:
        return 0.0
    return 1.0 if normalize(a) == normalize(b) else 0.0


def cmp_ratio(a: Optional[str], b: Optional[str]) -> float:
    """difflib similarity ratio of the two normalized strings."""
    if a is None or b is None:
        return 0.0
    return difflib.SequenceMatcher(None, normalize(a), normalize(b)).ratio()


def cmp_token_jaccard(a: Optional[str], b: Optional[str]) -> float:
    """Jaccard overlap of the two token sets; 0.0 if their union is empty."""
    if a is None or b is None:
        return 0.0
    ta, tb = tokens(a), tokens(b)
    union = ta | tb
    if not union:
        return 0.0
    return len(ta & tb) / len(union)


def cmp_path_suffix(a: Optional[str], b: Optional[str]) -> float:
    """Path-tail similarity.

    Split both on ``/`` and ``\\`` into non-empty components. If the basenames
    (final components) are case-insensitively equal, return 1.0. Otherwise
    return ``(# equal trailing components) / max(len_a, len_b)`` comparing from
    the end — which is 0.0 when the basenames differ, since the basename is the
    trailing-most component.
    """
    if a is None or b is None:
        return 0.0
    ca = [c for c in re.split(r"[/\\]", a) if c]
    cb = [c for c in re.split(r"[/\\]", b) if c]
    if not ca or not cb:
        return 0.0
    if ca[-1].lower() == cb[-1].lower():
        return 1.0
    equal = 0
    for x, y in zip(reversed(ca), reversed(cb)):
        if x.lower() == y.lower():
            equal += 1
        else:
            break
    denom = max(len(ca), len(cb))
    return equal / denom if denom else 0.0


# ── Weighted scoring ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class FieldRule:
    """One field's contribution to a pair score: which field, how to compare it,
    and how much its comparison is worth relative to the others."""

    field: str
    comparator: Callable[[Optional[str], Optional[str]], float]
    weight: float


SCORING_SPECS: Dict[str, List[FieldRule]] = {
    "binaries": [
        FieldRule("sha256", cmp_exact, 3.0),
        FieldRule("executable_name", cmp_norm_equal, 2.0),
        FieldRule("path", cmp_path_suffix, 1.0),
        FieldRule("arch", cmp_exact, 0.5),
    ],
    "daemons": [
        FieldRule("label", cmp_norm_equal, 3.0),
        FieldRule("program", cmp_path_suffix, 2.0),
        FieldRule("plist_path", cmp_path_suffix, 1.0),
    ],
}


def score_pair(
    entity_type: str, props_a: dict, props_b: dict
) -> Tuple[float, Dict[str, float]]:
    """Weighted similarity of two atoms' property dicts for ``entity_type``.

    For every :class:`FieldRule` whose ``field`` is present and non-None in
    *both* property dicts, the field value (coerced to ``str``) is run through
    the rule's comparator; the result is recorded in ``features`` and folded
    into a weighted average (``sum(weight * sub) / sum(weight)`` over shared
    fields only). Returns ``(score, features)``, or ``(0.0, {})`` when the two
    atoms share no scorable field. Raises ``KeyError`` for an unknown
    ``entity_type``.
    """
    if entity_type not in SCORING_SPECS:
        raise KeyError(
            f"No scoring spec for entity_type {entity_type!r}; "
            f"known types: {sorted(SCORING_SPECS)}"
        )

    numerator = 0.0
    denominator = 0.0
    features: Dict[str, float] = {}
    for rule in SCORING_SPECS[entity_type]:
        va = props_a.get(rule.field)
        vb = props_b.get(rule.field)
        if va is None or vb is None:
            continue
        sub = rule.comparator(str(va), str(vb))
        features[rule.field] = sub
        numerator += rule.weight * sub
        denominator += rule.weight

    if denominator > 0:
        return numerator / denominator, features
    return 0.0, {}


# ── Blocking (candidate generation) ───────────────────────────────────────

DEFAULT_BLOCKING_KEYS: Dict[str, List[str]] = {
    "binaries": ["executable_name"],
    "daemons": ["label"],
}


def candidate_pairs(
    conn: sqlite3.Connection,
    entity_type: str,
    blocking_keys: Optional[List[str]] = None,
    *,
    fts: bool = True,
    max_bucket: int = 200,
) -> Set[Tuple[int, int]]:
    """Generate plausibly-matching atom pairs for ``entity_type``.

    Two mechanisms are unioned:

    * **Buckets** — each atom is placed in a bucket keyed by joining
      ``normalize(str(props.get(k, "")))`` for each blocking key ``k`` (default:
      :data:`DEFAULT_BLOCKING_KEYS`) with ``"|"``. Atoms whose bucket key is
      all-blank are skipped. Every unordered pair within a bucket of size
      ``2..max_bucket`` becomes a candidate; a bucket larger than ``max_bucket``
      is skipped entirely with a ``WARNING`` on stderr (no silent cap).
    * **FTS** (only when ``fts=True``) — for each atom a safe FTS5 query is built
      from the tokens of its ``source_key`` (each token double-quoted, joined by
      ``" OR "``, bound as a parameter — never string-formatted into SQL). Rowids
      returned by ``atoms_fts`` that belong to this entity type become
      candidates, capped to ``max_bucket`` per atom. If ``atoms_fts`` is missing
      this degrades to buckets-only rather than raising.

    Returns a set of ``(min, max)`` atom-id pairs, excluding self-pairs.
    """
    block_keys = blocking_keys or DEFAULT_BLOCKING_KEYS[entity_type]

    rows = conn.execute(
        "SELECT id, source_key, properties FROM atoms WHERE entity_type = ?",
        (entity_type,),
    ).fetchall()

    id_set: Set[int] = set()
    source_keys: Dict[int, str] = {}
    parsed: Dict[int, dict] = {}
    for atom_id, source_key, properties in rows:
        id_set.add(atom_id)
        source_keys[atom_id] = source_key
        parsed[atom_id] = json.loads(properties)

    pairs: Set[Tuple[int, int]] = set()

    # ── Mechanism A — normalized blocking-key buckets ──────────────────────
    buckets: Dict[str, List[int]] = {}
    for atom_id in (r[0] for r in rows):
        props = parsed[atom_id]
        key_parts = [normalize(str(props.get(k, ""))) for k in block_keys]
        if not any(key_parts):  # all blocking values blank → not blockable
            continue
        bucket_key = "|".join(key_parts)
        buckets.setdefault(bucket_key, []).append(atom_id)

    for bucket_key, ids in buckets.items():
        size = len(ids)
        if size < 2:
            continue
        if size > max_bucket:
            print(
                f"WARNING: candidate_pairs: bucket {bucket_key!r} "
                f"({entity_type}) has {size} atoms > max_bucket={max_bucket}; "
                f"skipping",
                file=sys.stderr,
            )
            continue
        for i in range(size):
            for j in range(i + 1, size):
                a, b = ids[i], ids[j]
                pairs.add((min(a, b), max(a, b)))

    # ── Mechanism B — FTS5 token search over source_key ────────────────────
    if fts:
        try:
            for atom_id in (r[0] for r in rows):
                toks = tokens(source_keys[atom_id])
                if not toks:
                    continue
                match_query = " OR ".join(f'"{t}"' for t in sorted(toks))
                hits = conn.execute(
                    "SELECT rowid FROM atoms_fts WHERE atoms_fts MATCH ?",
                    (match_query,),
                ).fetchall()
                kept = 0
                for (hit_id,) in hits:
                    if hit_id == atom_id or hit_id not in id_set:
                        continue
                    pairs.add((min(atom_id, hit_id), max(atom_id, hit_id)))
                    kept += 1
                    if kept >= max_bucket:
                        break
        except sqlite3.OperationalError:
            # No atoms_fts (or it is otherwise unqueryable) → buckets-only.
            pass

    return pairs
