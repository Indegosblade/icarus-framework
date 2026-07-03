"""ICARUS Resolver Evaluation — a measurement harness for the scored resolver.

This is a **measurement/analysis tool only**. It builds a controlled dataset by
*perturbing* real atoms into new observations whose ground-truth identity is
known by construction (a base atom and its ``move``/``recompile``/``identical``
perturbation are the same entity; a ``new`` atom is nobody), runs the **real**
resolver (:meth:`icarus.core.resolver.EntityResolver.resolve_scored`) completely
unchanged over that dataset, and scores the resolver's output against the known
labels as precision / recall / F1. It **never** alters resolution behavior — it
neither imports nor reimplements any scoring/blocking/clustering logic, it only
reads the bags the resolver produced. Its purpose is to let the resolver's
``threshold`` (and, downstream, its scoring weights) be *measured* against ground
truth instead of asserted.

All randomness goes through a seeded :class:`random.Random` so a given
``(seed, plan)`` is fully reproducible; nothing here uses the global ``random``
state. Stdlib-only.

Pipeline::

    atomize (real source)  ->  perturb_atoms (known labels)
      ->  sweep(thresholds): reset + resolve_scored + evaluate
      ->  recommend_threshold (max F1)

CLI::

    python -m icarus.core.resolver_eval SOURCE_DB [--entity-type binaries]
        [--seed 1] [--thresholds 0.5,0.6,0.7,0.8,0.85,0.9,0.95]
"""

import argparse
import json
import random
import sqlite3
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from icarus.core.atomize import ATOM_PROJECTIONS, atomize_db
from icarus.core.resolver import EntityResolver
from icarus.core.schema import initialize_database, open_db

# ── Mutation vocabulary ────────────────────────────────────────────────────
#
# Consuming mutations each take over one distinct existing base atom; a "new"
# mutation invents a fresh atom tied to no base. A "drop" consumes a base atom
# but emits nothing, leaving that base alone in its cluster.
CONSUMING_MUTATIONS: Tuple[str, ...] = ("identical", "move", "recompile", "rename", "drop")
NONCONSUMING_MUTATIONS: Tuple[str, ...] = ("new",)
ALL_MUTATIONS: Tuple[str, ...] = CONSUMING_MUTATIONS + NONCONSUMING_MUTATIONS
# The mutations that produce a genuine (base, perturbation) true pair we can
# score recall against. new/drop have no such pair.
MATCHING_MUTATIONS: Tuple[str, ...] = ("identical", "move", "recompile", "rename")

# Which property carries each abstract role per entity type. Mutations target
# these roles; a role missing for a type falls back to "name", then source_key.
FIELD_ROLES: Dict[str, Dict[str, str]] = {
    "binaries": {"name": "executable_name", "path": "path", "hash": "sha256"},
    "daemons": {"name": "label", "path": "program"},
    "frameworks": {"name": "name", "path": "path"},
    "kexts": {"name": "name"},
    "files": {"name": "filename", "path": "path", "hash": "sha256"},
}


# ── Data classes ───────────────────────────────────────────────────────────


@dataclass
class GroundTruth:
    """The known-by-construction identity of every atom in the eval dataset.

    ``cluster_of`` maps every atom id (base + perturbed + new) to a ground-truth
    cluster id; a base atom and its non-dropped perturbation share one id, while
    a dropped base and each ``new`` atom is a singleton. ``mutation_of`` maps
    each perturbed/new atom to its mutation label and every base atom to
    ``"base"`` (a ``drop`` emits no atom, so it appears in neither map's values).
    """

    cluster_of: Dict[int, int]
    mutation_of: Dict[int, str]


@dataclass
class Metrics:
    """Pairwise precision / recall / F1 of the resolver against a GroundTruth."""

    precision: float
    recall: float
    f1: float
    tp: int
    fp: int
    fn: int
    per_mutation_recall: Dict[str, float]


# ── Role resolution + per-mutation field edits ─────────────────────────────


def _role_key(entity_type: str, role: str) -> Optional[str]:
    """The property name to mutate for ``role`` in ``entity_type``.

    Falls back to the ``name`` role's property when ``role`` is not defined for
    the type, and to ``None`` (meaning: mutate the source_key instead) when the
    type has no ``name`` role either.
    """
    roles = FIELD_ROLES[entity_type]
    if role in roles:
        return roles[role]
    if "name" in roles:
        return roles["name"]
    return None


def _apply_move(source_key: str, props: dict, entity_type: str) -> Tuple[str, dict]:
    """Change only the ``path`` property (prefix ``/moved``); keep source_key.

    Prefixing preserves the basename, so name+hash still match and the path
    comparator still scores the shared tail — a should-match relocation.
    """
    new_props = dict(props)
    key = _role_key(entity_type, "path")
    if key is None:
        return "/moved" + source_key, new_props
    new_props[key] = "/moved" + str(new_props.get(key, ""))
    return source_key, new_props


def _apply_recompile(
    source_key: str, props: dict, entity_type: str, rng: random.Random
) -> Tuple[str, dict]:
    """Change only the ``hash`` property to a different hex; keep name+path.

    A recompiled binary: identical name and location, new content hash. Should
    still match on name+path (the point of not weighting the hash at 1.0).
    """
    new_props = dict(props)
    key = _role_key(entity_type, "hash")
    if key is None:
        return source_key + "-h", new_props
    new_hex = format(rng.getrandbits(256), "064x")  # nosec B311 - eval data, not security
    while str(new_props.get(key)) == new_hex:  # pragma: no cover - astronomically rare
        new_hex = format(rng.getrandbits(256), "064x")  # nosec B311 - eval data, not security
    new_props[key] = new_hex
    return source_key, new_props


def _apply_rename(source_key: str, props: dict, entity_type: str) -> Tuple[str, dict]:
    """Change the ``name`` property and the source_key (append ``-r``).

    The hard case: the primary identifier changed. Candidacy survives only via
    the residual source_key token overlap; a legitimate miss is a finding.
    """
    new_props = dict(props)
    key = _role_key(entity_type, "name")
    if key is None:
        return source_key + "-r", new_props
    new_props[key] = str(new_props.get(key, "")) + "-r"
    return source_key + "-r", new_props


def _mutate(
    label: str, source_key: str, props: dict, entity_type: str, rng: random.Random
) -> Tuple[str, dict]:
    """Return the ``(source_key, properties)`` for one consuming, atom-emitting
    mutation of a base atom. ``drop`` is handled by the caller (emits nothing)."""
    if label == "identical":
        return source_key, dict(props)
    if label == "move":
        return _apply_move(source_key, props, entity_type)
    if label == "recompile":
        return _apply_recompile(source_key, props, entity_type, rng)
    if label == "rename":
        return _apply_rename(source_key, props, entity_type)
    raise ValueError(f"non-emitting or unknown mutation {label!r}")


def _make_new(i: int, entity_type: str, rng: random.Random) -> Tuple[str, dict]:
    """Invent a fresh atom with all-distinct name/path/hash and unique source_key
    (a single opaque token, so it never buckets or FTS-overlaps anything)."""
    tag = format(rng.getrandbits(64), "016x")  # nosec B311 - eval data, not security
    roles = FIELD_ROLES[entity_type]
    source_key = f"evalnewsrc{i}{tag}"
    props: Dict[str, str] = {}
    if "name" in roles:
        props[roles["name"]] = f"evalnewname{i}{tag}"
    if "path" in roles:
        props[roles["path"]] = f"/eval/new/{i}/{tag}"
    if "hash" in roles:
        props[roles["hash"]] = format(rng.getrandbits(256), "064x")  # nosec B311 - eval data
    return source_key, props


def _insert_atom(
    conn: sqlite3.Connection,
    version_id: int,
    entity_type: str,
    source_key: str,
    props: dict,
    now: str,
) -> int:
    """Insert one atom, returning its id. Disambiguates the source_key on the
    rare chance a perturbation collides with another under this version_id (the
    match is on properties, not the key, so a suffix is harmless)."""
    payload = json.dumps(props, sort_keys=True)
    key = source_key
    for attempt in range(10000):
        try:
            cursor = conn.execute(
                "INSERT INTO atoms (source_version_id, entity_type, source_key, "
                "properties, created_at) VALUES (?, ?, ?, ?, ?)",
                (version_id, entity_type, key, payload, now),
            )
        except sqlite3.IntegrityError:
            key = f"{source_key}-dup{attempt}"
            continue
        atom_id = cursor.lastrowid
        assert atom_id is not None
        return atom_id
    raise RuntimeError(  # pragma: no cover - defensive
        f"could not find a free source_key for {source_key!r}"
    )


# ── Perturbation ───────────────────────────────────────────────────────────


def perturb_atoms(
    db_path: str,
    base_version_id: int,
    new_version_id: int,
    mutations: Dict[str, int],
    entity_type: str,
    seed: int,
) -> GroundTruth:
    """Perturb base atoms into new-version atoms with known ground-truth labels.

    Reads the base atoms of ``entity_type`` under ``base_version_id`` (both
    ``versions`` rows must already exist — the caller creates them), then, using
    a seeded shuffle for reproducibility, assigns each *consuming* mutation
    (identical/move/recompile/rename/drop) to a distinct base atom and inserts
    the resulting perturbed atoms under ``new_version_id``. ``new`` mutations
    invent fresh atoms tied to no base.

    Raises ``ValueError`` if the consuming-mutation count exceeds the number of
    base atoms, if ``entity_type`` is unknown, or on an unknown mutation label.

    Returns the :class:`GroundTruth` covering every atom of the type across both
    versions.
    """
    if entity_type not in FIELD_ROLES:
        raise ValueError(
            f"Unknown entity_type {entity_type!r}; known: {sorted(FIELD_ROLES)}"
        )
    for label in mutations:
        if label not in ALL_MUTATIONS:
            raise ValueError(
                f"Unknown mutation {label!r}; known: {sorted(ALL_MUTATIONS)}"
            )

    rng = random.Random(seed)  # nosec B311 - deterministic eval data, not security

    conn = open_db(db_path)
    try:
        base: Dict[int, Tuple[str, dict]] = {}
        for atom_id, source_key, properties in conn.execute(
            "SELECT id, source_key, properties FROM atoms "
            "WHERE entity_type = ? AND source_version_id = ?",
            (entity_type, base_version_id),
        ).fetchall():
            base[atom_id] = (source_key, json.loads(properties))

        consuming_total = sum(mutations.get(m, 0) for m in CONSUMING_MUTATIONS)
        if consuming_total > len(base):
            raise ValueError(
                f"{consuming_total} consuming mutations "
                f"(identical/move/recompile/rename/drop) requested but only "
                f"{len(base)} base atom(s) of type {entity_type!r} exist under "
                f"version {base_version_id}"
            )

        # Seeded shuffle → each consuming mutation gets a distinct base atom.
        base_ids = sorted(base)
        rng.shuffle(base_ids)  # nosec B311 - deterministic eval data, not security

        assignments: List[str] = []
        for label in CONSUMING_MUTATIONS:
            assignments.extend([label] * mutations.get(label, 0))

        # Every base atom starts as its own cluster / "base" label. Perturbations
        # inherit their base's cluster id; new atoms get their own.
        cluster_of: Dict[int, int] = {atom_id: atom_id for atom_id in base}
        mutation_of: Dict[int, str] = {atom_id: "base" for atom_id in base}

        now = datetime.now(timezone.utc).isoformat()

        for label, base_id in zip(assignments, base_ids):
            source_key, props = base[base_id]
            if label == "drop":
                continue  # emit nothing; base stays alone in its cluster
            new_key, new_props = _mutate(label, source_key, props, entity_type, rng)
            pid = _insert_atom(conn, new_version_id, entity_type, new_key, new_props, now)
            cluster_of[pid] = base_id
            mutation_of[pid] = label

        for i in range(mutations.get("new", 0)):
            new_key, new_props = _make_new(i, entity_type, rng)
            nid = _insert_atom(conn, new_version_id, entity_type, new_key, new_props, now)
            cluster_of[nid] = nid
            mutation_of[nid] = "new"

        conn.commit()
    finally:
        conn.close()

    return GroundTruth(cluster_of=cluster_of, mutation_of=mutation_of)


# ── Scoring the resolver's output ──────────────────────────────────────────


def evaluate(db_path: str, entity_type: str, ground_truth: GroundTruth) -> Metrics:
    """Score the resolver's current bags against ``ground_truth``.

    Reads ``atom_id -> bag_id`` for ``entity_type``; an atom in no bag is treated
    as its own unique singleton (matches nothing). Over every unordered pair of
    atoms in ``ground_truth.cluster_of``, a pair is a true match iff both share a
    cluster and a predicted match iff both share a bag, tallied into tp/fp/fn.
    Precision and recall are 1.0 when their denominator is 0; F1 is 0.0 when
    precision+recall is 0. ``per_mutation_recall`` reports, per matching mutation
    actually present, the fraction of its (base, perturbation) true pairs whose
    two atoms share a bag.
    """
    conn = open_db(db_path)
    try:
        bag_of: Dict[int, int] = {}
        for atom_id, bag_id in conn.execute(
            "SELECT a.id, ba.bag_id FROM atoms a "
            "JOIN bag_atoms ba ON a.id = ba.atom_id "
            "WHERE a.entity_type = ?",
            (entity_type,),
        ).fetchall():
            bag_of[atom_id] = bag_id
    finally:
        conn.close()

    def group(atom_id: int) -> Tuple[str, int]:
        # Bagged atoms share ("bag", id); an unbagged atom is a unique singleton.
        if atom_id in bag_of:
            return ("bag", bag_of[atom_id])
        return ("atom", atom_id)

    atoms = sorted(ground_truth.cluster_of)
    tp = fp = fn = 0
    for i in range(len(atoms)):
        ai = atoms[i]
        for j in range(i + 1, len(atoms)):
            aj = atoms[j]
            true_same = ground_truth.cluster_of[ai] == ground_truth.cluster_of[aj]
            pred_same = group(ai) == group(aj)
            if true_same and pred_same:
                tp += 1
            elif pred_same and not true_same:
                fp += 1
            elif true_same and not pred_same:
                fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    per_mutation_recall: Dict[str, float] = {}
    for mutation in MATCHING_MUTATIONS:
        # cluster_of[pid] is the perturbation's base atom id, so (base, pid) is
        # exactly the true pair this mutation created.
        pairs = [
            (ground_truth.cluster_of[atom_id], atom_id)
            for atom_id, label in ground_truth.mutation_of.items()
            if label == mutation
        ]
        if not pairs:
            continue
        matched = sum(1 for base_id, pid in pairs if group(base_id) == group(pid))
        per_mutation_recall[mutation] = matched / len(pairs)

    return Metrics(
        precision=precision,
        recall=recall,
        f1=f1,
        tp=tp,
        fp=fp,
        fn=fn,
        per_mutation_recall=per_mutation_recall,
    )


def sweep(
    db_path: str,
    entity_type: str,
    ground_truth: GroundTruth,
    thresholds: List[float],
) -> List[Tuple[float, Metrics]]:
    """Resolve + evaluate at each threshold, resetting resolution state between.

    For each ``t``: delete all resolution state in foreign-key-safe order
    (event log and bag_atoms reference bags, so they go before bags;
    match_candidates last), run the real ``resolve_scored`` at ``t`` over the
    now-unresolved atoms, then :func:`evaluate`. Returns ``[(t, metrics), ...]``.
    """
    results: List[Tuple[float, Metrics]] = []
    for t in thresholds:
        resolver = EntityResolver(db_path, experimental=True)
        try:
            resolver.conn.execute("DELETE FROM resolution_event_log")
            resolver.conn.execute("DELETE FROM bag_atoms")
            resolver.conn.execute("DELETE FROM bags")
            resolver.conn.execute("DELETE FROM match_candidates")
            resolver.conn.commit()
            resolver.resolve_scored(entity_type, threshold=t)
        finally:
            resolver.close()
        results.append((t, evaluate(db_path, entity_type, ground_truth)))
    return results


def recommend_threshold(results: List[Tuple[float, Metrics]]) -> float:
    """The threshold with the highest F1; ties broken toward the higher one."""
    if not results:
        raise ValueError("recommend_threshold needs at least one (threshold, metrics)")
    best_t, best_f1 = results[0][0], results[0][1].f1
    for t, metrics in results[1:]:
        if metrics.f1 > best_f1 or (metrics.f1 == best_f1 and t > best_t):
            best_t, best_f1 = t, metrics.f1
    return best_t


# ── CLI ────────────────────────────────────────────────────────────────────


def _insert_version(conn: sqlite3.Connection, run_id: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES (?, 'resolver-eval', 'eval', ?)",
        (run_id, now),
    )
    conn.commit()
    version_id = cursor.lastrowid
    assert version_id is not None
    return version_id


def _default_plan(base_count: int) -> Dict[str, int]:
    """A perturbation plan scaled to ``base_count``: ~30% identical, 20% move,
    20% recompile, 15% rename, 10% new, 5% drop, at least 1 each where the count
    allows. Consuming mutations are clamped to fit the base atoms, dropping the
    least-informative ones (drop, then rename, ...) first."""
    ratios = [
        ("identical", 0.30),
        ("move", 0.20),
        ("recompile", 0.20),
        ("rename", 0.15),
        ("new", 0.10),
        ("drop", 0.05),
    ]
    plan = {name: max(1, round(ratio * base_count)) for name, ratio in ratios}

    reduce_order = ["drop", "rename", "recompile", "move", "identical"]

    def consuming_total() -> int:
        return sum(plan[m] for m in CONSUMING_MUTATIONS)

    while consuming_total() > base_count:
        for m in reduce_order:
            if plan[m] > 0:
                plan[m] -= 1
                break
        else:  # pragma: no cover - unreachable while base_count >= 1
            break

    return {name: count for name, count in plan.items() if count > 0}


def _print_report(
    entity_type: str,
    base_count: int,
    plan: Dict[str, int],
    results: List[Tuple[float, Metrics]],
    best_t: float,
) -> None:
    print()
    print(f"Resolver evaluation  —  entity_type={entity_type!r}, base atoms={base_count}")
    print("Perturbation plan:   " + ", ".join(f"{k}={v}" for k, v in plan.items()))
    print()
    header = (
        f"{'threshold':>10}  {'precision':>9}  {'recall':>7}  "
        f"{'f1':>7}  {'tp':>5}  {'fp':>5}  {'fn':>5}"
    )
    print(header)
    print("-" * len(header))
    for t, metrics in results:
        marker = "  <-- best" if t == best_t else ""
        print(
            f"{t:>10.3f}  {metrics.precision:>9.3f}  {metrics.recall:>7.3f}  "
            f"{metrics.f1:>7.3f}  {metrics.tp:>5}  {metrics.fp:>5}  "
            f"{metrics.fn:>5}{marker}"
        )
    print()

    best_metrics = next(metrics for t, metrics in results if t == best_t)
    print(f"Recommended threshold: {best_t:.3f}  (F1={best_metrics.f1:.3f})")
    if best_metrics.per_mutation_recall:
        print("Per-mutation recall at recommended threshold:")
        for mutation in MATCHING_MUTATIONS:
            if mutation in best_metrics.per_mutation_recall:
                print(f"  {mutation:<11} {best_metrics.per_mutation_recall[mutation]:.3f}")
    else:
        print("Per-mutation recall: (plan had no matchable mutation pairs)")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m icarus.core.resolver_eval",
        description=(
            "Measure the scored resolver's precision/recall by perturbing real "
            "atoms with known ground-truth labels and running the resolver "
            "unchanged. Measurement only — never alters resolution."
        ),
    )
    parser.add_argument("source_db", help="path to an ICARUS SQLite DB to atomize from")
    parser.add_argument(
        "--entity-type",
        default="binaries",
        help="entity type to evaluate (default: binaries)",
    )
    parser.add_argument("--seed", type=int, default=1, help="RNG seed (default: 1)")
    parser.add_argument(
        "--thresholds",
        default="0.5,0.6,0.7,0.8,0.85,0.9,0.95",
        help="comma-separated thresholds to sweep",
    )
    args = parser.parse_args(argv)

    entity_type = args.entity_type
    if entity_type not in ATOM_PROJECTIONS:
        print(
            f"Cannot evaluate entity type {entity_type!r}: no atomizer projection "
            f"exists for it. Supported: {sorted(ATOM_PROJECTIONS)}",
            file=sys.stderr,
        )
        return 2

    try:
        thresholds = [float(x) for x in args.thresholds.split(",") if x.strip()]
    except ValueError:
        print(f"Invalid --thresholds {args.thresholds!r}", file=sys.stderr)
        return 2
    if not thresholds:
        print("No thresholds given via --thresholds", file=sys.stderr)
        return 2

    source_db = args.source_db
    if not Path(source_db).exists():
        print(f"Source DB not found: {source_db}", file=sys.stderr)
        return 2

    tmpdir = tempfile.mkdtemp(prefix="icarus-eval-")
    eval_path = str(Path(tmpdir) / "eval.db")
    initialize_database(Path(eval_path))

    try:
        eval_conn = open_db(eval_path)
        src_conn = open_db(source_db, readonly=True)
        try:
            base_version_id = _insert_version(eval_conn, "eval-base")
            counts = atomize_db(src_conn, eval_conn, base_version_id, [entity_type])
            new_version_id = _insert_version(eval_conn, "eval-new")
        finally:
            src_conn.close()
            eval_conn.close()

        base_count = counts.get(entity_type, 0)
        if base_count == 0:
            print(
                f"No atoms of type {entity_type!r} were produced from {source_db} "
                f"(atomize projected nothing); nothing to evaluate."
            )
            return 0

        plan = _default_plan(base_count)
        ground_truth = perturb_atoms(
            eval_path, base_version_id, new_version_id, plan, entity_type, args.seed
        )
        results = sweep(eval_path, entity_type, ground_truth, thresholds)
        best_t = recommend_threshold(results)
        _print_report(entity_type, base_count, plan, results, best_t)
        return 0
    finally:
        for suffix in ("", "-wal", "-shm"):
            Path(eval_path + suffix).unlink(missing_ok=True)
        try:
            Path(tmpdir).rmdir()
        except OSError:  # pragma: no cover - best-effort cleanup
            pass


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
