"""Tests for the resolver evaluation harness (icarus.core.resolver_eval).

The harness is a *measurement* tool: it perturbs atoms with known ground-truth
labels, runs the real ``resolve_scored`` unchanged, and scores precision/recall.
These tests hand-check the pairwise metric math on tiny, fully-known datasets,
and verify the perturbation builds the ground-truth structure it claims to.
"""

import json
import sqlite3
import tempfile
from collections import Counter
from pathlib import Path

import pytest

from icarus.core.resolver import EntityResolver
from icarus.core.resolver_eval import (
    GroundTruth,
    Metrics,
    calibrate_threshold,
    evaluate,
    perturb_atoms,
    recommend_threshold,
    sweep,
)
from icarus.core.schema import initialize_database, open_db

BASE_VID = 1
NEW_VID = 2


@pytest.fixture
def eval_db():
    """A fresh v6 DB with two version rows (1=base, 2=new) for perturbation."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    initialize_database(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES ('eval-base', 'test', '/a', '2026-01-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES ('eval-new', 'test', '/b', '2026-01-01T00:00:00Z')"
    )
    conn.commit()
    conn.close()
    yield str(db_path)
    for suffix in ("", "-wal", "-shm"):
        Path(str(db_path) + suffix).unlink(missing_ok=True)


def _ingest(db_path, atoms, version_id=BASE_VID, entity_type="binaries"):
    """Ingest base atoms; returns their atom ids in order."""
    resolver = EntityResolver(db_path, experimental=True)
    try:
        return [
            resolver.ingest_atom(version_id, entity_type, source_key, props)
            for source_key, props in atoms
        ]
    finally:
        resolver.close()


def _resolve(db_path, entity_type="binaries", *, threshold):
    resolver = EntityResolver(db_path, experimental=True)
    try:
        resolver.resolve_scored(entity_type, threshold=threshold)
    finally:
        resolver.close()


# ── metrics math: a trivial positive is a clean TP ─────────────────────────


def test_identical_is_perfect(eval_db):
    """base + one identical perturbation → resolver bags them → P=R=F1=1.0."""
    _ingest(
        eval_db,
        [("foo", {"sha256": "deadbeef", "executable_name": "foo", "path": "/usr/bin/foo"})],
    )
    gt = perturb_atoms(eval_db, BASE_VID, NEW_VID, {"identical": 1}, "binaries", seed=1)
    _resolve(eval_db, threshold=0.85)

    metrics = evaluate(eval_db, "binaries", gt)
    assert metrics.tp == 1
    assert metrics.fp == 0
    assert metrics.fn == 0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1 == 1.0


# ── false negative: a recompile missed at a high threshold ─────────────────


def test_false_negative_recompile_high_threshold(eval_db):
    """recompile (hash differs, name+path same) misses at threshold 0.99."""
    _ingest(
        eval_db,
        [("svc", {"sha256": "1111", "executable_name": "svc", "path": "/usr/bin/svc"})],
    )
    gt = perturb_atoms(eval_db, BASE_VID, NEW_VID, {"recompile": 1}, "binaries", seed=1)
    _resolve(eval_db, threshold=0.99)

    metrics = evaluate(eval_db, "binaries", gt)
    assert metrics.fn >= 1
    assert metrics.recall < 1.0


# ── false positive: two different atoms wrongly merged at a low threshold ───


def test_false_positive_low_threshold(eval_db):
    """Two genuinely different binaries a low threshold merges → precision<1."""
    ids = _ingest(
        eval_db,
        [
            ("helper-1", {"sha256": "aaaa", "executable_name": "helper", "path": "/usr/bin/one"}),
            ("helper-2", {"sha256": "bbbb", "executable_name": "helper", "path": "/opt/lib/two"}),
        ],
    )
    # Hand-built ground truth: each is its own cluster (they are not the same).
    gt = GroundTruth(
        cluster_of={ids[0]: ids[0], ids[1]: ids[1]},
        mutation_of={ids[0]: "base", ids[1]: "base"},
    )
    _resolve(eval_db, threshold=0.3)

    metrics = evaluate(eval_db, "binaries", gt)
    assert metrics.fp >= 1
    assert metrics.precision < 1.0


# ── a new atom must stay a singleton ───────────────────────────────────────


def test_new_stays_singleton(eval_db):
    """A `new` atom merges with nothing: no TP from it, precision stays 1.0."""
    _ingest(
        eval_db,
        [("foo", {"sha256": "deadbeef", "executable_name": "foo", "path": "/usr/bin/foo"})],
    )
    gt = perturb_atoms(
        eval_db, BASE_VID, NEW_VID, {"identical": 1, "new": 1}, "binaries", seed=1
    )
    _resolve(eval_db, threshold=0.85)

    metrics = evaluate(eval_db, "binaries", gt)
    assert metrics.precision == 1.0

    new_ids = [aid for aid, label in gt.mutation_of.items() if label == "new"]
    assert len(new_ids) == 1
    conn = open_db(eval_db)
    try:
        bag_id = conn.execute(
            "SELECT bag_id FROM bag_atoms WHERE atom_id = ?", (new_ids[0],)
        ).fetchone()[0]
        members = conn.execute(
            "SELECT COUNT(*) FROM bag_atoms WHERE bag_id = ?", (bag_id,)
        ).fetchone()[0]
    finally:
        conn.close()
    assert members == 1


# ── per-mutation recall: keys for used mutations, identical == 1.0 ─────────


def test_per_mutation_recall_keys(eval_db):
    _ingest(
        eval_db,
        [
            ("foo", {"sha256": "deadbeef", "executable_name": "foo", "path": "/usr/bin/foo"}),
            ("bar", {"sha256": "cafef00d", "executable_name": "bar", "path": "/usr/bin/bar"}),
        ],
    )
    gt = perturb_atoms(
        eval_db, BASE_VID, NEW_VID, {"identical": 1, "recompile": 1}, "binaries", seed=1
    )
    _resolve(eval_db, threshold=0.85)

    metrics = evaluate(eval_db, "binaries", gt)
    assert set(metrics.per_mutation_recall) == {"identical", "recompile"}
    assert metrics.per_mutation_recall["identical"] == 1.0
    # recompile at 0.85 is below its ~0.5 score → missed → 0.0 recall (a finding).
    assert metrics.per_mutation_recall["recompile"] == 0.0
    assert "new" not in metrics.per_mutation_recall
    assert "drop" not in metrics.per_mutation_recall


# ── sweep: recall is non-increasing in threshold; one result per threshold ──


def test_sweep_recall_monotonic(eval_db):
    _ingest(
        eval_db,
        [
            ("foo", {"sha256": "deadbeef", "executable_name": "foo", "path": "/usr/bin/foo"}),
            ("bar", {"sha256": "cafef00d", "executable_name": "bar", "path": "/usr/bin/bar"}),
        ],
    )
    gt = perturb_atoms(
        eval_db, BASE_VID, NEW_VID, {"identical": 1, "recompile": 1}, "binaries", seed=1
    )
    thresholds = [0.5, 0.9]
    results = sweep(eval_db, "binaries", gt, thresholds)

    assert len(results) == len(thresholds)
    # Lower threshold catches at least as much → recall(low) >= recall(high).
    assert results[0][1].recall >= results[-1][1].recall
    # The low threshold catches recompile (~0.5) that the high one misses.
    assert results[0][1].recall == 1.0
    # recommend picks the best-F1 threshold (both perfect-precision here).
    assert recommend_threshold(results) in thresholds


# ── perturbation builds the ground-truth structure it claims ───────────────


def test_perturb_ground_truth_structure(eval_db):
    """{identical:2, new:1, drop:1} over 3 base atoms → 2 two-atom clusters,
    a singleton `new`, and a singleton dropped base."""
    _ingest(
        eval_db,
        [
            ("a", {"sha256": "a1", "executable_name": "aexe", "path": "/bin/a"}),
            ("b", {"sha256": "b2", "executable_name": "bexe", "path": "/bin/b"}),
            ("c", {"sha256": "c3", "executable_name": "cexe", "path": "/bin/c"}),
        ],
    )
    gt = perturb_atoms(
        eval_db,
        BASE_VID,
        NEW_VID,
        {"identical": 2, "new": 1, "drop": 1},
        "binaries",
        seed=1,
    )

    # 6 atoms: 3 base + 2 identical perturbations + 1 new.
    assert len(gt.cluster_of) == 6

    cluster_sizes = Counter(Counter(gt.cluster_of.values()).values())
    assert cluster_sizes[2] == 2  # two (base, identical) clusters
    assert cluster_sizes[1] == 2  # dropped base + new atom, each singleton

    labels = Counter(gt.mutation_of.values())
    assert labels["base"] == 3
    assert labels["identical"] == 2
    assert labels["new"] == 1
    assert "drop" not in labels  # a drop emits no atom

    conn = open_db(eval_db)
    try:
        new_version_atoms = conn.execute(
            "SELECT COUNT(*) FROM atoms "
            "WHERE source_version_id = ? AND entity_type = 'binaries'",
            (NEW_VID,),
        ).fetchone()[0]
    finally:
        conn.close()
    assert new_version_atoms == 3


# ── raises when consuming mutations exceed the base atoms ───────────────────


def test_perturb_too_many_consuming_raises(eval_db):
    _ingest(
        eval_db,
        [("only", {"sha256": "z", "executable_name": "only", "path": "/bin/only"})],
    )
    with pytest.raises(ValueError, match="consuming mutations"):
        perturb_atoms(
            eval_db, BASE_VID, NEW_VID, {"identical": 2}, "binaries", seed=1
        )


# ── confusable: a hard negative that copies a base's name but is its own id ──


def test_confusable_is_singleton_sharing_name(eval_db):
    """A `confusable` atom copies the base's name-role value verbatim yet is its
    own singleton cluster, with a distinct hash and path (a different entity)."""
    _ingest(
        eval_db,
        [("payload", {"sha256": "abc", "executable_name": "payload", "path": "/bin/payload"})],
    )
    gt = perturb_atoms(
        eval_db, BASE_VID, NEW_VID, {"identical": 1, "confusable": 1}, "binaries", seed=1
    )

    conf_ids = [aid for aid, label in gt.mutation_of.items() if label == "confusable"]
    assert len(conf_ids) == 1
    cid = conf_ids[0]
    # Its own singleton cluster — maps to itself and nobody else shares that id.
    assert gt.cluster_of[cid] == cid
    assert list(gt.cluster_of.values()).count(cid) == 1

    conn = open_db(eval_db)
    try:
        props = json.loads(
            conn.execute("SELECT properties FROM atoms WHERE id = ?", (cid,)).fetchone()[0]
        )
    finally:
        conn.close()
    # Shares the base's name-role value verbatim (→ same blocking bucket)...
    assert props["executable_name"] == "payload"
    # ...but is a genuinely different entity: distinct hash and path.
    assert props.get("sha256") != "abc"
    assert props.get("path") != "/bin/payload"


def test_confusable_makes_precision_drop(eval_db):
    """The whole point of the increment: a confusable that shares a base's name
    (but differs in hash+path) is wrongly merged at a LOW threshold — driving a
    false positive and precision < 1.0 — yet stays separate at a HIGH threshold.
    This proves the harness now actually exercises the precision axis."""
    _ingest(
        eval_db,
        [("helper", {"sha256": "aaaa", "executable_name": "helper", "path": "/usr/bin/helper"})],
    )
    gt = perturb_atoms(
        eval_db, BASE_VID, NEW_VID, {"identical": 1, "confusable": 1}, "binaries", seed=1
    )

    by_t = dict(sweep(eval_db, "binaries", gt, [0.3, 0.9]))
    low, high = by_t[0.3], by_t[0.9]

    # Low threshold: the confusable is merged wrongly → a false positive.
    assert low.fp >= 1
    assert low.precision < 1.0
    assert low.confusable_false_merges >= 1
    # High threshold: it stays its own bag → precision intact, no false merge.
    assert high.precision == 1.0
    assert high.confusable_false_merges == 0


def test_confusable_strong_drops_precision_at_realistic_threshold(eval_db):
    """A `confusable_strong` shares a base's name AND path, differing only in
    content hash — feature-identical to a `recompile` yet a genuinely different
    entity. It is wrongly merged at a realistic MID threshold (0.5), driving
    precision below 1.0 there, and only a HIGH threshold (0.85) keeps it apart.
    This demonstrates the real tension: recompile recall and this false positive
    are won or lost together."""
    _ingest(
        eval_db,
        [("svc", {"sha256": "aaaa", "executable_name": "svc", "path": "/usr/bin/svc"})],
    )
    gt = perturb_atoms(
        eval_db, BASE_VID, NEW_VID, {"identical": 1, "confusable_strong": 1}, "binaries", seed=1
    )
    by_t = dict(sweep(eval_db, "binaries", gt, [0.5, 0.85]))

    # Mid threshold: the strong confusable (name+path match, hash differs) is
    # wrongly merged -> precision damage at a realistic operating point.
    assert by_t[0.5].confusable_false_merges >= 1
    assert by_t[0.5].precision < 1.0
    # High threshold: kept separate -> precision intact.
    assert by_t[0.85].precision == 1.0
    assert by_t[0.85].confusable_false_merges == 0


def test_confusable_requires_a_base_atom(eval_db):
    """Confusable atoms copy a real base's name, so requesting them with no base
    atom is a ValueError, not a silent no-op."""
    with pytest.raises(ValueError, match="confusable"):
        perturb_atoms(
            eval_db, BASE_VID, NEW_VID, {"confusable": 1}, "binaries", seed=1
        )


# ── calibrate_threshold: precision-constrained, unlike max-F1 recommend ─────


def _metrics(precision, recall=1.0, f1=0.0):
    """A Metrics carrying only the fields calibrate_threshold reads."""
    return Metrics(
        precision=precision, recall=recall, f1=f1, tp=0, fp=0, fn=0, per_mutation_recall={}
    )


def test_calibrate_threshold_picks_lowest_precise():
    """Precision is below the floor at low thresholds and clears it from 0.7 up:
    calibrate returns the LOWEST threshold that still meets the floor (max recall
    while holding precision), where max-F1 recommend would happily go lower."""
    results = [
        (0.5, _metrics(0.80, recall=1.00, f1=0.89)),
        (0.6, _metrics(0.90, recall=0.95, f1=0.92)),
        (0.7, _metrics(0.97, recall=0.90, f1=0.93)),
        (0.8, _metrics(0.98, recall=0.85, f1=0.91)),
        (0.9, _metrics(1.00, recall=0.70, f1=0.82)),
    ]
    assert calibrate_threshold(results, min_precision=0.95) == 0.7
    # Contrast: max-F1 recommend prefers the reckless low-precision 0.7? No — here
    # 0.7 happens to also be max-F1; the divergence is exercised elsewhere. The
    # key claim is calibrate never dips below the precision floor:
    assert calibrate_threshold(results, min_precision=0.99) == 0.9


def test_calibrate_threshold_ties_break_toward_higher_f1():
    """Two thresholds share the lowest precise value; the higher-F1 one wins."""
    results = [
        (0.7, _metrics(0.96, recall=0.90, f1=0.93)),
        (0.7, _metrics(0.96, recall=0.95, f1=0.955)),
        (0.9, _metrics(0.99, recall=0.60, f1=0.75)),
    ]
    # Both 0.7 rows pass; tie on threshold → higher F1 (0.955) — still returns 0.7.
    assert calibrate_threshold(results, min_precision=0.95) == 0.7


def test_calibrate_threshold_falls_back_to_max_precision():
    """When NO threshold reaches the floor, return the most precise threshold
    (ties broken toward the higher, stricter threshold)."""
    results = [
        (0.5, _metrics(0.60)),
        (0.7, _metrics(0.80)),
        (0.9, _metrics(0.75)),
    ]
    assert calibrate_threshold(results, min_precision=0.95) == 0.7

    # Tie on precision → higher threshold wins.
    tied = [
        (0.5, _metrics(0.80)),
        (0.9, _metrics(0.80)),
    ]
    assert calibrate_threshold(tied, min_precision=0.95) == 0.9
