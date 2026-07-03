"""Tests for the resolver evaluation harness (icarus.core.resolver_eval).

The harness is a *measurement* tool: it perturbs atoms with known ground-truth
labels, runs the real ``resolve_scored`` unchanged, and scores precision/recall.
These tests hand-check the pairwise metric math on tiny, fully-known datasets,
and verify the perturbation builds the ground-truth structure it claims to.
"""

import sqlite3
import tempfile
from collections import Counter
from pathlib import Path

import pytest

from icarus.core.resolver import EntityResolver
from icarus.core.resolver_eval import (
    GroundTruth,
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
