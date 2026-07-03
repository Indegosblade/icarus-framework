"""Behavioral tests for EntityResolver.resolve_scored — the real
block -> score -> cluster -> merge pipeline (contrast resolve(), the exact-key
MVP covered in tests/test_resolver.py).

These assert the *payoff*: atoms observed under different source_version_ids
that describe the same real-world binary are merged into one bag, with the
decision left auditable via match_candidates, bags.score, and the event log.
"""

import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

from icarus.core.resolver import EntityResolver
from icarus.core.schema import initialize_database


@pytest.fixture
def scored_db():
    """A fresh v6 DB with TWO version rows so atoms can span sources."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    initialize_database(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES ('scored-run-a', 'test', '/a', '2026-01-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES ('scored-run-b', 'test', '/b', '2026-01-01T00:00:00Z')"
    )
    conn.commit()
    conn.close()
    yield db_path
    # open_db() runs WAL mode, so clean up the side files too.
    for suffix in ("", "-wal", "-shm"):
        Path(str(db_path) + suffix).unlink(missing_ok=True)


def _resolver(db_path):
    return EntityResolver(str(db_path), experimental=True)


def _bag_of(conn, atom_id):
    return conn.execute(
        "SELECT bag_id FROM bag_atoms WHERE atom_id = ?", (atom_id,)
    ).fetchone()[0]


# ── Headline: cross-source merge ──────────────────────────────────────────


def test_resolve_scored_cross_source_merge(scored_db):
    """The same binary seen under two source_version_ids lands in one bag."""
    with _resolver(scored_db) as r:
        # Same sha256 + executable_name, differing only in path — but ingested
        # under DIFFERENT source_version_ids (1 vs 2): a genuine cross-source
        # observation of one binary.
        foo1 = r.ingest_atom(
            1, "binaries", "foo-a",
            {"sha256": "deadbeef", "executable_name": "foo", "path": "/usr/bin/foo"},
        )
        foo2 = r.ingest_atom(
            2, "binaries", "foo-b",
            {"sha256": "deadbeef", "executable_name": "foo", "path": "/bin/foo"},
        )
        # A genuinely different binary.
        bar = r.ingest_atom(
            1, "binaries", "bar-c",
            {"sha256": "cafef00d", "executable_name": "bar", "path": "/usr/bin/bar"},
        )

        result = r.resolve_scored("binaries", threshold=0.85)

        assert result == {"clusters": 1, "merges": 1, "atoms_resolved": 3}

        conn = r.conn

        # The two foo atoms share ONE bag...
        foo_bag = _bag_of(conn, foo1)
        assert _bag_of(conn, foo2) == foo_bag
        members = {
            row[0]
            for row in conn.execute(
                "SELECT atom_id FROM bag_atoms WHERE bag_id = ?", (foo_bag,)
            ).fetchall()
        }
        assert members == {foo1, foo2}

        # ...and that bag's members span TWO distinct source_version_ids.
        svids = {
            row[0]
            for row in conn.execute(
                "SELECT a.source_version_id FROM bag_atoms ba "
                "JOIN atoms a ON a.id = ba.atom_id WHERE ba.bag_id = ?",
                (foo_bag,),
            ).fetchall()
        }
        assert len(svids) == 2

        # The bag carries a non-NULL, high confidence score.
        bag_score = conn.execute(
            "SELECT score FROM bags WHERE id = ?", (foo_bag,)
        ).fetchone()[0]
        assert bag_score is not None
        assert bag_score >= 0.85

        # match_candidates recorded the foo-foo pair with score + features.
        lo, hi = min(foo1, foo2), max(foo1, foo2)
        mc = conn.execute(
            "SELECT score, features FROM match_candidates "
            "WHERE atom_a = ? AND atom_b = ?",
            (lo, hi),
        ).fetchone()
        assert mc is not None
        assert mc[0] >= 0.85
        feats = json.loads(mc[1])
        assert feats  # non-empty
        assert "sha256" in feats

        # The event log has a "resolve" event for this bag with a confidence.
        evt = conn.execute(
            "SELECT confidence FROM resolution_event_log "
            "WHERE event_type = 'resolve' AND bag_id = ?",
            (foo_bag,),
        ).fetchone()
        assert evt is not None
        assert evt[0] is not None

        # bar is a singleton in its own bag.
        bar_bag = _bag_of(conn, bar)
        assert bar_bag != foo_bag
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM bag_atoms WHERE bag_id = ?", (bar_bag,)
            ).fetchone()[0]
            == 1
        )

        # Everything is resolved now.
        assert r.unresolved_atoms("binaries") == []


# ── Threshold cutoff ──────────────────────────────────────────────────────


def test_resolve_scored_threshold_cutoff(scored_db):
    """A candidate below a high threshold does not cluster; both go singleton."""
    with _resolver(scored_db) as r:
        # Same executable_name (so they ARE a candidate) but different sha256
        # and different path dir → partial score, comfortably below 0.99.
        a1 = r.ingest_atom(
            1, "binaries", "svc-a",
            {"sha256": "1111", "executable_name": "svc", "path": "/usr/bin/svc"},
        )
        a2 = r.ingest_atom(
            2, "binaries", "svc-b",
            {"sha256": "2222", "executable_name": "svc", "path": "/opt/svc"},
        )

        result = r.resolve_scored("binaries", threshold=0.99)

        assert result == {"clusters": 0, "merges": 0, "atoms_resolved": 2}

        # Two singleton bags, no cluster.
        assert r.conn.execute("SELECT COUNT(*) FROM bags").fetchone()[0] == 2
        assert _bag_of(r.conn, a1) != _bag_of(r.conn, a2)

        # But the candidate WAS scored and persisted (auditability), below cut.
        lo, hi = min(a1, a2), max(a1, a2)
        score = r.conn.execute(
            "SELECT score FROM match_candidates WHERE atom_a = ? AND atom_b = ?",
            (lo, hi),
        ).fetchone()[0]
        assert score < 0.99

        assert r.unresolved_atoms("binaries") == []


# ── Transitivity ──────────────────────────────────────────────────────────


def test_resolve_scored_transitivity(scored_db):
    """a1~a2 and a2~a3 match but a1~a3 does not — all three still cluster."""
    with _resolver(scored_db) as r:
        # All share executable_name "hub" (one bucket → all pairs are
        # candidates). Scores are engineered so only the chain edges clear 0.5:
        #   a1-a2: sha match + exec match, path basename differs → 5/6 ≈ 0.833
        #   a2-a3: exec match + path basename match + arch match  → 3.5/6.5 ≈ 0.538
        #   a1-a3: exec match only                                → 2/6   ≈ 0.333  (< 0.5)
        a1 = r.ingest_atom(
            1, "binaries", "trans-1",
            {"sha256": "S1", "executable_name": "hub", "path": "/p/a"},
        )
        a2 = r.ingest_atom(
            2, "binaries", "trans-2",
            {"sha256": "S1", "executable_name": "hub", "path": "/p/b", "arch": "x86"},
        )
        a3 = r.ingest_atom(
            1, "binaries", "trans-3",
            {"sha256": "S2", "executable_name": "hub", "path": "/p/b", "arch": "x86"},
        )

        result = r.resolve_scored("binaries", threshold=0.5)

        # Two chain edges (a1-a2, a2-a3); a1-a3 is below threshold. One bag of 3.
        assert result == {"clusters": 1, "merges": 2, "atoms_resolved": 3}

        conn = r.conn
        bags = {_bag_of(conn, a) for a in (a1, a2, a3)}
        assert len(bags) == 1
        (the_bag,) = bags
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM bag_atoms WHERE bag_id = ?", (the_bag,)
            ).fetchone()[0]
            == 3
        )

        # The a1-a3 pair was scored and persisted, but below the 0.5 cut.
        lo, hi = min(a1, a3), max(a1, a3)
        a1a3 = conn.execute(
            "SELECT score FROM match_candidates WHERE atom_a = ? AND atom_b = ?",
            (lo, hi),
        ).fetchone()
        assert a1a3 is not None
        assert a1a3[0] < 0.5


# ── Empty / idempotent ────────────────────────────────────────────────────


def test_resolve_scored_empty_type_returns_zero(scored_db):
    """No atoms of the type → all-zero dict, no writes."""
    with _resolver(scored_db) as r:
        assert r.resolve_scored("binaries") == {
            "clusters": 0,
            "merges": 0,
            "atoms_resolved": 0,
        }
        assert r.conn.execute("SELECT COUNT(*) FROM bags").fetchone()[0] == 0


def test_resolve_scored_idempotent_after_full_resolve(scored_db):
    """A single atom bags as a singleton; a second call is a no-op."""
    with _resolver(scored_db) as r:
        r.ingest_atom(
            1, "binaries", "solo",
            {"sha256": "z", "executable_name": "solo", "path": "/bin/solo"},
        )

        first = r.resolve_scored("binaries")
        assert first == {"clusters": 0, "merges": 0, "atoms_resolved": 1}

        # Nothing is unresolved now, so a re-run resolves nothing.
        second = r.resolve_scored("binaries")
        assert second == {"clusters": 0, "merges": 0, "atoms_resolved": 0}
