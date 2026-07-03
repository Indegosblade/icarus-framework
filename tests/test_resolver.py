"""Behavioral tests for the experimental EntityResolver subsystem.

Covers the audit findings closed on this branch:

* #128 — EntityResolver.resolve() had zero test coverage. These tests ingest
  atoms with overlapping/distinct blocking-key values, call resolve(), and
  assert the returned {"merges", "atoms_resolved"} counts AND the resulting
  bag membership.
* #118 — resolve() no longer advertises a threshold parameter and the dead
  FTS BlockingIndex class is gone.
* #113 — the subsystem is gated behind an explicit experimental flag /
  entry point.
* #63 / #68 — the resolver connection is opened through open_db(), so
  foreign_keys are actually enforced.
"""

import sqlite3
import tempfile
import warnings
from pathlib import Path

import pytest

import icarus.core.resolver as resolver_mod
from icarus.core.resolver import EntityResolver
from icarus.core.schema import initialize_database


@pytest.fixture
def resolver_db():
    """A freshly-initialized DB with a single version row for atom FKs."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    initialize_database(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES ('test-run-resolver', 'test', '/test', '2026-01-01T00:00:00Z')"
    )
    conn.commit()
    conn.close()
    yield db_path
    # open_db() runs the connection in WAL mode, so clean up side files too.
    for suffix in ("", "-wal", "-shm"):
        Path(str(db_path) + suffix).unlink(missing_ok=True)


def _resolver(db_path):
    """Construct the (experimental) resolver, acknowledging the flag."""
    return EntityResolver(str(db_path), experimental=True)


# ── #128: resolve() behavior ─────────────────────────────────────────────


def test_resolve_merges_overlapping_and_bags_distinct(resolver_db):
    """Two atoms sharing a normalized blocking key merge; a distinct one bags alone."""
    with _resolver(resolver_db) as r:
        # Same identity by email — note differing case + surrounding whitespace,
        # which resolve() normalizes via .lower().strip().
        a1 = r.ingest_atom(1, "identity", "src-1",
                           {"email": "alice@example.com", "name": "Alice"})
        a2 = r.ingest_atom(1, "identity", "src-2",
                           {"email": "  Alice@Example.COM  ", "name": "A."})
        # A genuinely different identity.
        a3 = r.ingest_atom(1, "identity", "src-3",
                           {"email": "bob@example.com", "name": "Bob"})

        result = r.resolve("identity", ["email"])

        # One multi-atom bag (alice) + one singleton (bob).
        assert result == {"merges": 1, "atoms_resolved": 3}

        conn = r.conn
        # The merged bag is keyed by the normalized cluster key.
        merged = conn.execute(
            "SELECT id FROM bags WHERE canonical_key = 'alice@example.com'"
        ).fetchone()
        assert merged is not None
        merged_atoms = {
            row[0]
            for row in conn.execute(
                "SELECT atom_id FROM bag_atoms WHERE bag_id = ?", (merged[0],)
            ).fetchall()
        }
        assert merged_atoms == {a1, a2}

        # Bob sits in his own singleton bag, distinct from alice's.
        bob_bag = conn.execute(
            "SELECT bag_id FROM bag_atoms WHERE atom_id = ?", (a3,)
        ).fetchone()[0]
        assert bob_bag != merged[0]
        bob_members = conn.execute(
            "SELECT COUNT(*) FROM bag_atoms WHERE bag_id = ?", (bob_bag,)
        ).fetchone()[0]
        assert bob_members == 1

        # Every atom is now assigned to exactly one bag.
        assert r.unresolved_atoms("identity") == []


def test_resolve_uses_compound_blocking_key(resolver_db):
    """A compound blocking key keeps same-email/different-tenant atoms apart."""
    with _resolver(resolver_db) as r:
        a1 = r.ingest_atom(1, "identity", "src-1", {"email": "x@y.com", "tenant": "acme"})
        # Same email, different tenant → its own singleton, not merged with a1/a3.
        r.ingest_atom(1, "identity", "src-2", {"email": "x@y.com", "tenant": "globex"})
        a3 = r.ingest_atom(1, "identity", "src-3", {"email": "x@y.com", "tenant": "acme"})

        result = r.resolve("identity", ["email", "tenant"])

        # Cluster "x@y.com|acme" = {a1, a3} (merge); "x@y.com|globex" = {a2} (singleton).
        assert result == {"merges": 1, "atoms_resolved": 3}

        bag = r.conn.execute(
            "SELECT id FROM bags WHERE canonical_key = 'x@y.com|acme'"
        ).fetchone()
        assert bag is not None
        members = {
            row[0]
            for row in r.conn.execute(
                "SELECT atom_id FROM bag_atoms WHERE bag_id = ?", (bag[0],)
            ).fetchall()
        }
        assert members == {a1, a3}


def test_resolve_skips_atoms_without_blocking_value(resolver_db):
    """Atoms lacking any blocking-key value are left unresolved, not bagged."""
    with _resolver(resolver_db) as r:
        # a1 has a blocking value (gets bagged); a2 has none (stays unresolved).
        r.ingest_atom(1, "identity", "src-1", {"email": "keep@y.com"})
        a2 = r.ingest_atom(1, "identity", "src-2", {"name": "no email here"})

        result = r.resolve("identity", ["email"])

        # a1 → singleton bag; a2 has no 'email' so it is never clustered.
        assert result == {"merges": 0, "atoms_resolved": 1}
        assert r.unresolved_atoms("identity") == [a2]


def test_resolve_no_atoms_returns_zero(resolver_db):
    """The early-return branch: nothing to resolve yields zero counts."""
    with _resolver(resolver_db) as r:
        assert r.resolve("identity", ["email"]) == {"merges": 0, "atoms_resolved": 0}


def test_resolve_is_idempotent_after_all_bagged(resolver_db):
    """Re-running resolve() once everything is bagged is a no-op (zero counts)."""
    with _resolver(resolver_db) as r:
        r.ingest_atom(1, "identity", "src-1", {"email": "solo@y.com"})
        first = r.resolve("identity", ["email"])
        assert first == {"merges": 0, "atoms_resolved": 1}
        assert r.resolve("identity", ["email"]) == {"merges": 0, "atoms_resolved": 0}


# ── #118: dropped threshold param + removed BlockingIndex ─────────────────


def test_resolve_rejects_removed_threshold_param(resolver_db):
    with _resolver(resolver_db) as r:
        with pytest.raises(TypeError):
            r.resolve("identity", ["email"], threshold=0.8)


def test_blockingindex_class_removed():
    assert not hasattr(resolver_mod, "BlockingIndex")


# ── #113: explicit experimental gate ─────────────────────────────────────


def test_resolver_is_flagged_experimental():
    assert resolver_mod.__experimental__ is True


def test_resolver_warns_without_experimental_flag(resolver_db):
    with pytest.warns(UserWarning, match="experimental"):
        r = EntityResolver(str(resolver_db))
    r.close()


def test_resolver_silent_with_experimental_flag(resolver_db):
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any warning would fail the test
        r = EntityResolver(str(resolver_db), experimental=True)
        r.close()


# ── #63 / #68: foreign_keys enforced via open_db ─────────────────────────


def test_resolver_connection_enforces_foreign_keys(resolver_db):
    with _resolver(resolver_db) as r:
        assert r.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        # atoms.source_version_id REFERENCES versions(id); version 999 does not
        # exist, so with FKs enforced the insert must fail.
        with pytest.raises(sqlite3.IntegrityError):
            r.ingest_atom(999, "identity", "src-x", {"email": "z@y.com"})
