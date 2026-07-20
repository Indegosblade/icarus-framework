"""Regression tests for SAN-09 (#42): secrets surviving in atoms_fts.

Root cause: the atoms table had FTS-sync triggers for AFTER INSERT
(atoms_ai) and AFTER DELETE (atoms_ad) but none for AFTER UPDATE, unlike
files/daemons which have all three. A sanitizer UPDATE to redact a secret
in atoms.properties therefore never propagated to atoms_fts, leaving the
secret searchable in the full-text index.

Two independent fixes are covered here:
1. icarus/core/schema.py FTS_TRIGGERS now defines atoms_au, mirroring
   daemons_au, so fresh databases stay in sync on UPDATE.
2. icarus/integrations/hygeia.sanitize_output() unconditionally rebuilds
   every FTS index after HYGEIA sanitizes, closing the same hole for any
   database built before atoms_au existed (the confidentiality boundary
   that does not depend on which triggers a given database happens to have).
"""

import json
import sqlite3

import pytest

from icarus.core.schema import initialize_database, open_db

try:
    from icarus.integrations import hygeia as hygeia_mod

    _HAS_HYGEIA_PACKAGE = hygeia_mod._HAS_HYGEIA_PACKAGE
except ImportError:  # pragma: no cover - hygeia integration module itself missing
    hygeia_mod = None
    _HAS_HYGEIA_PACKAGE = False


MARKER = "SAN09_UNIQUE_MARKER_f2c9a6"


def _insert_version(conn):
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES ('test-san09', 'test', '/test', '2026-01-01T00:00:00Z')"
    )
    conn.commit()
    return conn.execute("SELECT id FROM versions").fetchone()[0]


def _insert_atom(conn, version_id, source_key, properties):
    cur = conn.execute(
        "INSERT INTO atoms (source_version_id, entity_type, source_key, "
        "properties, created_at) VALUES (?, ?, ?, ?, ?)",
        (version_id, "binaries", source_key, properties, "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    return cur.lastrowid


def _fts_matches(conn, marker):
    return conn.execute(
        "SELECT rowid FROM atoms_fts WHERE atoms_fts MATCH ?", (marker,)
    ).fetchall()


# ── Part 1: atoms_au trigger exists and re-syncs atoms_fts on UPDATE ──────


def test_atoms_au_trigger_exists(tmp_path):
    db_path = tmp_path / "trigger.db"
    initialize_database(db_path)
    conn = open_db(db_path)
    try:
        trigger = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name = 'atoms_au'"
        ).fetchone()
        assert trigger is not None, "atoms_au trigger must exist on a fresh v6 database"
    finally:
        conn.close()


def test_atoms_fts_resyncs_on_update(tmp_path):
    db_path = tmp_path / "resync.db"
    initialize_database(db_path)
    conn = open_db(db_path)
    try:
        version_id = _insert_version(conn)
        atom_id = _insert_atom(
            conn, version_id, "atom-1", json.dumps({"note": f"secret={MARKER}"})
        )

        # Before the update, the marker is present and searchable via FTS.
        assert _fts_matches(conn, MARKER), "marker should be indexed after INSERT"

        # Simulate redaction: UPDATE the row to remove the marker.
        conn.execute(
            "UPDATE atoms SET properties = ? WHERE id = ?",
            (json.dumps({"note": "secret=REDACTED"}), atom_id),
        )
        conn.commit()

        # After the update, atoms_au must have re-synced atoms_fts so the
        # marker is no longer findable, and the redacted content-table row
        # must not itself still carry the marker.
        assert not _fts_matches(conn, MARKER), (
            "atoms_fts must no longer match the old marker after UPDATE "
            "(atoms_au must re-sync the FTS index)"
        )
        row = conn.execute(
            "SELECT properties FROM atoms WHERE id = ?", (atom_id,)
        ).fetchone()
        assert MARKER not in row[0]
    finally:
        conn.close()


# ── Part 2: sanitizer rebuilds every FTS index as a fail-closed boundary ──


@pytest.mark.skipif(not _HAS_HYGEIA_PACKAGE, reason="HYGEIA package not installed")
def test_sanitize_output_removes_secret_from_atoms_fts(tmp_path):
    db_path = tmp_path / "sanitize.db"
    initialize_database(db_path, {"source": "san09-test"})
    conn = open_db(db_path)
    try:
        version_id = _insert_version(conn)
        secret = "password = SyntheticSecretValue-SAN09-Only-For-Test"
        _insert_atom(conn, version_id, "atom-secret", json.dumps({"note": secret}))
        assert _fts_matches(conn, "SyntheticSecretValue"), "sanity: secret indexed pre-sanitize"
    finally:
        conn.close()

    stats = hygeia_mod.sanitize_output(db_path)
    assert stats["verified"] is True

    conn = sqlite3.connect(str(db_path))
    try:
        assert not conn.execute(
            "SELECT rowid FROM atoms_fts WHERE atoms_fts MATCH ?",
            ("SyntheticSecretValue",),
        ).fetchall(), "secret must not survive in atoms_fts after sanitize_output"

        remaining = conn.execute("SELECT properties FROM atoms").fetchall()
        for (properties,) in remaining:
            assert "SyntheticSecretValue" not in (properties or "")
    finally:
        conn.close()


def test_rebuild_fts_indexes_cleans_stale_index_without_update_trigger(tmp_path):
    """Direct test of the rebuild helper against a DB missing atoms_au.

    This does not depend on HYGEIA being installed: it simulates the exact
    pre-existing-database scenario Part 2 exists to cover — a database whose
    atoms table lacks (or predates) the AFTER UPDATE trigger, so a raw
    content-table UPDATE leaves stale, secret-bearing content behind in the
    FTS shadow tables even though the visible content table was cleaned.
    """
    if hygeia_mod is None:
        pytest.skip("icarus.integrations.hygeia module is not importable")

    db_path = tmp_path / "stale.db"
    initialize_database(db_path)
    conn = open_db(db_path)
    try:
        # Remove the update trigger to reproduce a pre-fix database.
        conn.execute("DROP TRIGGER IF EXISTS atoms_au")
        conn.commit()

        version_id = _insert_version(conn)
        atom_id = _insert_atom(
            conn, version_id, "atom-stale", json.dumps({"note": f"secret={MARKER}"})
        )
        assert _fts_matches(conn, MARKER), "sanity: marker indexed after INSERT"

        # Raw UPDATE with no au trigger present: content table changes,
        # FTS shadow table does not.
        conn.execute(
            "UPDATE atoms SET properties = ? WHERE id = ?",
            (json.dumps({"note": "secret=REDACTED"}), atom_id),
        )
        conn.commit()

        assert _fts_matches(conn, MARKER), (
            "sanity: without atoms_au, the stale marker must still be in atoms_fts"
        )
    finally:
        conn.close()

    # Run the same rebuild the sanitizer boundary runs.
    hygeia_mod._rebuild_fts_indexes(db_path)

    conn = sqlite3.connect(str(db_path))
    try:
        assert not _fts_matches(conn, MARKER), (
            "rebuild must clear stale FTS content even without atoms_au"
        )
    finally:
        conn.close()


def test_rebuild_fts_indexes_skips_missing_fts_tables(tmp_path):
    """The rebuild helper must not error when an FTS table is absent."""
    if hygeia_mod is None:
        pytest.skip("icarus.integrations.hygeia module is not importable")

    db_path = tmp_path / "no_fts.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)")
        conn.commit()
    finally:
        conn.close()

    # Must not raise even though none of files_fts/daemons_fts/atoms_fts exist.
    hygeia_mod._rebuild_fts_indexes(db_path)
