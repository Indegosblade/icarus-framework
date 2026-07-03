"""Tests for Increment B: resolver coverage extended to frameworks/kexts/files.

Prior to this increment the entity resolver (icarus.core.atomize +
icarus.core.matching) only projected/scored "binaries" and "daemons". This
file covers the three new ATOM_PROJECTIONS / SCORING_SPECS / DEFAULT_BLOCKING_KEYS
entries and the one new comparator added to support them — it does not repeat
existing binaries/daemons coverage (see tests/test_atomize.py,
tests/test_matching.py, tests/test_resolve_scored.py), and does not repeat the
unknown-entity_type KeyError case already covered by
tests/test_matching.py::test_score_pair_unknown_entity_type_raises_keyerror.

Covers:
* cmp_numeric_close: equal / None / unparseable / close / far-apart cases.
* atomize_db projects frameworks/kexts/files rows into atoms with the right
  entity_type / source_key / JSON properties.
* Cross-source EntityResolver.resolve_scored merges matching "files" and
  "frameworks" atoms (ingested under two different source_version_ids) into
  one bag with a non-NULL bags.score.
* score_pair for entity_type "files" scores a near-identical pair >= 0.9.
"""

import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

from icarus.core.atomize import ATOM_PROJECTIONS, atomize_db
from icarus.core.matching import cmp_numeric_close, score_pair
from icarus.core.resolver import EntityResolver
from icarus.core.schema import initialize_database

# ── cmp_numeric_close ──────────────────────────────────────────────────────


def test_cmp_numeric_close_equal_is_one():
    assert cmp_numeric_close("100", "100") == 1.0
    assert cmp_numeric_close("0", "0") == 1.0
    assert cmp_numeric_close("-5.5", "-5.5") == 1.0


def test_cmp_numeric_close_none_is_zero():
    assert cmp_numeric_close(None, "100") == 0.0
    assert cmp_numeric_close("100", None) == 0.0
    assert cmp_numeric_close(None, None) == 0.0


def test_cmp_numeric_close_unparseable_is_zero():
    assert cmp_numeric_close("abc", "100") == 0.0
    assert cmp_numeric_close("100", "xyz") == 0.0
    assert cmp_numeric_close("not-a-number", "also-not") == 0.0


def test_cmp_numeric_close_near_values():
    # 1 - |100-110|/max(100,110) = 1 - 10/110 = 100/110 = 0.9090909...
    assert cmp_numeric_close("100", "110") == pytest.approx(0.909090909, rel=1e-6)


def test_cmp_numeric_close_far_values_near_zero():
    # 1 - |1-1000000|/1000000 = 1 - 999999/1000000 = 0.000001 -> ~0.
    result = cmp_numeric_close("1", "1000000")
    assert 0.0 <= result < 0.01


# ── atomize the new entity types ──────────────────────────────────────────


@pytest.fixture
def db_path():
    """A freshly-initialized (v6) ICARUS database path, cleaned up after."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = Path(f.name)
    initialize_database(path)
    yield path
    # initialize_database opens WAL mode, so remove side files too.
    for suffix in ("", "-wal", "-shm"):
        Path(str(path) + suffix).unlink(missing_ok=True)


def _insert_version(conn: sqlite3.Connection, run_id: str) -> int:
    cur = conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES (?, 'resolve', '/src', '2026-01-01T00:00:00Z')",
        (run_id,),
    )
    conn.commit()
    vid = cur.lastrowid
    assert vid is not None
    return vid


def test_atomize_new_entity_types(db_path):
    # The three new types are declared in ATOM_PROJECTIONS (Deliverable 1).
    assert {"frameworks", "kexts", "files"} <= set(ATOM_PROJECTIONS)

    conn = sqlite3.connect(str(db_path))
    try:
        version_id = _insert_version(conn, "run-new-types")

        conn.execute(
            "INSERT INTO files (path, filename, extension, size, sha256, file_type) "
            "VALUES ('/usr/lib/libfoo.dylib', 'libfoo.dylib', 'dylib', 4096, "
            "'filehash123', 'Mach-O dynamic lib')"
        )
        conn.execute(
            "INSERT INTO frameworks (name, path, bundle_id, version) "
            "VALUES ('CoreFoo', '/System/Library/Frameworks/CoreFoo.framework', "
            "'com.apple.CoreFoo', '1.0')"
        )
        conn.execute(
            "INSERT INTO kexts (bundle_id, name, version) "
            "VALUES ('com.apple.foo.kext', 'FooKext', '2.0')"
        )
        conn.commit()

        counts = atomize_db(conn, conn, version_id, ["files", "frameworks", "kexts"])
        assert counts == {"files": 1, "frameworks": 1, "kexts": 1}

        # files atom is keyed by path (the first selected column).
        frow = conn.execute(
            "SELECT source_key, properties FROM atoms WHERE entity_type = 'files'"
        ).fetchone()
        assert frow[0] == "/usr/lib/libfoo.dylib"
        assert json.loads(frow[1]) == {
            "path": "/usr/lib/libfoo.dylib",
            "filename": "libfoo.dylib",
            "extension": "dylib",
            "size": 4096,
            "sha256": "filehash123",
            "file_type": "Mach-O dynamic lib",
        }

        # frameworks atom is keyed by path (the first selected column).
        fwrow = conn.execute(
            "SELECT source_key, properties FROM atoms WHERE entity_type = 'frameworks'"
        ).fetchone()
        assert fwrow[0] == "/System/Library/Frameworks/CoreFoo.framework"
        assert json.loads(fwrow[1]) == {
            "path": "/System/Library/Frameworks/CoreFoo.framework",
            "name": "CoreFoo",
            "bundle_id": "com.apple.CoreFoo",
            "version": "1.0",
        }

        # kexts atom is keyed by bundle_id (the first selected column).
        krow = conn.execute(
            "SELECT source_key, properties FROM atoms WHERE entity_type = 'kexts'"
        ).fetchone()
        assert krow[0] == "com.apple.foo.kext"
        assert json.loads(krow[1]) == {
            "bundle_id": "com.apple.foo.kext",
            "name": "FooKext",
            "version": "2.0",
        }
    finally:
        conn.close()


# ── cross-source scored merge for the new entity types ────────────────────


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


def _resolver(path):
    return EntityResolver(str(path), experimental=True)


def _bag_of(conn, atom_id):
    return conn.execute(
        "SELECT bag_id FROM bag_atoms WHERE atom_id = ?", (atom_id,)
    ).fetchone()[0]


def test_resolve_scored_merges_files_across_sources(scored_db):
    """Same sha256+filename, differing only in directory, under two
    source_version_ids -> one bag spanning both sources with a scored merge."""
    with _resolver(scored_db) as r:
        a1 = r.ingest_atom(
            1, "files", "/data/a/report.pdf",
            {"path": "/data/a/report.pdf", "filename": "report.pdf",
             "sha256": "deadbeef1234", "size": 1000, "file_type": "PDF document"},
        )
        a2 = r.ingest_atom(
            2, "files", "/data/b/report.pdf",
            {"path": "/data/b/report.pdf", "filename": "report.pdf",
             "sha256": "deadbeef1234", "size": 1000, "file_type": "PDF document"},
        )

        result = r.resolve_scored("files", threshold=0.85)
        assert result == {"clusters": 1, "merges": 1, "atoms_resolved": 2}

        conn = r.conn
        bag = _bag_of(conn, a1)
        assert _bag_of(conn, a2) == bag

        svids = {
            row[0]
            for row in conn.execute(
                "SELECT a.source_version_id FROM bag_atoms ba "
                "JOIN atoms a ON a.id = ba.atom_id WHERE ba.bag_id = ?",
                (bag,),
            ).fetchall()
        }
        assert svids == {1, 2}

        score = conn.execute(
            "SELECT score FROM bags WHERE id = ?", (bag,)
        ).fetchone()[0]
        assert score is not None
        assert score >= 0.85


def test_resolve_scored_merges_frameworks_across_sources(scored_db):
    """Same bundle_id+name, differing only in install path, under two
    source_version_ids -> one bag spanning both sources with a scored merge."""
    with _resolver(scored_db) as r:
        a1 = r.ingest_atom(
            1, "frameworks", "/System/Library/Frameworks/Foo.framework",
            {"path": "/System/Library/Frameworks/Foo.framework", "name": "Foo",
             "bundle_id": "com.apple.foo", "version": "1.0"},
        )
        a2 = r.ingest_atom(
            2, "frameworks", "/Volumes/Other/Frameworks/Foo.framework",
            {"path": "/Volumes/Other/Frameworks/Foo.framework", "name": "Foo",
             "bundle_id": "com.apple.foo", "version": "1.0"},
        )

        result = r.resolve_scored("frameworks", threshold=0.85)
        assert result == {"clusters": 1, "merges": 1, "atoms_resolved": 2}

        conn = r.conn
        bag = _bag_of(conn, a1)
        assert _bag_of(conn, a2) == bag

        svids = {
            row[0]
            for row in conn.execute(
                "SELECT a.source_version_id FROM bag_atoms ba "
                "JOIN atoms a ON a.id = ba.atom_id WHERE ba.bag_id = ?",
                (bag,),
            ).fetchall()
        }
        assert svids == {1, 2}

        score = conn.execute(
            "SELECT score FROM bags WHERE id = ?", (bag,)
        ).fetchone()[0]
        assert score is not None
        assert score >= 0.85


# ── score_pair for files ────────────────────────────────────────────────────


def test_score_pair_matching_files_high():
    a = {"sha256": "deadbeef", "filename": "report.pdf", "path": "/a/report.pdf"}
    b = {"sha256": "deadbeef", "filename": "REPORT.PDF", "path": "/b/REPORT.PDF"}
    score, features = score_pair("files", a, b)
    assert score >= 0.9
    assert "sha256" in features
    assert "filename" in features
