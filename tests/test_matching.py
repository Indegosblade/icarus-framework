"""Unit tests for icarus.core.matching — the block + score half of the scored
entity resolver.

Covers:
* Field comparators: None handling, case/whitespace normalization, difflib
  ratio bounds, token Jaccard on overlapping/disjoint sets, path-suffix rules.
* score_pair: high score for matching binaries, low score for mismatched ones,
  the no-shared-field early return, and the unknown-entity_type KeyError.
* candidate_pairs: bucket blocking, FTS token blocking, max_bucket skipping
  (with the stderr WARNING), and graceful degradation when atoms_fts is absent.
"""

import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

from icarus.core.matching import (
    candidate_pairs,
    cmp_exact,
    cmp_norm_equal,
    cmp_path_suffix,
    cmp_ratio,
    cmp_token_jaccard,
    normalize,
    score_pair,
    tokens,
)
from icarus.core.schema import initialize_database

# ── Normalization / tokenization ──────────────────────────────────────────


def test_normalize_lowercases_and_strips():
    assert normalize("  FooBar  ") == "foobar"


def test_tokens_alphanumeric_only():
    assert tokens("Foo-Bar_baz.1") == {"foo", "bar", "baz", "1"}
    assert tokens("   ") == set()


# ── Comparators: None handling ────────────────────────────────────────────


@pytest.mark.parametrize(
    "comparator",
    [cmp_exact, cmp_norm_equal, cmp_ratio, cmp_token_jaccard, cmp_path_suffix],
)
def test_comparators_return_zero_on_none(comparator):
    assert comparator(None, "x") == 0.0
    assert comparator("x", None) == 0.0
    assert comparator(None, None) == 0.0


# ── Comparators: behavior ─────────────────────────────────────────────────


def test_cmp_exact():
    assert cmp_exact("abc", "abc") == 1.0
    assert cmp_exact("abc", "ABC") == 0.0
    assert cmp_exact("abc", "abd") == 0.0


def test_cmp_norm_equal_ignores_case_and_whitespace():
    assert cmp_norm_equal("  Foo ", "foo") == 1.0
    assert cmp_norm_equal("Foo", "Bar") == 0.0


def test_cmp_ratio_identical_is_one_and_bounded():
    assert cmp_ratio("launchd", "launchd") == 1.0
    r = cmp_ratio("launchd", "launchdx")
    assert 0.0 <= r <= 1.0
    # Case-insensitive because it compares normalized strings.
    assert cmp_ratio("LAUNCHD", "launchd") == 1.0


def test_cmp_token_jaccard_overlap_and_disjoint():
    # {a,b,c} vs {b,c,d} -> intersection {b,c}=2, union {a,b,c,d}=4 -> 0.5
    assert cmp_token_jaccard("a b c", "b c d") == 0.5
    # Identical token sets -> 1.0
    assert cmp_token_jaccard("foo bar", "bar foo") == 1.0
    # Disjoint -> 0.0
    assert cmp_token_jaccard("foo", "bar") == 0.0


def test_cmp_path_suffix():
    # Basenames equal -> 1.0 even though the rest of the path differs.
    assert cmp_path_suffix("/usr/bin/foo", "/bin/foo") == 1.0
    # Different basename -> 0 trailing equal -> 0.0.
    assert cmp_path_suffix("/a/b/foo", "/a/b/bar") == 0.0
    # Basename match is case-insensitive.
    assert cmp_path_suffix("/opt/Foo", "/usr/local/foo") == 1.0
    # Backslash-separated paths split too.
    assert cmp_path_suffix(r"C:\\Windows\\svc.exe", "/tmp/svc.exe") == 1.0


# ── score_pair ────────────────────────────────────────────────────────────


def test_score_pair_matching_binaries_high():
    a = {"sha256": "deadbeef", "executable_name": "foo", "path": "/usr/bin/foo"}
    b = {"sha256": "deadbeef", "executable_name": "FOO", "path": "/bin/foo"}
    score, features = score_pair("binaries", a, b)
    assert score >= 0.9
    assert "sha256" in features
    assert "executable_name" in features


def test_score_pair_mismatched_binaries_low():
    a = {"sha256": "aaaa", "executable_name": "foo"}
    b = {"sha256": "bbbb", "executable_name": "bar"}
    score, _ = score_pair("binaries", a, b)
    assert score <= 0.3


def test_score_pair_no_shared_fields_returns_zero_and_empty():
    # a has only sha256, b has only executable_name -> no field present in both.
    assert score_pair("binaries", {"sha256": "x"}, {"executable_name": "y"}) == (0.0, {})


def test_score_pair_coerces_non_string_values():
    # arch/values may arrive as non-str; comparators must still work.
    a = {"executable_name": "foo", "arch": 64}
    b = {"executable_name": "foo", "arch": 64}
    score, features = score_pair("binaries", a, b)
    assert features["arch"] == 1.0
    assert score == 1.0


def test_score_pair_unknown_entity_type_raises_keyerror():
    with pytest.raises(KeyError):
        score_pair("widgets", {}, {})


# ── candidate_pairs ───────────────────────────────────────────────────────


@pytest.fixture
def matching_db():
    """A fresh v6 DB with a single version row for atom FKs."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    initialize_database(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES ('test-matching', 'test', '/test', '2026-01-01T00:00:00Z')"
    )
    conn.commit()
    version_id = conn.execute("SELECT id FROM versions").fetchone()[0]
    yield conn, version_id
    conn.close()
    for suffix in ("", "-wal", "-shm"):
        Path(str(db_path) + suffix).unlink(missing_ok=True)


def _insert_atom(conn, version_id, entity_type, source_key, props):
    cur = conn.execute(
        "INSERT INTO atoms (source_version_id, entity_type, source_key, "
        "properties, created_at) VALUES (?, ?, ?, ?, ?)",
        (version_id, entity_type, source_key, json.dumps(props), "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    return cur.lastrowid


def test_candidate_pairs_buckets_group_shared_key(matching_db):
    conn, vid = matching_db
    # Two binaries share executable_name "foo" (distinct source_keys); one is "bar".
    foo1 = _insert_atom(conn, vid, "binaries", "foo-1", {"executable_name": "foo"})
    foo2 = _insert_atom(conn, vid, "binaries", "foo-2", {"executable_name": "foo"})
    bar1 = _insert_atom(conn, vid, "binaries", "bar-1", {"executable_name": "bar"})

    # fts=False isolates the bucket mechanism.
    pairs = candidate_pairs(
        conn, "binaries", blocking_keys=["executable_name"], fts=False
    )

    assert (min(foo1, foo2), max(foo1, foo2)) in pairs
    # foo/bar never share the executable_name bucket.
    assert (min(foo1, bar1), max(foo1, bar1)) not in pairs
    assert (min(foo2, bar1), max(foo2, bar1)) not in pairs


def test_candidate_pairs_all_blank_bucket_key_skipped(matching_db):
    conn, vid = matching_db
    # No executable_name at all -> blank bucket key -> not blockable by buckets.
    a = _insert_atom(conn, vid, "binaries", "alpha-x", {})
    b = _insert_atom(conn, vid, "binaries", "beta-y", {})
    pairs = candidate_pairs(
        conn, "binaries", blocking_keys=["executable_name"], fts=False
    )
    assert (min(a, b), max(a, b)) not in pairs
    assert pairs == set()


def test_candidate_pairs_fts_token_overlap(matching_db):
    conn, vid = matching_db
    # Source keys share the token "common"; different executable_name so buckets
    # will NOT pair them — only FTS should.
    a = _insert_atom(conn, vid, "binaries", "alpha-common", {"executable_name": "alpha"})
    b = _insert_atom(conn, vid, "binaries", "beta-common", {"executable_name": "beta"})

    pair = (min(a, b), max(a, b))

    # Buckets alone (fts=False) do not connect them.
    assert pair not in candidate_pairs(
        conn, "binaries", blocking_keys=["executable_name"], fts=False
    )
    # With FTS enabled, the shared "common" token makes them candidates.
    assert pair in candidate_pairs(
        conn, "binaries", blocking_keys=["executable_name"], fts=True
    )


def test_candidate_pairs_respects_max_bucket(matching_db, capsys):
    conn, vid = matching_db
    # Three atoms share the "dup" bucket; with max_bucket=2 the bucket is skipped.
    ids = [
        _insert_atom(conn, vid, "binaries", f"dup-{i}", {"executable_name": "dup"})
        for i in range(3)
    ]
    pairs = candidate_pairs(
        conn, "binaries", blocking_keys=["executable_name"], fts=False, max_bucket=2
    )

    # None of the intra-bucket pairs survive the cap.
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            assert (min(ids[i], ids[j]), max(ids[i], ids[j])) not in pairs

    # And a WARNING naming the bucket + size was printed to stderr (no silent cap).
    err = capsys.readouterr().err
    assert "WARNING" in err
    assert "max_bucket" in err


def test_candidate_pairs_degrades_without_atoms_fts(matching_db):
    conn, vid = matching_db
    foo1 = _insert_atom(conn, vid, "binaries", "foo-1", {"executable_name": "foo"})
    foo2 = _insert_atom(conn, vid, "binaries", "foo-2", {"executable_name": "foo"})

    # Drop the FTS index; the AFTER-INSERT/DELETE triggers won't fire since we
    # do not touch atoms again, so this leaves a queryable-but-fts-less DB.
    conn.execute("DROP TABLE atoms_fts")
    conn.commit()

    # fts=True must NOT raise — it degrades to buckets-only.
    pairs = candidate_pairs(
        conn, "binaries", blocking_keys=["executable_name"], fts=True
    )
    # The bucket path still works.
    assert (min(foo1, foo2), max(foo1, foo2)) in pairs
