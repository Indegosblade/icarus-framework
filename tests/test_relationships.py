"""Behavioral tests for daemon->binary relationship edges (audit finding #93).

These build the real scenario and assert the edge is created and the
escape-surface join returns rows — not that the function merely runs.
"""

import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from icarus.core.schema import initialize_database
from icarus.parsers.base import link_daemons_to_binaries
from icarus.parsers.linux import LinuxParser, _parse_execstart


def _fresh_db(tmp: Path) -> Path:
    db = tmp / "out.db"
    initialize_database(db)
    return db


def _seed(conn: sqlite3.Connection, file_path: str, daemon_program: str) -> None:
    """Insert one file + its binary + one daemon whose program is daemon_program."""
    conn.execute(
        "INSERT INTO files (path, filename, size) VALUES (?, ?, 0)",
        (file_path, file_path.rsplit("/", 1)[-1]),
    )
    fid = conn.execute("SELECT id FROM files WHERE path = ?", (file_path,)).fetchone()[0]
    conn.execute(
        "INSERT INTO binaries (file_id, executable_name) VALUES (?, ?)",
        (fid, file_path.rsplit("/", 1)[-1]),
    )
    conn.execute(
        "INSERT INTO daemons (label, plist_path, program) VALUES ('svc', '/x.service', ?)",
        (daemon_program,),
    )
    conn.commit()


def test_parse_execstart_extracts_executable():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "foo.service"
        p.write_text("[Unit]\nDescription=x\n[Service]\nExecStart=-/usr/sbin/foo --flag a b\n")
        assert _parse_execstart(p) == "/usr/sbin/foo"


def test_parse_execstart_missing_returns_empty():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "bar.service"
        p.write_text("[Unit]\nDescription=no exec here\n")
        assert _parse_execstart(p) == ""


def test_linker_creates_edge_and_view_join_works():
    with tempfile.TemporaryDirectory() as d:
        db = _fresh_db(Path(d))
        conn = sqlite3.connect(str(db))
        _seed(conn, "/usr/bin/foo", "/usr/bin/foo")
        n = link_daemons_to_binaries(conn)
        conn.commit()
        assert n == 1, "one daemon->binary edge expected"
        binary_id = conn.execute("SELECT binary_id FROM daemons WHERE label='svc'").fetchone()[0]
        assert binary_id is not None, "daemon must now point at its binary"
        joined = conn.execute(
            "SELECT COUNT(*) FROM daemons d JOIN binaries b ON d.binary_id = b.id"
        ).fetchone()[0]
        assert joined == 1, "the escape-surface style join must now return the row"
        conn.close()


def test_linker_no_match_leaves_edge_null():
    with tempfile.TemporaryDirectory() as d:
        db = _fresh_db(Path(d))
        conn = sqlite3.connect(str(db))
        _seed(conn, "/usr/bin/foo", "/usr/bin/DIFFERENT")  # program points nowhere
        n = link_daemons_to_binaries(conn)
        conn.commit()
        assert n == 0
        binary_id = conn.execute("SELECT binary_id FROM daemons WHERE label='svc'").fetchone()[0]
        assert binary_id is None, "no false edge when the executable isn't in the dump"
        conn.close()


def test_linux_end_to_end_daemon_linked_to_its_elf():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "usr" / "bin").mkdir(parents=True)
        # minimal ELF (magic is all the parser checks; header padded to 64 bytes)
        (root / "usr" / "bin" / "foo").write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 57)
        (root / "lib" / "systemd" / "system").mkdir(parents=True)
        (root / "lib" / "systemd" / "system" / "foo.service").write_text(
            "[Service]\nExecStart=/usr/bin/foo --serve\n"
        )
        db = root / "out.db"
        initialize_database(db)
        p = LinuxParser()
        p.extract_entities(root, db)
        stats = p.extract_relationships(root, db)

        conn = sqlite3.connect(str(db))
        program = conn.execute("SELECT program FROM daemons WHERE label='foo'").fetchone()
        assert program and program[0] == "/usr/bin/foo", "ExecStart must be parsed into program"
        assert stats["linked"] >= 1, "the systemd unit must link to its ELF"
        binary_id = conn.execute("SELECT binary_id FROM daemons WHERE label='foo'").fetchone()[0]
        assert binary_id is not None
        conn.close()


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS: {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {t.__name__} — {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
