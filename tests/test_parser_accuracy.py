"""Regression tests for issues #23, #24, #26, #28 — parser count accuracy and
correctness fixes across macos.py, linux.py, windows.py, and
generic/json_parser.py.
"""

import json
import plistlib
import shutil
import sqlite3
from pathlib import Path

from icarus.core.schema import initialize_database

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ── #26 — stats counters must not inflate on duplicate rows / re-runs ──


def test_macos_counts_not_inflated_on_rerun(tmp_path):
    """Re-running macos extract_entities against the same DB must report zero
    *new* daemons/kexts/frameworks/sandbox_profiles, even though every row was
    already present (issue #26 — these four counters used to increment
    unconditionally after INSERT OR IGNORE)."""
    from icarus.parsers.macos import MacosParser

    root = tmp_path / "rootfs"
    shutil.copytree(FIXTURES_DIR / "macos", root)

    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(root)})
    p = MacosParser()
    first = p.extract_entities(root, db)
    second = p.extract_entities(root, db)

    gated_keys = ("daemons", "kexts", "frameworks", "sandbox_profiles")
    for key in gated_keys:
        assert first[key] > 0, f"fixture produced no {key} on first run"
        assert second[key] == 0, f"{key} inflated on rerun: reported {second[key]} new rows"

    conn = sqlite3.connect(str(db))
    try:
        for table in gated_keys:
            row_count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608
            assert row_count == first[table], (
                f"{table} row count {row_count} != first-run reported count {first[table]}"
            )
    finally:
        conn.close()


def test_linux_counts_not_inflated_on_rerun(tmp_path):
    """Same as above for linux.py daemons + frameworks (issue #26)."""
    from icarus.parsers.linux import LinuxParser

    root = tmp_path / "rootfs"
    (root / "etc").mkdir(parents=True)
    (root / "lib" / "systemd" / "system").mkdir(parents=True)
    (root / "usr" / "lib").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    (root / "lib" / "systemd" / "system" / "test.service").write_text(
        "[Unit]\nDescription=Test\n[Service]\nExecStart=/usr/bin/test\n"
    )
    (root / "usr" / "lib" / "libfoo.so").write_bytes(b"\x7fELF" + b"\x00" * 32)

    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(root)})
    p = LinuxParser()
    first = p.extract_entities(root, db)
    second = p.extract_entities(root, db)

    assert first["daemons"] == 1
    assert first["frameworks"] == 1
    assert second["daemons"] == 0
    assert second["frameworks"] == 0

    conn = sqlite3.connect(str(db))
    try:
        assert conn.execute("SELECT COUNT(*) FROM daemons").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM frameworks").fetchone()[0] == 1
    finally:
        conn.close()


def test_windows_frameworks_count_not_inflated_on_rerun(tmp_path):
    """Same as above for windows.py frameworks (issue #26)."""
    from icarus.parsers.windows import WindowsParser

    root = tmp_path / "app"
    root.mkdir()
    (root / "helper.dll").write_bytes(b"MZ" + b"\x00" * 62)

    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(root)})
    p = WindowsParser()
    first = p.extract_entities(root, db)
    second = p.extract_entities(root, db)

    assert first["frameworks"] == 1
    assert second["frameworks"] == 0

    conn = sqlite3.connect(str(db))
    try:
        assert conn.execute("SELECT COUNT(*) FROM frameworks").fetchone()[0] == 1
    finally:
        conn.close()


# ── #24 — duplicate daemon Label must not misattribute MachServices ──


def test_macos_duplicate_label_skips_second_plists_services(tmp_path):
    """Two plists sharing a Label (one in LaunchDaemons, one in LaunchAgents):
    the second must NOT graft its MachServices onto the first daemon's id, and
    the reported daemon/mach_services counts must reflect only the surviving
    (first-seen) plist."""
    from icarus.parsers.macos import MacosParser

    root = tmp_path / "rootfs"
    (root / "System" / "Library" / "LaunchDaemons").mkdir(parents=True)
    (root / "System" / "Library" / "LaunchAgents").mkdir(parents=True)
    with open(root / "System/Library/LaunchDaemons/com.test.dup.plist", "wb") as f:
        plistlib.dump({
            "Label": "com.test.dup",
            "Program": "/usr/libexec/first",
            "MachServices": {"com.test.dup.first": True},
        }, f)
    with open(root / "System/Library/LaunchAgents/com.test.dup.plist", "wb") as f:
        plistlib.dump({
            "Label": "com.test.dup",
            "Program": "/usr/libexec/second",
            "MachServices": {"com.test.dup.second": True},
        }, f)

    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(root)})
    p = MacosParser()
    stats = p.extract_entities(root, db)

    assert stats["daemons"] == 1
    assert stats["mach_services"] == 1

    conn = sqlite3.connect(str(db))
    try:
        rows = conn.execute(
            "SELECT id, program FROM daemons WHERE label='com.test.dup'"
        ).fetchall()
        assert len(rows) == 1
        daemon_id, program = rows[0]
        # LaunchDaemons is walked before LaunchAgents (LAUNCHD_DIRS order),
        # so the first plist wins and keeps its own program + services.
        assert program == "/usr/libexec/first"

        services = [
            r[0] for r in conn.execute(
                "SELECT service_name FROM mach_services WHERE daemon_id=?",
                (daemon_id,),
            ).fetchall()
        ]
        assert services == ["com.test.dup.first"]
        assert "com.test.dup.second" not in services
    finally:
        conn.close()


# ── #23 — systemd unit detection must cover usr-merged and etc dirs ──


def test_linux_detects_units_in_usr_merged_and_etc_dirs(tmp_path):
    from icarus.parsers.linux import LinuxParser

    root = tmp_path / "rootfs"
    (root / "usr" / "lib" / "systemd" / "system").mkdir(parents=True)
    (root / "etc" / "systemd" / "system").mkdir(parents=True)
    (root / "usr/lib/systemd/system/merged.service").write_text(
        "[Unit]\nDescription=Merged\n[Service]\nExecStart=/usr/bin/merged\n"
    )
    (root / "etc/systemd/system/admin.service").write_text(
        "[Unit]\nDescription=Admin\n[Service]\nExecStart=/usr/bin/admin\n"
    )

    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(root)})
    p = LinuxParser()
    stats = p.extract_entities(root, db)

    assert stats["daemons"] == 2
    conn = sqlite3.connect(str(db))
    try:
        labels = {r[0] for r in conn.execute("SELECT label FROM daemons").fetchall()}
        assert labels == {"merged", "admin"}
    finally:
        conn.close()


# ── #28 — json_parser properties must be JSON; windows .dll needs PE magic ──


def test_json_parser_properties_is_valid_json(tmp_path):
    from icarus.parsers.generic.json_parser import JsonParser

    root = tmp_path / "src"
    root.mkdir()
    (root / "data.json").write_text(json.dumps({"zeta": 1, "alpha": 2, "mid": 3}))

    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(root)})
    p = JsonParser()
    p.extract_entities(root, db)

    conn = sqlite3.connect(str(db))
    try:
        props = conn.execute(
            "SELECT properties FROM observations WHERE event_type='json_keys'"
        ).fetchone()[0]
    finally:
        conn.close()

    parsed = json.loads(props)  # must not raise — was a comma-joined string before #28
    assert parsed == ["alpha", "mid", "zeta"]


def test_windows_non_pe_dll_not_recorded_as_framework(tmp_path):
    from icarus.parsers.windows import WindowsParser

    root = tmp_path / "app"
    root.mkdir()
    (root / "notreally.dll").write_bytes(b"this is not a PE file at all, just text padding")

    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(root)})
    p = WindowsParser()
    stats = p.extract_entities(root, db)

    assert stats["frameworks"] == 0
    conn = sqlite3.connect(str(db))
    try:
        assert conn.execute("SELECT COUNT(*) FROM frameworks").fetchone()[0] == 0
    finally:
        conn.close()


def test_windows_pe_dll_still_recorded_as_framework(tmp_path):
    """Sanity check alongside the negative case above: a real PE-magic .dll
    is still classified as a framework."""
    from icarus.parsers.windows import WindowsParser

    root = tmp_path / "app"
    root.mkdir()
    (root / "real.dll").write_bytes(b"MZ" + b"\x00" * 62)

    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(root)})
    p = WindowsParser()
    stats = p.extract_entities(root, db)

    assert stats["frameworks"] == 1
    conn = sqlite3.connect(str(db))
    try:
        assert conn.execute("SELECT COUNT(*) FROM frameworks").fetchone()[0] == 1
    finally:
        conn.close()


# ── #78 — identify() bounds its auto-detect probe, never full-walks ──


def test_windows_identify_true_when_pe_present(tmp_path):
    from icarus.parsers.windows import WindowsParser

    root = tmp_path / "app"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "tool.exe").write_bytes(b"MZ")
    assert WindowsParser().identify(root) is True


def test_windows_identify_false_without_pe(tmp_path):
    from icarus.parsers.windows import WindowsParser

    root = tmp_path / "docs"
    root.mkdir()
    for i in range(20):
        (root / f"note{i}.txt").write_text("x")
    assert WindowsParser().identify(root) is False


def test_windows_identify_is_bounded(tmp_path, monkeypatch):
    """The probe stops after its file budget instead of walking the whole tree
    — a .exe past the budget is not reached (documents the detection trade-off;
    extraction still walks everything)."""
    from icarus.parsers import windows as win

    monkeypatch.setattr(win, "_IDENTIFY_FILE_BUDGET", 10)
    monkeypatch.setattr(win, "_IDENTIFY_DIR_BUDGET", 1)

    root = tmp_path / "big"
    root.mkdir()
    for i in range(50):  # 50 non-PE files > budget of 10
        (root / f"f{i}.txt").write_text("x")
    (root / "deep.exe").write_bytes(b"MZ")  # PE exists but past the file budget

    # Bounded: returns False without inspecting the .exe beyond the budget.
    assert win.WindowsParser().identify(root) is False

    # Raise the budget above the file count and the same tree now detects.
    monkeypatch.setattr(win, "_IDENTIFY_FILE_BUDGET", 5000)
    assert win.WindowsParser().identify(root) is True
