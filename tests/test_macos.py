"""Tests for the macOS / iOS parser and Mach-O entitlement extraction."""

import plistlib
import sqlite3
import struct
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PARSERS_DIR = Path(__file__).parent.parent / "icarus" / "parsers"
GATES = ["test_golden_output", "test_schema_conformance", "test_idempotency", "test_zero_pii"]


def _harness():
    from icarus.parsers.macos import MacosParser
    from icarus.parsers.manifest import load_manifest
    from icarus.parsers.testing import ParserTestHarness

    manifest = load_manifest(PARSERS_DIR / "macos.yaml")
    return ParserTestHarness(MacosParser(), manifest, FIXTURES_DIR / "macos")


@pytest.mark.parametrize("gate", GATES)
def test_macos_harness(gate):
    result = getattr(_harness(), gate)()
    assert result.passed, f"{gate} failed: {result.message}"


def test_macos_detects_fixture():
    from icarus.parsers import detect_parser

    assert detect_parser(FIXTURES_DIR / "macos") == "macos"


# ── Mach-O code-signature entitlement extraction ──

def _build_signed_macho(entitlements: dict) -> bytes:
    """A minimal arm64 Mach-O carrying an embedded-entitlements code signature.

    Layout: mach_header_64 (32) + LC_CODE_SIGNATURE (16) + code-signature
    SuperBlob (big-endian) holding a single CSSLOT_ENTITLEMENTS blob.
    """
    xml = plistlib.dumps(entitlements)
    ent_blob = struct.pack(">II", 0xFADE7171, 8 + len(xml)) + xml
    body = struct.pack(">II", 5, 20) + ent_blob          # index: slot 5, blob at offset 20
    superblob = struct.pack(">III", 0xFADE0CC0, 12 + len(body), 1) + body
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 16, 0, 0)
    lc = struct.pack("<IIII", 0x1D, 16, 48, len(superblob))  # dataoff=48 = 32+16
    return header + lc + superblob


def test_macho_entitlement_extraction(tmp_path):
    from icarus.parsers.macho import is_macho_magic, macho_info

    ents = {
        "get-task-allow": True,
        "com.apple.security.iokit-user-client-class": ["FooUserClient"],
    }
    b = tmp_path / "sample"
    b.write_bytes(_build_signed_macho(ents))
    assert is_macho_magic(b.read_bytes()[:4])
    info = macho_info(b)
    assert info["arch"] == "arm64"
    assert info["entitlements"] == ents


def test_macho_info_ignores_non_macho(tmp_path):
    from icarus.parsers.macho import macho_info

    junk = tmp_path / "notmacho"
    junk.write_bytes(b"this is not a mach-o file")
    assert macho_info(junk) is None


def test_macos_end_to_end_with_binary(tmp_path):
    """Full parse of a mini rootfs with a signed Mach-O daemon program.

    Exercises binaries, entitlements, the daemon->binary relationship,
    normalized mach_services, and the attack-surface queries end to end.
    """
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database
    from icarus.parsers.macos import MacosParser

    root = tmp_path / "rootfs"
    (root / "System/Library/CoreServices").mkdir(parents=True)
    (root / "System/Library/LaunchDaemons").mkdir(parents=True)
    (root / "usr/libexec").mkdir(parents=True)
    with open(root / "System/Library/CoreServices/SystemVersion.plist", "wb") as f:
        plistlib.dump({"ProductVersion": "26.5"}, f)
    (root / "usr/libexec/testd").write_bytes(_build_signed_macho({
        "get-task-allow": True,
        "com.apple.security.iokit-user-client-class": ["TestUserClient"],
    }))
    with open(root / "System/Library/LaunchDaemons/com.test.testd.plist", "wb") as f:
        plistlib.dump({
            "Label": "com.test.testd", "Program": "/usr/libexec/testd",
            "MachServices": {"com.test.testd": True, "com.test.testd.aux": True},
            "UserName": "root", "RunAtLoad": True,
        }, f)

    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(root)})
    p = MacosParser()
    p.extract_entities(root, db)
    assert p.extract_relationships(root, db)["linked"] == 1

    conn = sqlite3.connect(str(db))
    try:
        assert conn.execute("SELECT COUNT(*) FROM binaries").fetchone()[0] == 1
        assert conn.execute("SELECT arch FROM binaries").fetchone()[0] == "arm64"
        assert conn.execute("SELECT COUNT(*) FROM entitlements").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM mach_services").fetchone()[0] == 2
        assert conn.execute(
            "SELECT binary_id FROM daemons WHERE label='com.test.testd'"
        ).fetchone()[0] is not None
    finally:
        conn.close()

    with IcarusQuery(str(db)) as q:
        owners = q.mach_service_owners("com.test.%")
        assert owners.count == 2
        assert all(row[1] == "com.test.testd" for row in owners.rows)

        surface = q.daemons_with_entitlement("com.apple.security.iokit-user-client-class")
        assert surface.count == 1
        assert surface.rows[0][0] == "com.test.testd"

        # unsandboxed daemon exposing Mach services with entitlements
        assert q.escape_surface().count == 1
