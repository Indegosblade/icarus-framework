"""ICARUS STIX 2.1 Export — transform ICARUS entities to STIX 2.1 bundles."""

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import List, Optional


def _stix_id(prefix: str, seed: str) -> str:
    """Generate a deterministic STIX ID from a prefix and seed string."""
    h = hashlib.sha256(seed.encode()).hexdigest()[:32]
    return f"{prefix}--{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _make_bundle(objects: List[dict]) -> dict:
    return {
        "type": "bundle",
        "id": _stix_id("bundle", json.dumps(objects, sort_keys=True)),
        "spec_version": "2.1",
        "objects": objects,
    }


def _file_to_sco(row: dict) -> dict:
    """Map a files table row to a STIX file SCO."""
    obj = {
        "type": "file",
        "id": _stix_id("file", row["path"]),
        "spec_version": "2.1",
        "name": row.get("filename", ""),
    }
    if row.get("size"):
        obj["size"] = row["size"]
    if row.get("sha256"):
        obj["hashes"] = {"SHA-256": row["sha256"]}
    if row.get("file_type"):
        obj["x_icarus_file_type"] = row["file_type"]
    return obj


def _binary_to_sco(row: dict) -> dict:
    """Map a binaries table row to a STIX file SCO with extension."""
    obj = {
        "type": "file",
        "id": _stix_id("file", f"binary-{row['id']}"),
        "spec_version": "2.1",
        "name": row.get("executable_name", ""),
    }
    ext = {}
    if row.get("arch"):
        ext["arch"] = row["arch"]
    if row.get("bundle_id"):
        ext["bundle_id"] = row["bundle_id"]
    if ext:
        obj["x_icarus_binary"] = ext
    return obj


def _daemon_to_sdo(row: dict) -> dict:
    """Map a daemons table row to a STIX infrastructure SDO."""
    return {
        "type": "infrastructure",
        "id": _stix_id("infrastructure", row["label"]),
        "spec_version": "2.1",
        "name": row["label"],
        "infrastructure_types": ["hosting-target"],
        "x_icarus_program": row.get("program", ""),
        "x_icarus_user_name": row.get("user_name", ""),
    }


def _entitlement_to_sdo(row: dict) -> dict:
    """Map an entitlements row to a STIX course-of-action SDO."""
    return {
        "type": "course-of-action",
        "id": _stix_id("course-of-action", f"{row['key']}-{row['value']}"),
        "spec_version": "2.1",
        "name": row["key"],
        "description": str(row["value"]),
    }


def _observation_to_sdo(row: dict) -> dict:
    """Map an observations row to a STIX observed-data SDO."""
    return {
        "type": "observed-data",
        "id": _stix_id(
            "observed-data",
            f"{row['entity_table']}-{row['entity_id']}-{row['observed_at']}",
        ),
        "spec_version": "2.1",
        "first_observed": row["observed_at"],
        "last_observed": row["observed_at"],
        "number_observed": 1,
        "x_icarus_entity_table": row["entity_table"],
        "x_icarus_entity_id": row["entity_id"],
        "x_icarus_event_type": row.get("event_type", ""),
    }


def export_to_stix(
    db_path: Path,
    output_path: Path,
    include_tables: Optional[List[str]] = None,
) -> dict:
    """Export ICARUS database entities to a STIX 2.1 bundle JSON file."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    objects = []

    try:
        tables = include_tables or [
            "files", "binaries", "daemons", "entitlements", "observations",
        ]

        if "files" in tables:
            for row in conn.execute("SELECT * FROM files").fetchall():
                objects.append(_file_to_sco(dict(row)))

        if "binaries" in tables:
            try:
                for row in conn.execute("SELECT * FROM binaries").fetchall():
                    objects.append(_binary_to_sco(dict(row)))
            except sqlite3.OperationalError:
                pass

        if "daemons" in tables:
            try:
                for row in conn.execute("SELECT * FROM daemons").fetchall():
                    objects.append(_daemon_to_sdo(dict(row)))
            except sqlite3.OperationalError:
                pass

        if "entitlements" in tables:
            try:
                for row in conn.execute("SELECT * FROM entitlements").fetchall():
                    objects.append(_entitlement_to_sdo(dict(row)))
            except sqlite3.OperationalError:
                pass

        if "observations" in tables:
            try:
                for row in conn.execute("SELECT * FROM observations").fetchall():
                    objects.append(_observation_to_sdo(dict(row)))
            except sqlite3.OperationalError:
                pass
    finally:
        conn.close()

    bundle = _make_bundle(objects)
    output_path.write_text(json.dumps(bundle, indent=2) + "\n")
    return bundle


def diff_to_stix(
    old_db: Path, new_db: Path, output_path: Path
) -> dict:
    """Export a diff result as a STIX 2.1 bundle."""
    from icarus.core.differ import IcarusDiffer

    objects = []
    with IcarusDiffer(str(old_db), str(new_db)) as d:
        results = d.full_diff()

        for key, diff_result in results.items():
            if not hasattr(diff_result, "added"):
                continue
            for item in getattr(diff_result, "added", []):
                obj = {
                    "type": "note",
                    "id": _stix_id("note", f"added-{key}-{item}"),
                    "spec_version": "2.1",
                    "content": f"Added in {key}: {item}",
                    "x_icarus_diff_category": "addition",
                    "x_icarus_diff_table": key,
                }
                objects.append(obj)

            for item in getattr(diff_result, "removed", []):
                obj = {
                    "type": "note",
                    "id": _stix_id("note", f"removed-{key}-{item}"),
                    "spec_version": "2.1",
                    "content": f"Removed from {key}: {item}",
                    "x_icarus_diff_category": "deletion",
                    "x_icarus_diff_table": key,
                }
                objects.append(obj)

    bundle = _make_bundle(objects)
    output_path.write_text(json.dumps(bundle, indent=2) + "\n")
    return bundle
