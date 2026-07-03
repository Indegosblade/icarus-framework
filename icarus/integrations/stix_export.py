"""ICARUS STIX 2.1 Export — transform ICARUS entities to STIX 2.1 bundles."""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


def _stix_id(prefix: str, seed: str) -> str:
    """Generate a deterministic STIX ID from a prefix and seed string."""
    h = hashlib.sha256(seed.encode()).hexdigest()[:32]
    return f"{prefix}--{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _stix_timestamp(observed: Optional[str] = None) -> str:
    """Return an RFC 3339 UTC timestamp for a STIX created/modified property.

    Derives the timestamp from ``observed`` (e.g. a row's observed_time /
    observed_at column) when given, normalizing it to end in 'Z' as STIX 2.1
    requires. Falls back to the current export time when no observed
    timestamp is available (observed_time is nullable and often unset).
    """
    if observed:
        ts = observed.strip().replace(" ", "T", 1)
        if ts.endswith("+00:00"):
            ts = ts[: -len("+00:00")]
        if not ts.endswith("Z"):
            ts += "Z"
        return ts
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


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
    ts = _stix_timestamp(row.get("observed_time"))
    return {
        "type": "infrastructure",
        "id": _stix_id("infrastructure", row["label"]),
        "spec_version": "2.1",
        "created": ts,
        "modified": ts,
        "name": row["label"],
        "infrastructure_types": ["hosting-target"],
        "x_icarus_program": row.get("program", ""),
        "x_icarus_user_name": row.get("user_name", ""),
    }


def _entitlement_to_sdo(row: dict) -> dict:
    """Map an entitlements row to a STIX course-of-action SDO."""
    ts = _stix_timestamp(row.get("observed_time"))
    return {
        "type": "course-of-action",
        "id": _stix_id("course-of-action", f"{row['key']}-{row['value']}"),
        "spec_version": "2.1",
        "created": ts,
        "modified": ts,
        "name": row["key"],
        "description": str(row["value"]),
    }


# STIX SCO/SDO type emitted for each entity_table an observation can
# reference, matching what that table's own mapper produces (_file_to_sco,
# _binary_to_sco, _daemon_to_sdo, _entitlement_to_sdo). Tables with no
# dedicated mapper fall back to a generic custom SCO type so object_refs
# always contains a validly-shaped STIX identifier.
_ENTITY_TABLE_STIX_TYPE = {
    "files": "file",
    "binaries": "file",
    "daemons": "infrastructure",
    "entitlements": "course-of-action",
}


def _entity_ref(entity_table: str, entity_id: int) -> str:
    """Build the STIX identifier of the entity an observation refers to."""
    sco_type = _ENTITY_TABLE_STIX_TYPE.get(
        entity_table, f"x-icarus-{entity_table.replace('_', '-')}"
    )
    return _stix_id(sco_type, f"{entity_table}-{entity_id}")


def _observation_to_sdo(row: dict) -> dict:
    """Map an observations row to a STIX observed-data SDO."""
    ts = _stix_timestamp(row.get("observed_at"))
    return {
        "type": "observed-data",
        "id": _stix_id(
            "observed-data",
            f"{row['entity_table']}-{row['entity_id']}-{row['observed_at']}",
        ),
        "spec_version": "2.1",
        "created": ts,
        "modified": ts,
        "first_observed": row["observed_at"],
        "last_observed": row["observed_at"],
        "number_observed": 1,
        "object_refs": [_entity_ref(row["entity_table"], row["entity_id"])],
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
            key_column = diff_result.key_column

            for item in diff_result.added:
                item_key = item.get(key_column, "?")
                objects.append({
                    "type": "note",
                    "id": _stix_id("note", f"added-{key}-{item_key}"),
                    "spec_version": "2.1",
                    "content": f"Added in {key}: {item_key}",
                    "x_icarus_diff_category": "addition",
                    "x_icarus_diff_table": key,
                })

            for item in diff_result.removed:
                item_key = item.get(key_column, "?")
                objects.append({
                    "type": "note",
                    "id": _stix_id("note", f"removed-{key}-{item_key}"),
                    "spec_version": "2.1",
                    "content": f"Removed from {key}: {item_key}",
                    "x_icarus_diff_category": "deletion",
                    "x_icarus_diff_table": key,
                })

            for item in diff_result.changed:
                item_key = item.get(key_column, "?")
                objects.append({
                    "type": "note",
                    "id": _stix_id("note", f"changed-{key}-{item_key}"),
                    "spec_version": "2.1",
                    "content": (
                        f"Changed in {key}: {item_key} "
                        f"({item.get('old_value', '?')} -> {item.get('new_value', '?')})"
                    ),
                    "x_icarus_diff_category": "property_change",
                    "x_icarus_diff_table": key,
                })

            for item in diff_result.structural:
                item_key = item.get(key_column, "?")
                objects.append({
                    "type": "note",
                    "id": _stix_id(
                        "note",
                        f"structural-{key}-{item.get('type', '')}-{item_key}",
                    ),
                    "spec_version": "2.1",
                    "content": item.get(
                        "description", f"Structural change in {key}: {item_key}"
                    ),
                    "x_icarus_diff_category": "structural",
                    "x_icarus_diff_table": key,
                })

    bundle = _make_bundle(objects)
    output_path.write_text(json.dumps(bundle, indent=2) + "\n")
    return bundle
