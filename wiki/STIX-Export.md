# STIX 2.1 Export

ICARUS maps entities and diffs to STIX 2.1 objects for interoperability with threat intelligence platforms (MISP, OpenCTI, TAXII servers).

## Entity Mapping

| ICARUS Entity | STIX Object | STIX Type |
|--------------|-------------|-----------|
| files | File SCO | `file` |
| binaries | File SCO (with x_icarus_binary extension) | `file` |
| daemons | Infrastructure SDO | `infrastructure` |
| entitlements | Course of Action SDO | `course-of-action` |
| observations | Observed Data SDO | `observed-data` |

## Usage

### CLI

```bash
# Export a diff as STIX 2.1 bundle
icarus diff old.db new.db --stix changes.json
```

### Python API

```python
from icarus.integrations.stix_export import export_to_stix, diff_to_stix
from pathlib import Path

# Export all entities from a database
bundle = export_to_stix(
    db_path=Path("intel.db"),
    output_path=Path("entities.json"),
    include_tables=["files", "binaries", "daemons"],  # optional filter
)
print(f"Exported {len(bundle['objects'])} STIX objects")

# Export a diff as STIX bundle
bundle = diff_to_stix(
    old_db=Path("v1.db"),
    new_db=Path("v2.db"),
    output_path=Path("diff.json"),
)
```

## Bundle Format

Output is a standard STIX 2.1 bundle:

```json
{
  "type": "bundle",
  "id": "bundle--<deterministic-uuid>",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "file",
      "id": "file--<deterministic-uuid>",
      "spec_version": "2.1",
      "name": "example.exe",
      "size": 524288,
      "hashes": {"SHA-256": "abc123..."}
    }
  ]
}
```

IDs are deterministic — same input produces the same STIX IDs. This makes bundles diffable and deduplicable.

## Diff Export

Diffs export as STIX Note objects:

```json
{
  "type": "note",
  "id": "note--<deterministic-uuid>",
  "spec_version": "2.1",
  "content": "Added in daemons: new-service",
  "x_icarus_diff_category": "addition",
  "x_icarus_diff_table": "daemons"
}
```

Categories: `addition` and `deletion`.

## Custom Extensions

ICARUS-specific data uses `x_icarus_` prefixed properties:

| Extension | On | Contains |
|-----------|------|---------|
| `x_icarus_file_type` | File SCO | Parser-assigned file type |
| `x_icarus_binary` | File SCO | arch, bundle_id |
| `x_icarus_program` | Infrastructure SDO | Executable path |
| `x_icarus_user_name` | Infrastructure SDO | Run-as user |
| `x_icarus_entity_table` | Observed Data SDO | Source ontology table |
| `x_icarus_entity_id` | Observed Data SDO | Source entity row ID |
| `x_icarus_event_type` | Observed Data SDO | Observation event type |
| `x_icarus_diff_category` | Note SDO | addition or deletion |
| `x_icarus_diff_table` | Note SDO | Source diff table |
