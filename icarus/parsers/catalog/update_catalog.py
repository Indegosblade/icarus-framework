"""Regenerate parser catalog files from manifests.

Usage: python -m icarus.parsers.catalog.update_catalog
"""

import json
import sys
from pathlib import Path

from icarus.parsers.manifest import load_manifest

PARSERS_DIR = Path(__file__).parent.parent
CATALOG_DIR = Path(__file__).parent


def update():
    production = []
    devel = []

    for yaml_path in sorted(PARSERS_DIR.glob("**/*.yaml")):
        try:
            m = load_manifest(yaml_path)
        except Exception as e:
            print(f"SKIP {yaml_path.name}: {e}", file=sys.stderr)
            continue

        entry = {
            "parser_id": m.parser_id,
            "version": m.version,
            "quality_tier": m.quality_tier,
            "description": m.description,
            "specificity_level": m.specificity_level,
            "reliability": m.reliability,
            "entity_types": m.entity_types,
        }

        if m.quality_tier == "production":
            production.append(entry)
        elif m.quality_tier in ("candidate", "prototype"):
            devel.append(entry)

    (CATALOG_DIR / "parsers.json").write_text(
        json.dumps(production, indent=2) + "\n"
    )
    (CATALOG_DIR / "parsers-devel.json").write_text(
        json.dumps(devel, indent=2) + "\n"
    )
    print(f"Updated: {len(production)} production, {len(devel)} devel")


if __name__ == "__main__":
    update()
