"""
ICARUS iOS Quick Start — Process an iOS rootfs into an intelligence database.

Usage:
    python examples/ios_quickstart.py --rootfs /path/to/rootfs --output intel.db
"""

import argparse
from pathlib import Path

from icarus.core.pipeline import Pipeline
from icarus.core.schema import initialize_database
from icarus.integrations.hygeia import sanitize_output, verify_clean
from icarus.parsers.ios import iOSParser


def main():
    parser = argparse.ArgumentParser(description="ICARUS iOS Pipeline")
    parser.add_argument("--rootfs", required=True, help="Path to extracted iOS rootfs")
    parser.add_argument("--output", required=True, help="Output database path")
    parser.add_argument("--skip-sanitize", action="store_true", help="Skip HYGEIA pass")
    args = parser.parse_args()

    source = Path(args.rootfs)
    output = Path(args.output)

    if not source.exists():
        print(f"Error: rootfs not found at {source}")
        return 1

    ios_parser = iOSParser()

    if not ios_parser.identify(source):
        print(f"Warning: {source} doesn't look like an iOS rootfs, proceeding anyway")

    pipeline = Pipeline(source, output, parser_name="ios")

    pipeline.add_phase("init", lambda ctx: initialize_database(ctx.output_db, {
        "source": str(ctx.source),
        "parser": ctx.parser_name,
    }), "Initialize database schema")

    pipeline.add_phase(
        "extract", lambda ctx: ios_parser.extract_entities(ctx.source, ctx.output_db),
        "Extract all entities from rootfs")

    pipeline.add_phase(
        "relationships",
        lambda ctx: ios_parser.extract_relationships(ctx.source, ctx.output_db),
        "Map entity relationships")

    pipeline.add_phase("verify", lambda ctx: ios_parser.verify(ctx.output_db),
                       "Quality gates")

    if not args.skip_sanitize:
        pipeline.add_phase("sanitize", lambda ctx: sanitize_output(ctx.output_db),
                           "HYGEIA PII removal")
        pipeline.add_phase("verify_clean", lambda ctx: verify_clean(ctx.output_db),
                           "Verify no PII remains")

    ctx = pipeline.run()

    print(f"\nDatabase: {output}")
    print(f"Stats: {ctx.stats}")
    return 0


if __name__ == "__main__":
    exit(main())
