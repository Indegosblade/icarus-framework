"""ICARUS CLI — python -m icarus"""

import argparse
import sys
from pathlib import Path


def cmd_build(args):
    from icarus.core.pipeline import create_default_pipeline
    from icarus.parsers import detect_parser

    source = Path(args.source)
    if not source.exists():
        print(f"ERROR: Source path does not exist: {source}", file=sys.stderr)
        sys.exit(1)
    if not source.is_dir():
        print(f"ERROR: Source must be a directory: {source}", file=sys.stderr)
        sys.exit(1)

    parser_name = args.parser
    if parser_name is None:
        parser_name = detect_parser(source)
        if parser_name is None:
            print(
                "ERROR: Could not auto-detect source type. Specify --parser",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"[ICARUS] Auto-detected parser: {parser_name}")

    pipeline = create_default_pipeline(
        source=source,
        output=Path(args.output),
        parser_name=parser_name,
        skip_hygeia=args.skip_hygeia,
    )
    pipeline.run(resume=not args.fresh)


def cmd_query(args):
    from icarus.core.query import IcarusQuery
    with IcarusQuery(args.database) as q:
        if args.search:
            result = q.search(args.search, table=args.table)
        elif args.sql:
            result = q.execute(args.sql)
        elif args.stats:
            stats = q.stats()
            for table, count in stats.items():
                print(f"{table}: {count:,}")
            return
        else:
            print("Specify --sql, --search, or --stats", file=sys.stderr)
            sys.exit(1)
        print(result.to_markdown())


def cmd_diff(args):
    if args.stix:
        from icarus.integrations.stix_export import diff_to_stix
        bundle = diff_to_stix(Path(args.old), Path(args.new), Path(args.stix))
        print(f"STIX bundle written to {args.stix} ({len(bundle['objects'])} objects)")
        return

    from icarus.core.differ import IcarusDiffer
    with IcarusDiffer(args.old, args.new) as d:
        report = d.generate_report()
        if args.output:
            Path(args.output).write_text(report)
            print(f"Report written to {args.output}")
        else:
            print(report)


def cmd_parser(args):
    if args.parser_command == "validate":
        from icarus.parsers.manifest import validate_manifest
        manifest_path = Path(args.path)
        if not manifest_path.exists():
            print(f"ERROR: Manifest not found: {manifest_path}", file=sys.stderr)
            sys.exit(1)
        try:
            validate_manifest(manifest_path)
            print(f"PASS: {manifest_path}")
        except Exception as e:
            print(f"FAIL: {manifest_path}\n  {e}", file=sys.stderr)
            sys.exit(1)
    elif args.parser_command == "test":
        from icarus.parsers import get_parser
        from icarus.parsers.manifest import load_manifest
        from icarus.parsers.testing import ParserTestHarness
        parser_inst = get_parser(args.parser_name)
        parsers_dir = Path(__file__).parent / "parsers"
        manifest_path = parsers_dir / f"{args.parser_name}.yaml"
        if not manifest_path.exists():
            print(f"ERROR: No manifest for parser '{args.parser_name}'", file=sys.stderr)
            sys.exit(1)
        manifest = load_manifest(manifest_path)
        fixtures_dir = manifest.tests.get("fixtures_dir") if manifest.tests else None
        if not fixtures_dir:
            print("ERROR: No fixtures_dir in manifest", file=sys.stderr)
            sys.exit(1)
        fixtures_path = Path(fixtures_dir)
        if not fixtures_path.is_absolute():
            fixtures_path = Path(__file__).parent.parent / fixtures_dir
        print(f"Testing parser: {args.parser_name}")
        harness = ParserTestHarness(parser_inst, manifest, fixtures_path)
        results = harness.run_all()
        if not all(r.passed for r in results):
            sys.exit(1)
    elif args.parser_command == "list":
        from icarus.parsers import get_registry
        entries = get_registry().list_all()
        if not entries:
            print("No parsers registered.")
            return
        print(f"{'Name':<20} {'Tier':<12} {'Version':<10} {'Spec':<6} Description")
        print("-" * 80)
        for e in entries:
            print(
                f"{e['name']:<20} {e['tier']:<12} {e['version']:<10} "
                f"{e['specificity']:<6} {e['description']}"
            )
    else:
        print("Unknown parser command. Use: validate, list, test", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="icarus",
        description="ICARUS — Modular intelligence framework for structured data analysis",
    )
    sub = parser.add_subparsers(dest="command")

    # build
    build_p = sub.add_parser("build", help="Build an intelligence database from a data source")
    build_p.add_argument(
        "--source", "-s", required=True, help="Path to data source directory")
    build_p.add_argument("--output", "-o", required=True, help="Output database path")
    build_p.add_argument(
        "--parser", "-p", default=None,
        help="Parser to use: windows, linux (default: auto-detect)")
    build_p.add_argument(
        "--fresh", action="store_true", help="Ignore checkpoints, start from scratch")
    build_p.add_argument(
        "--skip-hygeia", action="store_true",
        help="Skip HYGEIA sanitization (output will contain raw unsanitized data)")

    # query
    query_p = sub.add_parser("query", help="Query an intelligence database")
    query_p.add_argument("database", help="Path to ICARUS database")
    query_p.add_argument("--sql", help="Raw SQL query")
    query_p.add_argument("--search", help="Full-text search query")
    query_p.add_argument("--table", default="files", help="Table for FTS search (default: files)")
    query_p.add_argument("--stats", action="store_true", help="Show table row counts")

    # diff
    diff_p = sub.add_parser("diff", help="Compare two intelligence databases")
    diff_p.add_argument("old", help="Path to older database")
    diff_p.add_argument("new", help="Path to newer database")
    diff_p.add_argument("--output", "-o", help="Write report to file (default: stdout)")
    diff_p.add_argument("--stix", help="Export diff as STIX 2.1 bundle JSON")

    # parser
    parser_p = sub.add_parser("parser", help="Parser management commands")
    parser_sub = parser_p.add_subparsers(dest="parser_command")
    validate_p = parser_sub.add_parser("validate", help="Validate a parser manifest")
    validate_p.add_argument("path", help="Path to parser.yaml manifest file")
    test_p = parser_sub.add_parser("test", help="Run parser test harness")
    test_p.add_argument("parser_name", help="Name of the parser to test")
    parser_sub.add_parser("list", help="List all registered parsers")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        {"build": cmd_build, "query": cmd_query, "diff": cmd_diff,
         "parser": cmd_parser}[args.command](args)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
