"""ICARUS CLI — python -m icarus"""

import argparse
import sys
from pathlib import Path


def cmd_build(args):
    from icarus.core.pipeline import create_default_pipeline
    pipeline = create_default_pipeline(
        source=Path(args.source),
        output=Path(args.output),
        parser_name=args.parser,
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
    from icarus.core.differ import IcarusDiffer
    with IcarusDiffer(args.old, args.new) as d:
        report = d.generate_report()
        if args.output:
            Path(args.output).write_text(report)
            print(f"Report written to {args.output}")
        else:
            print(report)


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
        "--parser", "-p", default="windows",
        help="Parser to use: windows, linux (default: windows)")
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

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    {"build": cmd_build, "query": cmd_query, "diff": cmd_diff}[args.command](args)


if __name__ == "__main__":
    main()
