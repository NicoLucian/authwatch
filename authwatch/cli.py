"""Command line entry point: ``python -m authwatch.cli auth.log``."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .detect import SEVERITY_ORDER, run_all
from .parser import count_time_bases, parse_file
from .report import build_stats, render_console, render_json, render_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authwatch",
        description="Triage Linux authentication logs and report brute force, "
                    "password spraying and suspicious logins.",
        epilog="Example: python -m authwatch.cli data/sample_auth.log --format md",
    )
    parser.add_argument("logfile", help="auth.log / secure / journalctl export to analyse")
    parser.add_argument("--year", type=int, default=None,
                        help="year to assume for syslog lines that omit it (default: current)")
    parser.add_argument("--syslog-offset", type=float, default=None, metavar="HOURS",
                        help="UTC offset of the hosts writing syslog lines, e.g. -3 for Chile; "
                             "converts them to UTC so they share an axis with ISO timestamps")
    parser.add_argument("--threshold", type=int, default=5,
                        help="failed attempts needed to raise a brute-force finding (default: 5)")
    parser.add_argument("--window", type=int, default=10,
                        help="sliding window in minutes for brute-force detection (default: 10)")
    parser.add_argument("--spray-users", type=int, default=3,
                        help="distinct accounts needed to raise a spraying finding (default: 3)")
    parser.add_argument("--business-hours", default="7-20", metavar="START-END",
                        help="working window as START-END hours (default: 7-20)")
    parser.add_argument("--format", choices=("console", "md", "json"), default="console",
                        help="output format (default: console)")
    parser.add_argument("--out", default=None, help="write the report to this file")
    parser.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER), default=None,
                        help="hide findings below this severity")
    parser.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER) + ("none",), default="high",
                        help="exit with status 1 when a finding reaches this severity (default: high)")
    parser.add_argument("--version", action="version", version=f"authwatch {__version__}")
    return parser


def _parse_hours(value: str) -> tuple:
    try:
        start, end = value.split("-", 1)
        start_hour, end_hour = int(start), int(end)
    except (ValueError, AttributeError):
        raise SystemExit("--business-hours must look like 7-20")
    if not (0 <= start_hour < 24 and 0 <= end_hour <= 24):
        raise SystemExit("--business-hours hours must be between 0 and 24")
    return start_hour, end_hour


def _check_offset(value: float) -> float:
    if not -14 <= value <= 14:
        raise SystemExit("--syslog-offset must be between -14 and 14 hours")
    return value


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    start_hour, end_hour = _parse_hours(args.business_hours)
    syslog_offset = _check_offset(args.syslog_offset) if args.syslog_offset is not None else None

    try:
        with open(args.logfile, "r", encoding="utf-8", errors="replace") as handle:
            bases = count_time_bases(handle)
        events = parse_file(args.logfile, year=args.year, syslog_offset=syslog_offset)
    except FileNotFoundError:
        print(f"authwatch: file not found: {args.logfile}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"authwatch: cannot read {args.logfile}: {exc}", file=sys.stderr)
        return 2

    if bases["mixed"] and syslog_offset is None:
        print(
            "authwatch: warning: this file mixes ISO timestamps (normalised to UTC) with "
            f"syslog timestamps ({bases['syslog']} lines, host wall clock). Windows and "
            "off-hours results may be shifted. Pass --syslog-offset to declare the hosts' "
            "UTC offset.",
            file=sys.stderr,
        )

    findings = run_all(
        events,
        threshold=args.threshold,
        window_minutes=args.window,
        spray_users=args.spray_users,
        business_start=start_hour,
        business_end=end_hour,
    )

    if args.min_severity:
        ceiling = SEVERITY_ORDER[args.min_severity]
        findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 9) <= ceiling]

    stats = build_stats(events)

    if args.format == "console":
        report = render_console(findings, stats)
    elif args.format == "md":
        report = render_markdown(findings, stats, source=args.logfile)
    else:
        report = render_json(findings, stats)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(report + "\n")
        print(f"authwatch: report written to {args.out} "
              f"({len(findings)} findings, {stats['total']} events parsed)")
    else:
        print(report)

    if args.fail_on == "none" or not findings:
        return 0
    worst = min(SEVERITY_ORDER.get(f.severity, 9) for f in findings)
    return 1 if worst <= SEVERITY_ORDER[args.fail_on] else 0


if __name__ == "__main__":
    raise SystemExit(main())
