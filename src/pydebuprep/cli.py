"""Command-line entry point."""

from __future__ import annotations

import argparse
import dataclasses
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from pydebuprep import __version__, checks
from pydebuprep.checks.base import Context
from pydebuprep.model import CheckResult, Host, Report, Severity, compute_summary
from pydebuprep.osinfo import detect_os
from pydebuprep.render import EXTENSIONS, FORMATS, render
from pydebuprep.runner import run_checks
from pydebuprep.snapshot import (
    DEFAULT_SNAPSHOT_DIR,
    SnapshotError,
    baseline_info,
    create_snapshot,
    find_latest,
    format_timestamp,
    load_snapshot,
    running_kernel,
)
from pydebuprep.system import System

EXIT_TOOL_ERROR = 3
COMMANDS = ("report", "snapshot", "list-checks")


class ToolError(Exception):
    pass


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pydebuprep",
        description="Read-only health report for Debian and Ubuntu systems after a release "
        "upgrade. Makes no changes; prints remediation steps instead.",
    )
    parser.add_argument("--version", action="version", version=f"pydebuprep {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    report = sub.add_parser("report", help="run all checks and print a report (default)")
    report.add_argument("--format", "-f", choices=FORMATS, default="text", help="output format")
    out = report.add_mutually_exclusive_group()
    out.add_argument(
        "--output-dir",
        metavar="DIR",
        help="write the report to a timestamped file in DIR instead of stdout",
    )
    out.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="write the report to FILE (a timestamp is added if FILE exists)",
    )
    base = report.add_mutually_exclusive_group()
    base.add_argument("--baseline", metavar="FILE", help="compare against this snapshot")
    base.add_argument(
        "--no-baseline", action="store_true", help="do not compare against any snapshot"
    )
    report.add_argument(
        "--snapshot-dir",
        metavar="DIR",
        default=DEFAULT_SNAPSHOT_DIR,
        help=f"where to look for the newest snapshot (default: {DEFAULT_SNAPSHOT_DIR})",
    )
    report.add_argument("--checks", type=_csv, metavar="ID,...", help="run only these checks")
    report.add_argument(
        "--skip", type=_csv, default=[], metavar="ID,...", help="do not run these checks"
    )
    report.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity][::-1],
        default="info",
        help="hide findings below this severity (exit code still counts them)",
    )
    report.add_argument("--no-color", action="store_true", help="never colorize text output")

    snap = sub.add_parser("snapshot", help="record a pre-upgrade baseline")
    snap.add_argument(
        "--snapshot-dir",
        metavar="DIR",
        default=DEFAULT_SNAPSHOT_DIR,
        help=f"where to store the snapshot (default: {DEFAULT_SNAPSHOT_DIR})",
    )

    sub.add_parser("list-checks", help="list available checks")
    return parser


def _with_default_command(argv: list[str]) -> list[str]:
    if argv and (argv[0] in COMMANDS or argv[0] in ("-h", "--help", "--version")):
        return argv
    return ["report", *argv]


def _stdout_is_tty() -> bool:
    return sys.stdout.isatty()


def use_color(no_color_flag: bool) -> bool:
    return not no_color_flag and "NO_COLOR" not in os.environ and _stdout_is_tty()


def resolve_output_path(
    output: str | None, output_dir: str | None, hostname: str, fmt: str, now: datetime
) -> Path | None:
    stamp = format_timestamp(now)
    if output_dir is not None:
        return Path(output_dir) / f"pydebuprep-{hostname}-{stamp}.{EXTENSIONS[fmt]}"
    if output is None:
        return None
    path = Path(output)
    if path.exists():
        return path.with_name(f"{path.stem}-{stamp}{path.suffix}")
    return path


def _filter_for_display(results: list[CheckResult], minimum: Severity) -> list[CheckResult]:
    def keep(findings: list[Any]) -> list[Any]:
        return [f for f in findings if f.severity.rank >= minimum.rank]

    return [
        dataclasses.replace(
            r,
            findings=keep(r.findings),
            baseline_diff=None if r.baseline_diff is None else keep(r.baseline_diff),
        )
        for r in results
    ]


def _load_baseline(args: argparse.Namespace) -> tuple[str, dict[str, Any]] | None:
    if args.no_baseline:
        return None
    if args.baseline:
        return args.baseline, load_snapshot(args.baseline)
    return find_latest(args.snapshot_dir)


def _write(text: str, path: Path) -> None:
    try:
        with open(path, "x", encoding="utf-8") as fh:
            fh.write(text)
    except OSError as exc:
        raise ToolError(f"cannot write {path}: {exc.strerror or exc}") from exc


def cmd_report(args: argparse.Namespace, system: System) -> int:
    selected = checks.get_checks(args.checks, args.skip)
    osinfo = detect_os(system)
    loaded = _load_baseline(args)
    ctx = Context(system, osinfo, loaded[1] if loaded else None)
    results = run_checks(selected, ctx)
    summary = compute_summary(results)
    host = Host(
        hostname=system.hostname(),
        os_id=osinfo.id,
        os_version=osinfo.version_id,
        codename=osinfo.codename,
        kernel=running_kernel(ctx),
        is_root=system.is_root(),
    )
    now = system.now()
    report = Report(
        tool={"name": "pydebuprep", "version": __version__},
        generated_at=now.isoformat(timespec="seconds"),
        host=host,
        baseline=baseline_info(*loaded) if loaded else None,
        summary=summary,
        results=_filter_for_display(results, Severity(args.min_severity)),
    )
    path = resolve_output_path(args.output, args.output_dir, host.hostname, args.format, now)
    if path is None:
        sys.stdout.write(render(report, args.format, color=use_color(args.no_color)))
    else:
        _write(render(report, args.format), path)
        print(f"Report written to {path}", file=sys.stderr)
    return summary.exit_code


def cmd_snapshot(args: argparse.Namespace, system: System) -> int:
    ctx = Context(system, detect_os(system))
    path = create_snapshot(checks.get_checks(), ctx, args.snapshot_dir)
    print(path)
    return 0


def cmd_list_checks() -> int:
    for check in sorted(checks.get_checks(), key=lambda c: (c.category, c.id)):
        notes = []
        if check.requires_root:
            notes.append("root")
        if check.supports_baseline:
            notes.append("baseline")
        suffix = f" [{', '.join(notes)}]" if notes else ""
        print(f"{check.id:<20} {check.category:<9} {check.title}{suffix}")
    return 0


def main(argv: list[str] | None = None, *, system: System | None = None) -> int:
    args_list = _with_default_command(list(sys.argv[1:] if argv is None else argv))
    try:
        args = build_parser().parse_args(args_list)
    except SystemExit as exc:
        return 0 if exc.code in (0, None) else EXIT_TOOL_ERROR
    system = system or System()
    try:
        if args.command == "snapshot":
            return cmd_snapshot(args, system)
        if args.command == "list-checks":
            return cmd_list_checks()
        return cmd_report(args, system)
    except (ToolError, SnapshotError, ValueError) as exc:
        print(f"pydebuprep: error: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR
    except KeyboardInterrupt:
        return 130
