"""Command-line entry point."""

from __future__ import annotations

import argparse
import copy
import dataclasses
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydebuprep import __version__, checks
from pydebuprep.checks.base import Check, CommandFailed, Context, running_kernel
from pydebuprep.config import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_TOKEN_FILE,
    Config,
    ConfigError,
    UploadSettings,
    example_config,
    load_config,
)
from pydebuprep.deps import MissingDependency
from pydebuprep.model import (
    CATEGORY_ORDER,
    CheckResult,
    ConfigInfo,
    Host,
    Report,
    Severity,
    compute_summary,
)
from pydebuprep.osinfo import detect_os
from pydebuprep.portal import CA_FILE_ENV, Connection, PortalError, read_token, upload_report
from pydebuprep.remote_config import is_url, load_remote_config
from pydebuprep.render import EXTENSIONS, FORMATS, render
from pydebuprep.reportfile import ReportFileError, load_report
from pydebuprep.runner import run_checks
from pydebuprep.snapshot import (
    DEFAULT_SNAPSHOT_DIR,
    SnapshotError,
    baseline_info,
    baseline_warnings,
    create_snapshot,
    find_latest,
    format_timestamp,
    load_snapshot,
)
from pydebuprep.state import (
    UNSAFE_IN_FILE_NAME,
    StateError,
    pending_reports,
    remove_pending,
    save_pending,
    state_dir,
)
from pydebuprep.system import System

EXIT_TOOL_ERROR = 3
COMMANDS = (
    "report",
    "convert",
    "upload",
    "snapshot",
    "list-checks",
    "configtest",
    "example-config",
    "completion",
)
CONFIG_ENV = "PYDEBUPREP_CONFIG"


class ToolError(Exception):
    pass


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _add_config_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--config",
        "-c",
        metavar="FILE",
        help=f"read settings from FILE (default: {DEFAULT_CONFIG_PATH} if it exists)",
    )
    group.add_argument("--no-config", action="store_true", help="ignore any config file")


def _add_check_option_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--check-option",
        action="append",
        default=[],
        metavar="CHECK.OPTION=VALUE",
        help="set a check option, overriding the config file (repeatable)",
    )


def _add_portal_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help="allow http:// portal URLs (the token is sent unencrypted; for test setups)",
    )
    parser.add_argument(
        "--ca-file",
        metavar="FILE",
        help=f"extra CA certificates to trust for the portal (default: ${CA_FILE_ENV}, "
        "then upload: ca_file:)",
    )
    parser.add_argument(
        "--token-file",
        metavar="FILE",
        help="file holding the portal token (default: upload: token_file:, "
        "/etc/pydebuprep/token); $PYDEBUPREP_TOKEN takes precedence",
    )


def _add_output_args(parser: argparse.ArgumentParser) -> None:
    out = parser.add_mutually_exclusive_group()
    out.add_argument(
        "--output-dir",
        metavar="DIR",
        help="write the report to a timestamped file in DIR instead of stdout",
    )
    out.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="write the report to FILE (a timestamp is added if FILE exists); "
        "'-' means standard output, overriding a configured output_dir",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pydebuprep",
        description="Read-only health report for Debian and Ubuntu systems after a release "
        "upgrade. Makes no changes; prints remediation steps instead.",
    )
    parser.add_argument("--version", action="version", version=f"pydebuprep {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    report = sub.add_parser("report", help="run all checks and print a report (default)")
    report.add_argument("--format", "-f", choices=FORMATS, help="output format (default: text)")
    _add_output_args(report)
    base = report.add_mutually_exclusive_group()
    base.add_argument("--baseline", metavar="FILE", help="compare against this snapshot")
    base.add_argument(
        "--no-baseline", action="store_true", help="do not compare against any snapshot"
    )
    report.add_argument(
        "--snapshot-dir",
        metavar="DIR",
        help=f"where to look for the newest snapshot (default: {DEFAULT_SNAPSHOT_DIR})",
    )
    report.add_argument("--checks", type=_csv, metavar="ID,...", help="run only these checks")
    report.add_argument(
        "--skip", type=_csv, default=[], metavar="ID,...", help="do not run these checks"
    )
    report.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity][::-1],
        help="hide findings below this severity (default: info; exit code still counts them)",
    )
    report.add_argument("--no-color", action="store_true", help="never colorize text output")
    report.add_argument(
        "--todo",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="add a TODO checklist of what needs fixing at the end of the report",
    )
    _add_check_option_arg(report)
    _add_config_args(report)
    _add_portal_args(report)

    conv = sub.add_parser("convert", help="render a saved JSON or YAML report in another format")
    conv.add_argument(
        "report",
        metavar="FILE",
        help="a report written with --format json or --format yaml; '-' reads standard input",
    )
    conv.add_argument("--format", "-f", choices=FORMATS, help="output format (default: text)")
    _add_output_args(conv)
    conv.add_argument("--no-color", action="store_true", help="never colorize text output")
    conv.add_argument(
        "--todo",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="add a TODO checklist of what needs fixing at the end of the report",
    )

    snap = sub.add_parser("snapshot", help="record a pre-upgrade baseline")
    snap.add_argument(
        "--snapshot-dir",
        metavar="DIR",
        help=f"where to store the snapshot (default: {DEFAULT_SNAPSHOT_DIR})",
    )
    _add_check_option_arg(snap)
    _add_config_args(snap)
    _add_portal_args(snap)

    listing = sub.add_parser("list-checks", help="list available checks")
    listing.add_argument(
        "--verbose", "-v", action="store_true", help="also show each check's options"
    )

    test = sub.add_parser("configtest", help="validate the config file and exit")
    _add_config_args(test)
    _add_portal_args(test)

    up = sub.add_parser(
        "upload",
        help="send saved JSON or YAML reports to the portal (default: those kept "
        "after a failed upload)",
    )
    up.add_argument(
        "files",
        nargs="*",
        metavar="FILE",
        help="reports to send (default: every report in upload: pending_dir:)",
    )
    _add_config_args(up)
    _add_portal_args(up)

    sub.add_parser("example-config", help="print an example config file with all defaults")

    comp = sub.add_parser("completion", help="print a shell completion script")
    comp.add_argument("shell", choices=("bash", "zsh"), help="shell to generate for")
    return parser


def _with_default_command(argv: list[str]) -> list[str]:
    if argv and (argv[0] in COMMANDS or argv[0] in ("-h", "--help", "--version")):
        return argv
    return ["report", *argv]


def _stdout_is_tty() -> bool:
    return sys.stdout.isatty()


def use_color(no_color_flag: bool, configured: bool = True) -> bool:
    return configured and not no_color_flag and "NO_COLOR" not in os.environ and _stdout_is_tty()


def default_config_path() -> str:
    return os.environ.get(CONFIG_ENV) or DEFAULT_CONFIG_PATH


def _load_config(args: argparse.Namespace) -> tuple[Config, ConfigInfo | None]:
    """The config, and where it came from when that was a URL."""
    if args.no_config:
        return Config.defaults(), None
    # A path named on the command line or in the environment must exist; only the
    # built-in default location is optional.
    explicit = args.config or os.environ.get(CONFIG_ENV) or None
    if explicit and is_url(explicit):
        # The config isn't loaded yet, so its upload settings can't apply to fetching it.
        return load_remote_config(
            explicit,
            token_file=args.token_file or DEFAULT_TOKEN_FILE,
            conn=connection(args, UploadSettings()),
            cache_dir=os.path.join(state_dir(), "configs"),
            now=datetime.now(timezone.utc),
            warn=_warn,
        )
    return load_config(explicit, default_path=DEFAULT_CONFIG_PATH), None


def _check_settings(args: argparse.Namespace, config: Config) -> dict[str, dict[str, Any]]:
    settings = copy.deepcopy(config.check_settings)
    known = {cls.id: {o.name: o for o in cls.options} for cls in checks.ALL_CHECKS}
    from_cli: dict[tuple[str, str], list[Any]] = {}
    for text in args.check_option:
        check_id, name, value = checks.parse_check_option(text)
        option = known.get(check_id, {}).get(name)
        if option is not None and isinstance(option.default, list):
            # Repeating a list option adds to it; the command line replaces the config value.
            # (A string always coerces to a list, so this cannot fail.)
            from_cli.setdefault((check_id, name), []).extend(option.coerce(value))
        else:
            settings.setdefault(check_id, {})[name] = value
    for (check_id, name), items in from_cli.items():
        settings.setdefault(check_id, {})[name] = items
    checks.get_checks(settings=settings)  # validate every setting, used or not
    return settings


def _select_checks(args: argparse.Namespace, config: Config) -> list[Check]:
    settings = _check_settings(args, config)
    skip = list(args.skip)
    if not args.checks:
        skip += sorted(config.disabled - set(skip))
    return checks.get_checks(args.checks, skip, settings)


def _ensure_writable_dir(directory: Path, what: str) -> None:
    if not directory.is_dir():
        raise ToolError(f"{what} {directory} does not exist")
    if not os.access(directory, os.W_OK):
        raise ToolError(f"{what} {directory} is not writable")


def resolve_output_path(
    output: str | None, output_dir: str | None, hostname: str, fmt: str, now: datetime
) -> Path | None:
    stamp = format_timestamp(now)
    if output_dir is not None:
        # Reports read back by `convert` may come from other hosts: keep the name plain.
        host = UNSAFE_IN_FILE_NAME.sub("_", hostname)
        return Path(output_dir) / f"pydebuprep-{host}-{stamp}.{EXTENSIONS[fmt]}"
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


def _load_baseline(
    args: argparse.Namespace, config: Config, snapshot_dir: str
) -> tuple[str, dict[str, Any]] | None:
    if args.no_baseline:
        return None
    choice = args.baseline or config.report.baseline
    if choice == "none":
        return None
    if choice == "auto":
        return find_latest(snapshot_dir)
    return choice, load_snapshot(choice)


def _write(text: str, path: Path) -> None:
    try:
        with open(path, "x", encoding="utf-8", errors="replace") as fh:
            fh.write(text)
    except OSError as exc:
        raise ToolError(f"cannot write {path}: {exc.strerror or exc}") from exc


def _print(text: str) -> None:
    """Write to stdout; a reader that went away (`| head`) is not an error."""
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except BrokenPipeError:
        # Point stdout at /dev/null so the interpreter's final flush doesn't raise again.
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except (OSError, ValueError):
            pass


def cmd_report(args: argparse.Namespace, system: System) -> int:
    config, source = _load_config(args)
    fmt = args.format or config.report.format
    min_severity = args.min_severity or config.report.min_severity
    snapshot_dir = args.snapshot_dir or config.report.snapshot_dir
    to_stdout = args.output == "-"
    output = None if to_stdout else args.output
    output_dir = None if (to_stdout or output) else (args.output_dir or config.report.output_dir)
    selected = _select_checks(args, config)
    if output_dir is not None:
        _ensure_writable_dir(Path(output_dir), "output directory")
    elif output:
        _ensure_writable_dir(Path(output).parent, "output directory")
    osinfo = detect_os(system)
    loaded = _load_baseline(args, config, snapshot_dir)
    if loaded and "os-release" not in {c.id for c in selected}:
        # os-release reports these itself; repeat them only when it isn't running.
        for warning in baseline_warnings(loaded[1], system.hostname(), osinfo.codename):
            print(f"pydebuprep: warning: {warning}", file=sys.stderr)
    ctx = Context(system, osinfo, loaded[1] if loaded else None, tuple(config.log_ignore))
    results = run_checks(selected, ctx)
    summary = compute_summary(results)
    try:
        kernel = running_kernel(ctx)
    except CommandFailed:
        kernel = "unknown"
    host = Host(
        hostname=system.hostname(),
        os_id=osinfo.id,
        os_version=osinfo.version_id,
        codename=osinfo.codename,
        kernel=kernel,
        is_root=system.is_root(),
    )
    now = system.now()
    report = Report(
        tool={"name": "pydebuprep", "version": __version__},
        generated_at=now.isoformat(timespec="seconds"),
        host=host,
        baseline=baseline_info(*loaded) if loaded else None,
        summary=summary,
        results=_filter_for_display(results, Severity(min_severity)),
        config=source,
    )
    path = resolve_output_path(output, output_dir, host.hostname, fmt, now)
    todo = config.report.todo if args.todo is None else args.todo
    _write_or_print(report, fmt, path, use_color(args.no_color, config.report.color), todo)
    if config.upload.url:
        # The portal gets every finding: --min-severity only shapes the local output.
        full = dataclasses.replace(report, results=results)
        _upload_after_report(full, config.upload.url, args, config.upload)
    return summary.exit_code


def connection(args: argparse.Namespace, settings: UploadSettings) -> Connection:
    ca_file = args.ca_file or os.environ.get(CA_FILE_ENV) or settings.ca_file
    return Connection(allow_http=args.allow_http, ca_file=ca_file)


def token_file(args: argparse.Namespace, settings: UploadSettings) -> str:
    return str(args.token_file or settings.token_file)


def _warn(message: str) -> None:
    print(f"pydebuprep: warning: {message}", file=sys.stderr)


def _upload_after_report(
    report: Report, url: str, args: argparse.Namespace, settings: UploadSettings
) -> None:
    """Upload the report; on failure keep it for `pydebuprep upload`. Never fails the run."""
    body = render(report, "json").encode()
    try:
        token = read_token(token_file(args, settings), os.environ)
        where = upload_report(url, token, connection(args, settings), body)
    except PortalError as exc:
        _warn(f"upload failed: {exc}")
        if settings.pending_dir is None:
            _warn("the report was not kept (upload: pending_dir is null)")
            return
        try:
            kept = save_pending(
                settings.pending_dir, body, report.host.hostname, report.generated_at
            )
        except StateError as exc:
            _warn(f"could not keep it: {exc}")
            return
        print(f"pydebuprep: kept for `pydebuprep upload`: {kept}", file=sys.stderr)
        return
    print(f"Report uploaded to {where}", file=sys.stderr)


def _upload_body(path: str) -> bytes:
    """A saved report as JSON: JSON files as they are, YAML converted."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise ToolError(f"{path}: {exc.strerror or exc}") from None
    try:
        report = load_report(data.decode("utf-8"))
    except UnicodeDecodeError:
        raise ToolError(f"{path}: not a UTF-8 text file") from None
    except ReportFileError as exc:
        raise ToolError(f"{path}: {exc}") from None
    return data if data.lstrip().startswith(b"{") else render(report, "json").encode()


def cmd_upload(args: argparse.Namespace) -> int:
    settings = _load_config(args)[0].upload
    if not settings.url:
        raise ToolError("no upload URL configured (upload: url: in the config file)")
    pending_dir = settings.pending_dir
    files = list(args.files) or (pending_reports(pending_dir) if pending_dir else [])
    if not files:
        print("Nothing to upload")
        return 0
    try:
        token = read_token(token_file(args, settings), os.environ)
    except PortalError as exc:
        raise ToolError(str(exc)) from None
    conn = connection(args, settings)
    failed = 0
    for path in files:
        try:
            where = upload_report(settings.url, token, conn, _upload_body(path))
        except ToolError as exc:
            print(f"pydebuprep: error: {exc}", file=sys.stderr)
            failed += 1
            continue
        except PortalError as exc:
            print(f"pydebuprep: error: {path}: upload failed: {exc}", file=sys.stderr)
            failed += 1
            continue
        print(f"{path}: uploaded to {where}")
        # Only reports kept after a failed upload are removed, never the user's own files.
        if pending_dir and os.path.dirname(os.path.abspath(path)) == os.path.abspath(pending_dir):
            remove_pending(path)
    return EXIT_TOOL_ERROR if failed else 0


def _write_or_print(
    report: Report, fmt: str, path: Path | None, color: bool, todo: bool = False
) -> None:
    if path is None:
        _print(render(report, fmt, color=color, todo=todo))
    else:
        _write(render(report, fmt, todo=todo), path)
        print(f"Report written to {path}", file=sys.stderr)


def cmd_convert(args: argparse.Namespace) -> int:
    source = args.report
    try:
        if source == "-":
            text = sys.stdin.read()
        else:
            with open(source, encoding="utf-8") as fh:
                text = fh.read()
    except OSError as exc:
        raise ToolError(f"cannot read {source}: {exc.strerror or exc}") from exc
    except UnicodeDecodeError:
        raise ToolError(f"{source}: not a UTF-8 text file") from None
    try:
        report = load_report(text)
    except ReportFileError as exc:
        raise ToolError(f"{source}: {exc}") from None
    fmt = args.format or "text"
    to_stdout = args.output == "-"
    output = None if to_stdout else args.output
    output_dir = None if to_stdout else args.output_dir
    if output_dir is not None:
        _ensure_writable_dir(Path(output_dir), "output directory")
    elif output:
        _ensure_writable_dir(Path(output).parent, "output directory")
    when = datetime.fromisoformat(report.generated_at).astimezone(timezone.utc)
    path = resolve_output_path(output, output_dir, report.host.hostname, fmt, when)
    _write_or_print(report, fmt, path, use_color(args.no_color), bool(args.todo))
    return 0


def cmd_snapshot(args: argparse.Namespace, system: System) -> int:
    config, _ = _load_config(args)
    selected = checks.get_checks(
        skip=sorted(config.disabled), settings=_check_settings(args, config)
    )
    ctx = Context(system, detect_os(system))
    path = create_snapshot(selected, ctx, args.snapshot_dir or config.report.snapshot_dir)
    print(path)
    return 0


def cmd_list_checks(verbose: bool) -> int:
    order = {cat: i for i, cat in enumerate(CATEGORY_ORDER)}
    for check in sorted(checks.get_checks(), key=lambda c: (order.get(c.category, 99), c.id)):
        notes = []
        if check.requires_root:
            notes.append("root")
        if check.supports_baseline:
            notes.append("baseline")
        suffix = f" [{', '.join(notes)}]" if notes else ""
        print(f"{check.id:<20} {check.category:<9} {check.title}{suffix}")
        if verbose:
            for option in check.options:
                print(f"    {option.name} = {_show(option.default)}  ({option.help})")
    return 0


def _show(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ",".join(str(v) for v in value) or "(empty)"
    return str(value)


def cmd_configtest(args: argparse.Namespace) -> int:
    if args.no_config:
        print("Config file ignored (--no-config); built-in defaults apply")
    else:
        config, source = _load_config(args)
        if source is not None and source.stale:
            print(
                f"Using the copy of {source.source} fetched on {source.fetched_at} "
                "(the portal could not be reached)"
            )
        elif source is not None:
            print(f"Using {source.source} (fetched now)")
        elif config.path is None:
            print(f"Config file {default_config_path()} not found; built-in defaults apply")
        else:
            print(f"Using {config.path}")
    print("Syntax OK")
    return 0


def main(argv: list[str] | None = None, *, system: System | None = None) -> int:
    args_list = _with_default_command(list(sys.argv[1:] if argv is None else argv))
    try:
        args = build_parser().parse_args(args_list)
    except SystemExit as exc:
        return 0 if exc.code in (0, None) else EXIT_TOOL_ERROR
    system = system or System()
    try:
        if args.command == "convert":
            return cmd_convert(args)
        if args.command == "upload":
            return cmd_upload(args)
        if args.command == "snapshot":
            return cmd_snapshot(args, system)
        if args.command == "list-checks":
            return cmd_list_checks(args.verbose)
        if args.command == "configtest":
            return cmd_configtest(args)
        if args.command == "example-config":
            _print(example_config())
            return 0
        if args.command == "completion":
            from pydebuprep.completion import bash_completion, zsh_completion

            _print(bash_completion() if args.shell == "bash" else zsh_completion())
            return 0
        return cmd_report(args, system)
    except MissingDependency as exc:
        print(f"pydebuprep: error: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR
    except ConfigError as exc:
        for error in exc.errors:
            print(f"pydebuprep: config error: {error}", file=sys.stderr)
        return EXIT_TOOL_ERROR
    except (ToolError, SnapshotError, ValueError) as exc:
        print(f"pydebuprep: error: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR
    except KeyboardInterrupt:
        return 130
