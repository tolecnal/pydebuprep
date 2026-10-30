"""The optional YAML configuration file (/etc/pydebuprep.conf by default)."""

from __future__ import annotations

import json
import os
import re
import textwrap
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from pydebuprep import checks
from pydebuprep.checks.base import Option
from pydebuprep.deps import require_yaml
from pydebuprep.model import CATEGORY_ORDER, Severity
from pydebuprep.render import FORMATS
from pydebuprep.snapshot import DEFAULT_SNAPSHOT_DIR
from pydebuprep.state import DEFAULT_PENDING_DIR

DEFAULT_CONFIG_PATH = "/etc/pydebuprep.conf"
DEFAULT_TOKEN_FILE = "/etc/pydebuprep/token"  # nosec B105 - a path, not a token
SEVERITIES = tuple(s.value for s in reversed(Severity))  # info, warning, critical


class ConfigError(Exception):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("\n".join(errors))
        self.errors = errors


@dataclass
class ReportSettings:
    format: str = "text"
    output_dir: str | None = None
    min_severity: str = "info"
    color: bool = True
    todo: bool = False
    baseline: str = "auto"
    snapshot_dir: str = DEFAULT_SNAPSHOT_DIR


REPORT_HELP = {
    "format": f"Output format: {', '.join(FORMATS)}",
    "output_dir": "Write reports to timestamped files in this directory (null = standard output)",
    "min_severity": "Hide findings below this severity: info, warning, critical "
    "(the exit code still counts them)",
    "color": "Colorize text output when writing to a terminal",
    "todo": "Add a TODO checklist of what needs fixing at the end of each report",
    "baseline": "Snapshot to compare against: auto (newest in snapshot_dir), none, or a file path",
    "snapshot_dir": "Where snapshots are written and looked up",
}


@dataclass
class UploadSettings:
    url: str | None = None
    token_file: str = DEFAULT_TOKEN_FILE
    ca_file: str | None = None
    pending_dir: str | None = DEFAULT_PENDING_DIR


UPLOAD_HELP = {
    "url": "Portal to upload each report to, e.g. https://portal.example.com (null = don't upload)",
    # nosec B105 - help text, not a token
    "token_file": "File holding the upload token, readable by root only; the PYDEBUPREP_TOKEN "
    "environment variable takes precedence",
    "ca_file": "Extra CA certificates to trust for the portal, besides the system's "
    "(null = system CAs only)",
    "pending_dir": "Where reports that failed to upload are kept for `pydebuprep upload` "
    "(null = don't keep them)",
}


@dataclass
class Config:
    report: ReportSettings = field(default_factory=ReportSettings)
    disabled: set[str] = field(default_factory=set)
    check_settings: dict[str, dict[str, Any]] = field(default_factory=dict)
    path: str | None = None
    log_ignore: list[str] = field(default_factory=list)
    upload: UploadSettings = field(default_factory=UploadSettings)

    @classmethod
    def defaults(cls) -> Config:
        return cls()


def _report_settings(data: Any, source: str, errors: list[str]) -> ReportSettings:
    settings = ReportSettings()
    if data is None:
        return settings
    if not isinstance(data, dict):
        errors.append(f"{source}: report: expected a mapping")
        return settings
    for key, value in data.items():
        where = f"{source}: report.{key}"
        if key not in REPORT_HELP:
            errors.append(f"{source}: report: unknown key {key!r}")
        elif key == "format":
            if value not in FORMATS:
                errors.append(f"{where}: must be one of {', '.join(FORMATS)}")
            else:
                settings.format = value
        elif key == "min_severity":
            if value not in SEVERITIES:
                errors.append(f"{where}: must be one of {', '.join(SEVERITIES)}")
            else:
                settings.min_severity = value
        elif key in ("color", "todo"):
            if not isinstance(value, bool):
                errors.append(f"{where}: expected true or false")
            else:
                setattr(settings, key, value)
        elif key == "output_dir":
            if value is not None and not isinstance(value, str):
                errors.append(f"{where}: expected a directory path or null")
            else:
                settings.output_dir = value or None
        elif not isinstance(value, str) or not value:
            errors.append(f"{where}: expected a non-empty string")
        else:
            setattr(settings, key, value)
    return settings


def url_problem(url: Any) -> str | None:
    """Why URL can't be a portal URL, or None if it can."""
    expected = "expected an https:// or http:// URL"
    if not isinstance(url, str):
        return expected
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - raises ValueError for an invalid port
    except ValueError:
        return "invalid port"
    if parts.scheme not in ("https", "http") or not parts.hostname:
        return expected
    if parts.username is not None or parts.password is not None:
        return "must not contain a user name or password"
    if parts.query or parts.fragment or url.endswith(("?", "#")):
        return "must not have a query or fragment"
    return None


def _upload_settings(data: Any, source: str, errors: list[str]) -> UploadSettings:
    settings = UploadSettings()
    if data is None:
        return settings
    if not isinstance(data, dict):
        errors.append(f"{source}: upload: expected a mapping")
        return settings
    for key, value in data.items():
        where = f"{source}: upload.{key}"
        if key not in UPLOAD_HELP:
            errors.append(f"{source}: upload: unknown key {key!r}")
        elif key == "url":
            problem = None if value is None else url_problem(value)
            if problem:
                errors.append(f"{where}: {problem}")
            else:
                settings.url = value
        elif key == "token_file":
            if not isinstance(value, str) or not value:
                errors.append(f"{where}: expected a non-empty string")
            else:
                settings.token_file = value
        elif value is not None and (not isinstance(value, str) or not value):
            kind = "file" if key == "ca_file" else "directory"
            errors.append(f"{where}: expected a {kind} path or null")
        else:
            setattr(settings, key, value)
    return settings


def _check_settings(
    data: Any, source: str, errors: list[str]
) -> tuple[set[str], dict[str, dict[str, Any]]]:
    disabled: set[str] = set()
    settings: dict[str, dict[str, Any]] = {}
    if data is None:
        return disabled, settings
    if not isinstance(data, dict):
        errors.append(f"{source}: checks: expected a mapping")
        return disabled, settings
    known = {cls.id: cls for cls in checks.ALL_CHECKS}
    for check_id, values in data.items():
        if check_id not in known:
            errors.append(f"{source}: checks: unknown check: {check_id}")
            continue
        if values is None:
            continue
        if not isinstance(values, dict):
            errors.append(f"{source}: checks.{check_id}: expected a mapping")
            continue
        options = dict(values)
        if "enabled" in options:
            enabled = options.pop("enabled")
            if not isinstance(enabled, bool):
                errors.append(f"{source}: checks.{check_id}.enabled: expected true or false")
            elif not enabled:
                disabled.add(check_id)
        try:
            instance = known[check_id](options)
        except ValueError as exc:
            errors.append(f"{source}: {exc}")
            continue
        if options:
            settings[check_id] = {name: instance.opt(name) for name in options}
    return disabled, settings


def parse_config(text: str, source: str) -> Config:
    """Parse and validate a config file; ConfigError lists every problem found."""
    yaml = require_yaml()
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f"line {mark.line + 1}, column {mark.column + 1}: " if mark else ""
        problem = getattr(exc, "problem", None) or str(exc)
        raise ConfigError([f"{source}: {where}{problem}"]) from None
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError([f"{source}: expected a mapping with 'report' and 'checks' sections"])
    errors = [
        f"{source}: unknown top-level key {key!r}"
        for key in data
        if key not in ("report", "logs", "checks", "upload")
    ]
    report = _report_settings(data.get("report"), source, errors)
    log_ignore = _log_ignore(data.get("logs"), source, errors)
    disabled, check_settings = _check_settings(data.get("checks"), source, errors)
    upload = _upload_settings(data.get("upload"), source, errors)
    if errors:
        raise ConfigError(errors)
    return Config(report, disabled, check_settings, source, log_ignore, upload)


LOGS_HELP = (
    "Regular expressions for log messages to leave out of both journal-errors and "
    "dmesg-errors, matched against the message text. Kernel messages appear in both, so "
    "one pattern here covers them; use a check's own 'ignore' option for the rest."
)


def _log_ignore(data: Any, source: str, errors: list[str]) -> list[str]:
    if data is None:
        return []
    if not isinstance(data, dict):
        errors.append(f"{source}: logs: expected a mapping")
        return []
    errors.extend(f"{source}: logs: unknown key {key!r}" for key in data if key != "ignore")
    patterns = data.get("ignore") or []
    if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
        errors.append(f"{source}: logs.ignore: expected a list of regular expressions")
        return []
    for pattern in patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            errors.append(f"{source}: logs.ignore: invalid pattern {pattern!r}: {exc}")
    return list(patterns)


def load_config(path: str | None, *, default_path: str = DEFAULT_CONFIG_PATH) -> Config:
    """Load PATH, or the default file if it exists; built-in defaults otherwise."""
    explicit = path is not None
    target = path if path is not None else default_path
    try:
        with open(target, encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        if not explicit:
            return Config.defaults()
        raise ConfigError([f"cannot read config file {target}: file not found"]) from None
    except PermissionError:
        raise ConfigError(
            [
                f"cannot read config file {target}: permission denied "
                "(make it readable, run as root, or use --no-config)"
            ]
        ) from None
    except (OSError, UnicodeDecodeError) as exc:
        reason = getattr(exc, "strerror", None) or str(exc)
        raise ConfigError([f"cannot read config file {target}: {reason}"]) from None
    return _resolve_paths(parse_config(text, target), os.path.dirname(os.path.abspath(target)))


def _resolve_paths(config: Config, base: str) -> Config:
    """Relative paths in a config file are relative to the file, not the working directory."""

    def resolve(path: str) -> str:
        return path if os.path.isabs(path) else os.path.normpath(os.path.join(base, path))

    report = config.report
    if report.output_dir is not None:
        report.output_dir = resolve(report.output_dir)
    report.snapshot_dir = resolve(report.snapshot_dir)
    if report.baseline not in ("auto", "none"):
        report.baseline = resolve(report.baseline)
    upload = config.upload
    upload.token_file = resolve(upload.token_file)
    if upload.ca_file is not None:
        upload.ca_file = resolve(upload.ca_file)
    if upload.pending_dir is not None:
        upload.pending_dir = resolve(upload.pending_dir)
    return config


def _yaml_value(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(json.dumps(v) for v in value) + "]"
    text = str(value)
    return text if _plain_yaml_scalar(text) else json.dumps(text)


YAML_WORDS = {"null", "true", "false", "yes", "no", "on", "off", "y", "n", "~", ""}
PLAIN = re.compile(r"[A-Za-z_/][A-Za-z0-9_./@+-]*")


def _plain_yaml_scalar(text: str) -> bool:
    """Whether TEXT reads back as the same string when written unquoted in YAML."""
    return bool(PLAIN.fullmatch(text)) and text.lower() not in YAML_WORDS


def _option_lines(option: Option) -> list[str]:
    return [f"    # {option.help}", f"    {option.name}: {_yaml_value(option.default)}"]


def example_config() -> str:
    """A commented config file showing every setting at its default."""
    defaults = ReportSettings()
    lines = [
        "# pydebuprep configuration",
        "#",
        f"# Read from {DEFAULT_CONFIG_PATH} if it exists, or from the file given with --config.",
        "# Every value below is the built-in default; keep only what you change.",
        "# Command-line options override these settings. Check a file with:",
        "#   pydebuprep configtest --config FILE",
        "",
        "report:",
    ]
    for key, help_text in REPORT_HELP.items():
        lines += [f"  # {help_text}", f"  {key}: {_yaml_value(getattr(defaults, key))}"]
    lines += [
        "",
        *(f"# {line}" for line in textwrap.wrap(LOGS_HELP, 86, break_on_hyphens=False)),
        "logs:",
        "  ignore: []",
        "",
        "# Uploading each report to a pydebuprep portal. Off unless url is set.",
        "upload:",
    ]
    upload = UploadSettings()
    for key, help_text in UPLOAD_HELP.items():
        lines += [f"  # {help_text}", f"  {key}: {_yaml_value(getattr(upload, key))}"]
    lines += [
        "",
        "# One section per check. 'enabled: false' leaves a check out; the other keys are",
        "# that check's options. Override on the command line with",
        "#   --check-option CHECK.OPTION=VALUE",
        "checks:",
    ]
    order = {cat: i for i, cat in enumerate(CATEGORY_ORDER)}
    for cls in sorted(checks.ALL_CHECKS, key=lambda c: (order.get(c.category, 99), c.id)):
        notes = [cls.category]
        if cls.requires_root:
            notes.append("needs root")
        if cls.requires_commands:
            notes.append("uses " + ", ".join(cls.requires_commands))
        lines += [f"  # {cls.title} ({'; '.join(notes)})", f"  {cls.id}:", "    enabled: true"]
        for option in cls.options:
            lines += _option_lines(option)
    return "\n".join(lines) + "\n"
