"""The optional YAML configuration file (/etc/pydebuprep.conf by default)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import yaml

from pydebuprep import checks
from pydebuprep.checks.base import Option
from pydebuprep.model import CATEGORY_ORDER, Severity
from pydebuprep.render import FORMATS
from pydebuprep.snapshot import DEFAULT_SNAPSHOT_DIR

DEFAULT_CONFIG_PATH = "/etc/pydebuprep.conf"
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
    baseline: str = "auto"
    snapshot_dir: str = DEFAULT_SNAPSHOT_DIR


REPORT_HELP = {
    "format": f"Output format: {', '.join(FORMATS)}",
    "output_dir": "Write reports to timestamped files in this directory (null = standard output)",
    "min_severity": "Hide findings below this severity: info, warning, critical "
    "(the exit code still counts them)",
    "color": "Colorize text output when writing to a terminal",
    "baseline": "Snapshot to compare against: auto (newest in snapshot_dir), none, or a file path",
    "snapshot_dir": "Where snapshots are written and looked up",
}


@dataclass
class Config:
    report: ReportSettings = field(default_factory=ReportSettings)
    disabled: set[str] = field(default_factory=set)
    check_settings: dict[str, dict[str, Any]] = field(default_factory=dict)
    path: str | None = None

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
        elif key == "color":
            if not isinstance(value, bool):
                errors.append(f"{where}: expected true or false")
            else:
                settings.color = value
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
        if key not in ("report", "checks")
    ]
    report = _report_settings(data.get("report"), source, errors)
    disabled, check_settings = _check_settings(data.get("checks"), source, errors)
    if errors:
        raise ConfigError(errors)
    return Config(report, disabled, check_settings, source)


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
    return parse_config(text, target)


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
    plain = yaml.safe_load(text) == text and ": " not in text and not text.startswith("#")
    return text if plain else json.dumps(text)


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
