"""MkDocs hooks: fill the generated parts of the documentation from pydebuprep's code.

Pages hold markers such as ``<!-- facts: disk-space -->``; each is replaced with
Markdown built from the check registry, the config schema or the CLI parser, so the
facts in the docs can't drift from the code. tests/test_docs_site.py tests this
module and checks every page against the registry.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pydebuprep import checks  # noqa: E402
from pydebuprep.checks.base import Check  # noqa: E402
from pydebuprep.cli import build_parser  # noqa: E402
from pydebuprep.completion import _help  # noqa: E402
from pydebuprep.config import (  # noqa: E402
    DEFAULT_CONFIG_PATH,
    LOGS_HELP,
    REPORT_HELP,
    ReportSettings,
    _yaml_value,
    example_config,
)
from pydebuprep.model import CATEGORY_ORDER  # noqa: E402

MARKER = re.compile(
    r"<!-- (facts|options|checks-index|config-reference|example-config|cli-reference)"
    r"(?:: ([a-z0-9-]+))? -->"
)
CATEGORY_TITLES = {
    "release": "Release",
    "packages": "Packages",
    "boot": "Boot",
    "services": "Services",
    "applications": "Applications",
    "network": "Network",
    "security": "Security",
    "storage": "Storage",
}


class DocsError(ValueError):
    pass


def check_classes() -> list[type[Check]]:
    """All checks in report order: by category, then id."""
    order = {cat: i for i, cat in enumerate(CATEGORY_ORDER)}
    return sorted(checks.ALL_CHECKS, key=lambda c: (order[c.category], c.id))


def _check(check_id: str) -> type[Check]:
    for cls in checks.ALL_CHECKS:
        if cls.id == check_id:
            return cls
    raise DocsError(f"no check with id {check_id!r}")


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _yes(flag: bool) -> str:
    return "yes" if flag else "no"


def facts(check_id: str) -> str:
    """The facts box at the top of a check page."""
    cls = _check(check_id)
    check = cls()
    commands = ", ".join(f"`{c}`" for c in cls.requires_commands) or "none"
    lines = [
        '!!! abstract "At a glance"',
        "",
        "    | | |",
        "    |---|---|",
        f"    | ID | `{cls.id}` |",
        f"    | Category | {CATEGORY_TITLES[cls.category]} |",
        f"    | Needs root | {_yes(cls.requires_root)} (skipped without it) |"
        if cls.requires_root
        else "    | Needs root | no |",
        f"    | Needs programs | {commands} |",
        f"    | Compares with a snapshot | {_yes(check.supports_baseline)} |",
        f"    | Options | {len(cls.options)} |",
        "",
    ]
    return "\n".join(lines)


def options(check_id: str) -> str:
    """The options section at the end of a check page."""
    cls = _check(check_id)
    lines: list[str] = []
    if cls.options:
        lines += ["## Options", "", "| Option | Default | Description |", "|---|---|---|"]
        for opt in cls.options:
            lines.append(
                f"| `{opt.name}` | `{_cell(_yaml_value(opt.default))}` | {_cell(opt.help)} |"
            )
        example = "\n".join(f"    {opt.name}: {_yaml_value(opt.default)}" for opt in cls.options)
        lines += [
            "",
            f"Set them in the [configuration file](../configuration/index.md) "
            f"under `checks: {cls.id}:`, or for one run with `--check-option`:",
            "",
            "```yaml",
            "checks:",
            f"  {cls.id}:",
            "    enabled: true",
            example,
            "```",
            "",
            "```sh",
            f"pydebuprep report --check-option {cls.id}.{_cli_example(cls.options[0])}",
            "```",
            "",
        ]
        if any(isinstance(o.default, list) for o in cls.options):
            lines += [
                "For a list option, `--check-option` replaces the configured list; repeat "
                "it to give several items.",
                "",
            ]
    else:
        lines += [
            "## Options",
            "",
            f"This check has no options. Turn it off with `enabled: false` under "
            f"`checks: {cls.id}:` in the [configuration file](../configuration/index.md), "
            f"or for one run with `--skip {cls.id}`.",
            "",
        ]
    return "\n".join(lines)


def _cli_example(opt: Any) -> str:
    if isinstance(opt.default, list):
        return f"{opt.name}={opt.default[0] if opt.default else 'VALUE'}"
    return f"{opt.name}={_yaml_value(opt.default)}"


def checks_index() -> str:
    """One table per category, linking every check page."""
    out: list[str] = []
    for category in CATEGORY_ORDER:
        members = [c for c in check_classes() if c.category == category]
        out += [
            f"## {CATEGORY_TITLES[category]}",
            "",
            "| Check | What it looks at | Root | Snapshot |",
            "|---|---|---|---|",
        ]
        for cls in members:
            out.append(
                f"| [`{cls.id}`]({cls.id}.md) | {_cell(cls.title)} | "
                f"{_yes(cls.requires_root)} | {_yes(cls().supports_baseline)} |"
            )
        out.append("")
    return "\n".join(out)


def config_reference() -> str:
    """Every key of the configuration file: the report and logs sections, then checks."""
    defaults = ReportSettings()
    out = [
        "## `report`",
        "",
        "Defaults for the `report` command. Command-line options override them.",
        "",
        "| Key | Default | Description |",
        "|---|---|---|",
    ]
    for key, text in REPORT_HELP.items():
        value = _yaml_value(getattr(defaults, key))
        out.append(f"| `{key}` | `{value}` | {_cell(text)} |")
    out += [
        "",
        "## `logs`",
        "",
        "| Key | Default | Description |",
        "|---|---|---|",
        f"| `ignore` | `[]` | {_cell(LOGS_HELP)} |",
        "",
        "## `checks`",
        "",
        "One section per check, named by its ID. Every section accepts `enabled` "
        "(default `true`; `false` leaves the check out of reports and snapshots) plus "
        "the check's own options:",
        "",
        "| Check | Option | Default | Description |",
        "|---|---|---|---|",
    ]
    for cls in check_classes():
        for opt in cls.options:
            out.append(
                f"| [`{cls.id}`](../checks/{cls.id}.md) | `{opt.name}` | "
                f"`{_cell(_yaml_value(opt.default))}` | {_cell(opt.help)} |"
            )
    without = [c.id for c in check_classes() if not c.options]
    out += [
        "",
        f"Checks with no options (only `enabled`): {', '.join(f'`{i}`' for i in without)}.",
        "",
    ]
    return "\n".join(out)


def example() -> str:
    return f'```yaml title="{DEFAULT_CONFIG_PATH}"\n{example_config().rstrip()}\n```\n'


def _subparsers(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    raise DocsError("the parser has no subcommands")  # pragma: no cover - always has


def _helps(parser: argparse.ArgumentParser) -> dict[str, str]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return {a.dest: a.help or "" for a in action._choices_actions}
    return {}  # pragma: no cover - always has subcommands


def cli_reference() -> str:
    """Every command with its usage line and options, from the argparse parser."""
    parser = build_parser()
    helps = _helps(parser)
    out: list[str] = []
    for name, sub in _subparsers(parser).items():
        usage = " ".join(sub.format_usage().split())
        out += [f"## `{name}`", "", helps.get(name, "").capitalize() + ".", ""]
        out += ["```text", usage.removeprefix("usage: "), "```", ""]
        rows = []
        for action in sub._actions:
            if isinstance(action, argparse._HelpAction):
                continue
            if action.option_strings:
                flags = ", ".join(f"`{f}`" for f in action.option_strings)
                if action.nargs != 0:
                    meta = action.metavar or (
                        "{" + ",".join(str(c) for c in action.choices) + "}"
                        if action.choices
                        else action.dest.upper()
                    )
                    flags += f" `{meta}`"
            else:
                flags = f"`{action.metavar or action.dest}`"
                if action.choices:
                    flags += " (" + ", ".join(f"`{c}`" for c in action.choices) + ")"
            rows.append(f"| {flags} | {_cell(_help(action, sub.prog))} |")
        if rows:
            out += ["| Argument | Description |", "|---|---|", *rows, ""]
    return "\n".join(out)


def render_marker(kind: str, arg: str | None) -> str:
    if kind in ("facts", "options"):
        if not arg:
            raise DocsError(f"the {kind} marker needs a check id: <!-- {kind}: ID -->")
        return facts(arg) if kind == "facts" else options(arg)
    if kind == "checks-index":
        return checks_index()
    if kind == "config-reference":
        return config_reference()
    if kind == "example-config":
        return example()
    return cli_reference()


def expand(markdown: str) -> str:
    return MARKER.sub(lambda m: render_marker(m.group(1), m.group(2)), markdown)


def on_page_markdown(markdown: str, **_: Any) -> str:
    """MkDocs hook: expand the markers on every page."""
    return expand(markdown)
