"""The interface every check implements."""

from __future__ import annotations

import copy
from collections.abc import Container, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydebuprep.model import Finding
from pydebuprep.osinfo import OsInfo
from pydebuprep.system import DEFAULT_TIMEOUT, CommandResult, System


class CheckSkipped(Exception):
    """Raised by a check that discovers at run time it cannot run here."""


class CommandFailed(RuntimeError):
    """A command a check depends on timed out, could not start or exited unexpectedly."""


@dataclass
class Context:
    system: System
    osinfo: OsInfo
    baseline: dict[str, Any] | None = None
    # Regular expressions from the config file's logs.ignore, shared by the log checks
    # and matched against the message text.
    log_ignore: tuple[str, ...] = ()

    @property
    def is_root(self) -> bool:
        return self.system.is_root()

    def baseline_for(self, check_id: str) -> Any | None:
        if not self.baseline:
            return None
        return self.baseline.get("checks", {}).get(check_id)


TRUE_WORDS = ("true", "yes", "on", "1")
FALSE_WORDS = ("false", "no", "off", "0")


@dataclass(frozen=True)
class Option:
    """A setting a check accepts; its type is the type of its default."""

    name: str
    default: Any
    help: str
    # For list options: whether a single string is split on commas. Off for values that
    # may themselves contain commas, such as regular expressions.
    split: bool = True

    def coerce(self, value: Any) -> Any:
        """Convert a config-file or command-line value; raises ValueError with a reason."""
        default = self.default
        if isinstance(default, bool):
            if isinstance(value, bool):
                return value
            word = str(value).strip().lower()
            if word in TRUE_WORDS:
                return True
            if word in FALSE_WORDS:
                return False
            raise ValueError("expected true or false")
        if isinstance(default, int):
            if isinstance(value, bool):
                raise ValueError("expected an integer")
            try:
                return int(str(value).strip())
            except ValueError:
                raise ValueError("expected an integer") from None
        if isinstance(default, float):
            if isinstance(value, bool):
                raise ValueError("expected a number")
            try:
                return float(str(value).strip())
            except ValueError:
                raise ValueError("expected a number") from None
        if isinstance(default, list):
            if isinstance(value, str):
                if not self.split:
                    return [value] if value else []
                return [item.strip() for item in value.split(",") if item.strip()]
            if isinstance(value, (list, tuple)):
                if not all(
                    isinstance(item, (str, int, float)) and not isinstance(item, bool)
                    for item in value
                ):
                    raise ValueError("expected a list of strings")
                return [str(item) for item in value]
            raise ValueError("expected a list")
        if isinstance(value, (dict, list)):
            raise ValueError("expected a string")
        return str(value)


class Check:
    id: str = ""
    title: str = ""
    category: str = ""
    requires_root: bool = False
    requires_commands: tuple[str, ...] = ()
    install_hint: str | None = None
    options: tuple[Option, ...] = ()

    def __init__(self, settings: Mapping[str, Any] | None = None) -> None:
        known = {o.name: o for o in self.options}
        self.settings: dict[str, Any] = {o.name: copy.deepcopy(o.default) for o in self.options}
        for name, value in (settings or {}).items():
            if name not in known:
                raise ValueError(f"{self.id}: unknown option {name!r}")
            try:
                self.settings[name] = known[name].coerce(value)
            except ValueError as exc:
                raise ValueError(f"{self.id}.{name}: {exc}") from None
        try:
            self.validate()
        except ValueError as exc:
            raise ValueError(f"{self.id}: {exc}") from None

    def opt(self, name: str) -> Any:
        return self.settings[name]

    def validate(self) -> None:
        """Check option values against each other; raise ValueError if they don't fit."""

    def run(self, ctx: Context) -> list[Finding]:
        raise NotImplementedError

    def collect_baseline(self, ctx: Context) -> Any | None:
        return None

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        return []

    @property
    def supports_baseline(self) -> bool:
        return type(self).collect_baseline is not Check.collect_baseline

    def unmet_requirement(self, ctx: Context) -> str | None:
        """Why this check cannot run here, or None if it can."""
        if self.requires_root and not ctx.is_root:
            return "requires root (run with sudo for this check)"
        for cmd in self.requires_commands:
            if not ctx.system.which(cmd):
                reason = f"command not found: {cmd}"
                if self.install_hint:
                    reason += f"; {self.install_hint}"
                return reason
        return None


def count(n: int, singular: str, plural: str | None = None) -> str:
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def output_lines(text: str) -> list[str]:
    return [line.rstrip() for line in text.splitlines() if line.strip()]


def run_checked(
    ctx: Context,
    argv: Sequence[str],
    *,
    ok_codes: Container[int] | None = (0,),
    timeout: float = DEFAULT_TIMEOUT,
) -> CommandResult:
    """Run a command, raising CommandFailed instead of returning output that can't be trusted.

    ok_codes=None accepts any exit status (for commands that signal findings that way),
    but a timeout or a failure to start always raises.
    """
    res = ctx.system.run(argv, timeout=timeout)
    if res.timed_out:
        raise CommandFailed(f"{argv[0]} timed out after {timeout:g}s")
    stderr = res.stderr.strip().splitlines()
    reason = f": {stderr[0]}" if stderr else ""
    if res.returncode in (126, 127):
        raise CommandFailed(f"{argv[0]} could not be run{reason}")
    if ok_codes is not None and res.returncode not in ok_codes:
        raise CommandFailed(f"{argv[0]} exited with status {res.returncode}{reason}")
    return res


def running_kernel(ctx: Context) -> str:
    kernel = run_checked(ctx, ["uname", "-r"]).stdout.strip()
    if not kernel:
        raise CommandFailed("uname -r printed nothing")
    return kernel
