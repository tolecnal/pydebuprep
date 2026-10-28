"""The interface every check implements."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydebuprep.model import Finding
from pydebuprep.osinfo import OsInfo
from pydebuprep.system import System


@dataclass
class Context:
    system: System
    osinfo: OsInfo
    baseline: dict[str, Any] | None = None

    @property
    def is_root(self) -> bool:
        return self.system.is_root()

    def baseline_for(self, check_id: str) -> Any | None:
        if not self.baseline:
            return None
        return self.baseline.get("checks", {}).get(check_id)


class Check:
    id: str = ""
    title: str = ""
    category: str = ""
    requires_root: bool = False
    requires_commands: tuple[str, ...] = ()
    install_hint: str | None = None

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


def running_kernel(ctx: Context) -> str:
    res = ctx.system.run(["uname", "-r"])
    return res.stdout.strip() if res.ok else "unknown"
