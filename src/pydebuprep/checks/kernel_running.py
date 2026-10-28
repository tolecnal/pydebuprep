from __future__ import annotations

import functools
from typing import Any

from pydebuprep.checks.base import Check, Context, output_lines, running_kernel
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.system import System

REBOOT_REQUIRED = ("/run/reboot-required", "/var/run/reboot-required")


def _order(c: str) -> int:
    if not c or c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    """dpkg's comparison of an upstream version or revision string."""
    while a or b:
        while (a and not a[0].isdigit()) or (b and not b[0].isdigit()):
            ac, bc = _order(a[:1]), _order(b[:1])
            if ac != bc:
                return ac - bc
            a, b = a[1:], b[1:]
        a, b = a.lstrip("0"), b.lstrip("0")
        first_diff = 0
        while a[:1].isdigit() and b[:1].isdigit():
            if not first_diff:
                first_diff = int(a[0]) - int(b[0])
            a, b = a[1:], b[1:]
        if a[:1].isdigit():
            return 1
        if b[:1].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split(version: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in version:
        head, _, rest = version.partition(":")
        if head.isdigit():
            epoch, version = int(head), rest
    upstream, sep, revision = version.rpartition("-")
    if not sep:
        return epoch, version, ""
    return epoch, upstream, revision


def compare_versions(a: str, b: str) -> int:
    """Compare two Debian version strings like `dpkg --compare-versions`; returns -1, 0 or 1."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    result = (ea > eb) - (ea < eb) or _verrevcmp(ua, ub) or _verrevcmp(ra, rb)
    return (result > 0) - (result < 0)


def installed_kernels(system: System) -> list[str]:
    versions = [p.removeprefix("/boot/vmlinuz-") for p in system.glob("/boot/vmlinuz-*")]
    return sorted(versions, key=functools.cmp_to_key(compare_versions))


class KernelRunningCheck(Check):
    id = "kernel-running"
    title = "Running kernel"
    category = "boot"
    requires_commands = ("uname",)

    def run(self, ctx: Context) -> list[Finding]:
        findings = []
        running = running_kernel(ctx)
        installed = installed_kernels(ctx.system)
        if installed and compare_versions(running, installed[-1]) < 0:
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    f"Running kernel {running} is older than installed {installed[-1]}",
                    detail="A reboot is part of a release upgrade; until then the new kernel, "
                    "its modules and many fixes are not in use.",
                    evidence=installed,
                    remediation=["sudo reboot"],
                )
            )
        for flag in REBOOT_REQUIRED:
            if ctx.system.exists(flag):
                pkgs = output_lines(ctx.system.read_text(flag + ".pkgs") or "")
                findings.append(
                    Finding(
                        Severity.CRITICAL,
                        "A reboot is required",
                        detail=f"{flag} exists; packages below asked for a reboot.",
                        evidence=truncate_evidence(pkgs),
                        remediation=["sudo reboot"],
                    )
                )
                break
        return findings

    def collect_baseline(self, ctx: Context) -> Any:
        return {"running": running_kernel(ctx), "installed": installed_kernels(ctx.system)}

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        old, now = before.get("running"), running_kernel(ctx)
        if old == now:
            return [
                Finding(
                    Severity.WARNING,
                    f"Still running the pre-upgrade kernel {now}",
                    remediation=["sudo reboot"],
                )
            ]
        return [Finding(Severity.INFO, f"Kernel changed from {old} to {now}")]
