from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from pydebuprep.checks.base import Check, Context, run_checked, running_kernel
from pydebuprep.model import Finding, Severity

TRAILING_NOTE = re.compile(r"\s*\(.*\)\s*$")


@dataclass
class DkmsEntry:
    name: str
    version: str
    kernel: str | None
    status: str


def parse_dkms_status(text: str) -> list[DkmsEntry]:
    entries = []
    for line in text.splitlines():
        left, sep, status = line.rpartition(": ")
        if not sep:
            continue
        status = TRAILING_NOTE.sub("", status).strip()
        parts = [p.strip() for p in left.split(",")]
        if "/" in parts[0]:
            name, _, version = parts[0].partition("/")
            kernel = parts[1] if len(parts) > 1 else None
        else:
            name = parts[0]
            version = parts[1] if len(parts) > 1 else ""
            kernel = parts[2] if len(parts) > 2 else None
        entries.append(DkmsEntry(name, version, kernel, status))
    return entries


def _modules(ctx: Context) -> list[DkmsEntry]:
    return parse_dkms_status(run_checked(ctx, ["dkms", "status"], timeout=60).stdout)


class DkmsCheck(Check):
    id = "dkms"
    title = "Out-of-tree kernel modules (DKMS)"
    category = "boot"
    requires_commands = ("dkms",)

    def run(self, ctx: Context) -> list[Finding]:
        running = running_kernel(ctx)
        entries = _modules(ctx)
        findings = []
        for name in sorted({e.name for e in entries}):
            mine = [e for e in entries if e.name == name]
            if any(e.kernel == running and e.status.startswith("installed") for e in mine):
                continue
            version = mine[-1].version
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    f"DKMS module {name} is not built for the running kernel",
                    detail=f"Running kernel is {running}; hardware or filesystems that need "
                    f"{name} will not work.",
                    evidence=[f"{e.name}/{e.version} {e.kernel or '-'}: {e.status}" for e in mine],
                    remediation=[
                        f"sudo dkms autoinstall -k {running}",
                        f"If the build fails, see /var/lib/dkms/{name}/{version}/build/make.log",
                    ],
                )
            )
        return findings

    def collect_baseline(self, ctx: Context) -> Any:
        return sorted({e.name for e in _modules(ctx)})

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now = {e.name for e in _modules(ctx)}
        return [
            Finding(
                Severity.WARNING,
                f"DKMS module {name} was registered before the upgrade",
                detail="It is no longer known to DKMS; the package providing it may have been "
                "removed.",
                remediation=[f"Reinstall the package that provides {name} if you still need it"],
            )
            for name in sorted(set(before) - now)
        ]
