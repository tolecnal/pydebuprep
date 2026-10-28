from __future__ import annotations

from typing import Any

from pydebuprep.checks.base import Check, Context
from pydebuprep.model import Finding, Severity
from pydebuprep.osinfo import RELEASES


def _supported_list() -> str:
    return ", ".join(
        f"{r.family.capitalize()} {r.version} ({r.codename})" for r in RELEASES.values()
    )


def _describe(os_id: str, version: str, codename: str) -> str:
    return f"{os_id.capitalize()} {version} ({codename})"


class OsReleaseCheck(Check):
    id = "os-release"
    title = "Operating system release"
    category = "release"

    def run(self, ctx: Context) -> list[Finding]:
        info = ctx.osinfo
        if info.supported:
            return []
        return [
            Finding(
                Severity.CRITICAL,
                f"Unsupported release {info.pretty_name}",
                detail=f"/etc/os-release reports ID={info.id}, VERSION_ID={info.version_id}, "
                f"codename={info.codename or 'unknown'}.",
                remediation=[
                    "Confirm this is the release you meant to upgrade to: cat /etc/os-release",
                    f"pydebuprep supports {_supported_list()}; other results may be incomplete.",
                ],
            )
        ]

    def collect_baseline(self, ctx: Context) -> Any:
        info = ctx.osinfo
        return {
            "id": info.id,
            "version_id": info.version_id,
            "codename": info.codename,
            "hostname": ctx.system.hostname(),
        }

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        info = ctx.osinfo
        findings: list[Finding] = []
        hostname = ctx.system.hostname()
        if before.get("hostname") and before["hostname"] != hostname:
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"Baseline is from host {before['hostname']}",
                    detail=f"This host is {hostname}; comparisons may be meaningless.",
                    remediation=["Pass the right snapshot with --baseline, or use --no-baseline."],
                )
            )
        old = _describe(
            before.get("id", "?"), before.get("version_id", "?"), before.get("codename", "?")
        )
        new = _describe(info.id, info.version_id, info.codename)
        if before.get("codename") == info.codename:
            findings.append(
                Finding(
                    Severity.WARNING,
                    "Baseline was taken on the same release; it may be a post-upgrade snapshot",
                    detail=f"Baseline and current system are both {new}.",
                    remediation=[
                        "Pick the pre-upgrade snapshot with --baseline FILE "
                        "(see /var/lib/pydebuprep/snapshots/)."
                    ],
                )
            )
        else:
            findings.append(
                Finding(
                    Severity.INFO,
                    f"Upgraded from {old} to {new}",
                    remediation=[
                        "Read the release notes' known-issues section for this upgrade path."
                    ],
                    references=[info.release.notes_url] if info.release else [],
                )
            )
        return findings
