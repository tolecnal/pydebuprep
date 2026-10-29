from __future__ import annotations

import re
from collections import Counter
from typing import Any

from pydebuprep.checks.base import Check, CheckSkipped, Context, count, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence

AA_ENABLED = "/sys/module/apparmor/parameters/enabled"
AA_PROFILES = "/sys/kernel/security/apparmor/profiles"
JOURNAL_DENIALS = ("journalctl", "-b", "-k", "--no-pager", "-o", "cat", '--grep=apparmor="DENIED"')
FIELD = re.compile(r'(\w+)="([^"]*)"')


def _profiles(ctx: Context) -> dict[str, str]:
    profiles = {}
    for line in (ctx.system.read_text(AA_PROFILES) or "").splitlines():
        name, sep, mode = line.strip().rpartition(" (")
        if sep:
            profiles[name] = mode.rstrip(")")
    return profiles


def _enabled(ctx: Context) -> bool:
    text = ctx.system.read_text(AA_ENABLED)
    if text is None:
        raise CheckSkipped("AppArmor is not available in this kernel")
    return text.strip() == "Y"


class AppArmorCheck(Check):
    id = "apparmor"
    title = "AppArmor"
    category = "security"
    requires_root = True

    def run(self, ctx: Context) -> list[Finding]:
        findings = []
        if not _enabled(ctx):
            findings.append(
                Finding(
                    Severity.WARNING,
                    "AppArmor is disabled",
                    detail="Debian and Ubuntu enable AppArmor by default; services lose their "
                    "confinement without it.",
                    remediation=[
                        "cat /proc/cmdline   # look for apparmor=0 or security=",
                        "sudo systemctl enable --now apparmor",
                    ],
                )
            )
        complain = sorted(n for n, mode in _profiles(ctx).items() if mode == "complain")
        if complain:
            findings.append(
                Finding(
                    Severity.INFO,
                    f"{count(len(complain), 'AppArmor profile is', 'AppArmor profiles are')} "
                    "in complain mode",
                    detail="Complain mode logs violations instead of blocking them.",
                    evidence=truncate_evidence(complain),
                    remediation=["sudo aa-enforce PROFILE   # once it no longer logs denials"],
                )
            )
        if ctx.system.which("journalctl"):
            denials: Counter[str] = Counter()
            for line in run_checked(ctx, JOURNAL_DENIALS, ok_codes=(0, 1)).stdout.splitlines():
                fields = dict(FIELD.findall(line))
                if fields.get("apparmor") == "DENIED":
                    denials[f"{fields.get('profile', '?')}: {fields.get('operation', '?')}"] += 1
            if denials:
                findings.append(
                    Finding(
                        Severity.WARNING,
                        f"{count(sum(denials.values()), 'AppArmor denial')} this boot",
                        detail="A profile from the new release may not fit your configuration.",
                        evidence=truncate_evidence(
                            [f"{n}x {key}" for key, n in denials.most_common()]
                        ),
                        remediation=["sudo journalctl -b -k --grep='apparmor=\"DENIED\"'"],
                    )
                )
        return findings

    def collect_baseline(self, ctx: Context) -> Any:
        return {"enabled": _enabled(ctx), "profiles": _profiles(ctx)}

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now = _profiles(ctx)
        lost = []
        for name, mode in sorted((before.get("profiles") or {}).items()):
            if mode != "enforce":
                continue
            if name not in now:
                lost.append(f"{name}: no longer loaded")
            elif now[name] != "enforce":
                lost.append(f"{name}: now {now[name]}")
        if not lost:
            return []
        return [
            Finding(
                Severity.WARNING,
                f"{count(len(lost), 'AppArmor profile is', 'AppArmor profiles are')} "
                "no longer enforced",
                evidence=truncate_evidence(lost),
                remediation=["sudo aa-status", "sudo aa-enforce PROFILE"],
            )
        ]
