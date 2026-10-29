from __future__ import annotations

import re
from typing import Any

from pydebuprep.checks.base import Check, Context, run_checked
from pydebuprep.checks.dpkg_rc import DPKG_RC_ARGV
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.osinfo import known_codenames

APT_CONFIG_DUMP = ("apt-config", "dump")
SETTING = re.compile(r'^(\S+?)(?:::)? "(.*)";$')
ORIGIN_KEYS = ("Unattended-Upgrade::Origins-Pattern", "Unattended-Upgrade::Allowed-Origins")


def _installed(ctx: Context) -> bool:
    return any(
        line.startswith("ii") and line.split()[-1] == "unattended-upgrades"
        for line in run_checked(ctx, DPKG_RC_ARGV).stdout.splitlines()
    )


def _config(ctx: Context) -> list[tuple[str, str, str]]:
    """(key, value, line) for every setting apt-config reports."""
    settings = []
    for line in run_checked(ctx, APT_CONFIG_DUMP).stdout.splitlines():
        m = SETTING.match(line.strip())
        if m:
            settings.append((m.group(1), m.group(2), line.strip()))
    return settings


def _enabled(settings: list[tuple[str, str, str]]) -> bool:
    values = {key: value for key, value, _ in settings}
    return values.get("APT::Periodic::Enable", "1") != "0" and values.get(
        "APT::Periodic::Unattended-Upgrade", "0"
    ) not in ("", "0")


class UnattendedUpgradesCheck(Check):
    id = "unattended-upgrades"
    title = "Automatic security updates"
    category = "security"
    requires_commands = ("apt-config", "dpkg-query")

    def run(self, ctx: Context) -> list[Finding]:
        if not _installed(ctx):
            return []
        settings = _config(ctx)
        findings = []
        if not _enabled(settings):
            findings.append(
                Finding(
                    Severity.WARNING,
                    "unattended-upgrades is installed but disabled",
                    detail="APT::Periodic::Unattended-Upgrade is not set to 1 (or "
                    "APT::Periodic::Enable is 0), so security updates aren't applied.",
                    remediation=["sudo dpkg-reconfigure -plow unattended-upgrades"],
                )
            )
        current = ctx.osinfo.codename
        old = sorted(known_codenames(ctx.osinfo.family) - {current})
        for codename in old:
            lines = [
                line
                for key, value, line in settings
                if key.startswith(ORIGIN_KEYS) and re.search(rf"\b{codename}\b", value)
            ]
            if lines:
                findings.append(
                    Finding(
                        Severity.WARNING,
                        f"unattended-upgrades still names the old release {codename}",
                        detail="Origins that name a release instead of ${distro_codename} stop "
                        "matching after an upgrade, so no updates come from them.",
                        evidence=truncate_evidence(lines),
                        remediation=[
                            "Edit /etc/apt/apt.conf.d/50unattended-upgrades: use "
                            f"${{distro_codename}} instead of {codename}",
                            "sudo unattended-upgrade --dry-run --debug   # to check",
                        ],
                    )
                )
        return findings

    def collect_baseline(self, ctx: Context) -> Any:
        installed = _installed(ctx)
        return {"installed": installed, "enabled": installed and _enabled(_config(ctx))}

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        if before.get("installed") and not _installed(ctx):
            return [
                Finding(
                    Severity.WARNING,
                    "unattended-upgrades was removed by the upgrade",
                    remediation=["sudo apt install unattended-upgrades"],
                )
            ]
        return []
