from __future__ import annotations

from pydebuprep.checks.base import Check, Context, count, output_lines, run_checked
from pydebuprep.checks.dpkg_rc import DPKG_RC_ARGV
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.system import apt_command

# dpkg's status letters (second character of ${db:Status-Abbrev}), by what fixes them.
NOT_CONFIGURED = {"U": "unpacked", "F": "half-configured"}
REINSTALL = {"H": "half-installed"}
TRIGGERS = {"W": "triggers awaited", "T": "triggers pending"}


def _states(ctx: Context) -> dict[str, list[str]]:
    """Packages in a problem state, as "name (state)", grouped by remedy."""
    groups: dict[str, list[str]] = {"configure": [], "reinstall": [], "triggers": []}
    for line in run_checked(ctx, DPKG_RC_ARGV).stdout.splitlines():
        abbrev, _, name = line.partition(" ")
        name = name.strip()
        if len(abbrev) < 2 or not name:
            continue
        status = abbrev[1]
        if len(abbrev) > 2 and abbrev[2] == "R":
            groups["reinstall"].append(f"{name} (reinstall required)")
        elif status in REINSTALL:
            groups["reinstall"].append(f"{name} ({REINSTALL[status]})")
        elif status in NOT_CONFIGURED:
            groups["configure"].append(f"{name} ({NOT_CONFIGURED[status]})")
        elif status in TRIGGERS:
            groups["triggers"].append(f"{name} ({TRIGGERS[status]})")
    return {k: sorted(v) for k, v in groups.items()}


class DpkgAuditCheck(Check):
    id = "dpkg-audit"
    title = "Broken or half-configured packages"
    category = "packages"
    requires_commands = ("dpkg", "apt-get")

    def run(self, ctx: Context) -> list[Finding]:
        groups = _states(ctx)
        findings = self._state_findings(groups)
        audit = run_checked(ctx, ["dpkg", "--audit"], ok_codes=(0, 1))
        lines = output_lines(audit.stdout)
        # dpkg --audit repeats the states above; keep it for what they don't show.
        if lines and not findings:
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    "dpkg reports broken or half-configured packages",
                    evidence=truncate_evidence(lines),
                    remediation=["sudo dpkg --configure -a", "sudo apt -f install"],
                )
            )
        check = run_checked(ctx, apt_command("apt-get", "check"), ok_codes=None)
        if not check.ok:
            evidence = output_lines(check.stderr) or output_lines(check.stdout)
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    "apt-get check reports unmet dependencies or a broken package database",
                    evidence=truncate_evidence(evidence),
                    remediation=["sudo apt -f install", "sudo dpkg --configure -a"],
                )
            )
        return findings

    @staticmethod
    def _state_findings(groups: dict[str, list[str]]) -> list[Finding]:
        findings = []
        if groups["configure"]:
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    f"{count(len(groups['configure']), 'package is', 'packages are')} "
                    "unpacked but not configured",
                    detail="An interrupted upgrade left them half done; they may not work, "
                    "and apt refuses most operations until they are configured.",
                    evidence=truncate_evidence(groups["configure"]),
                    remediation=["sudo dpkg --configure -a", "sudo apt -f install"],
                )
            )
        if groups["reinstall"]:
            names = " ".join(item.split(" ", 1)[0] for item in groups["reinstall"])
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    f"{count(len(groups['reinstall']), 'package needs', 'packages need')} "
                    "reinstalling",
                    detail="Their files may be incomplete; configuring them again isn't enough.",
                    evidence=truncate_evidence(groups["reinstall"]),
                    remediation=[f"sudo apt install --reinstall {names}"],
                )
            )
        if groups["triggers"]:
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"{count(len(groups['triggers']), 'package is', 'packages are')} "
                    "waiting for triggers",
                    detail="Post-install processing (man pages, libraries, caches) hasn't run "
                    "for them yet.",
                    evidence=truncate_evidence(groups["triggers"]),
                    remediation=["sudo dpkg --triggers-only -a"],
                )
            )
        return findings
