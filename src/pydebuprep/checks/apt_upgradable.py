from __future__ import annotations

from pydebuprep.checks.base import Check, Context, count, output_lines, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.system import apt_command

SIMULATE_UPGRADE = ("apt-get", "-s", "upgrade")


def package_lines(text: str) -> list[str]:
    """Package rows of `apt list` output, without the banner and CLI warnings."""
    return [
        line
        for line in output_lines(text)
        if "/" in line and not line.startswith(("Listing", "WARNING:"))
    ]


def _simulated_sections(text: str) -> dict[str, list[str]]:
    """The package lists of `apt-get -s upgrade`, by their "The following ...:" heading."""
    sections: dict[str, list[str]] = {}
    heading = None
    for line in text.splitlines():
        if line.startswith("The following") and line.rstrip().endswith(":"):
            heading = line
            sections[heading] = []
        elif heading and line.startswith(" "):
            sections[heading] += line.split()
        else:
            heading = None
    return sections


class AptUpgradableCheck(Check):
    id = "apt-upgradable"
    title = "Pending package upgrades"
    category = "packages"
    requires_commands = ("apt",)

    def run(self, ctx: Context) -> list[Finding]:
        rows = {}
        for line in package_lines(
            run_checked(ctx, apt_command("apt", "list", "--upgradable")).stdout
        ):
            fields = line.split()
            name, _, suites = fields[0].partition("/")
            version = fields[1] if len(fields) > 1 else "?"
            rows[name] = (f"{name} {version} ({suites})", suites.split(","))
        if not rows:
            return []
        sections = _simulated_sections(run_checked(ctx, apt_command(*SIMULATE_UPGRADE)).stdout)
        security = sorted(
            n for n, (_, suites) in rows.items() if any(s.endswith("-security") for s in suites)
        )
        held = {n for h, names in sections.items() if "kept back" in h for n in names}
        phased = {n for h, names in sections.items() if "phasing" in h for n in names}
        kept = sorted((held & rows.keys()) - set(security))
        deferred = sorted((phased & rows.keys()) - set(security))
        other = sorted(rows.keys() - set(security) - set(kept) - set(deferred))
        findings = []
        if security:
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"{count(len(security), 'security update is', 'security updates are')} pending",
                    detail="Fixes for known vulnerabilities, published but not installed.",
                    evidence=truncate_evidence([rows[n][0] for n in security]),
                    remediation=["sudo apt update && sudo apt upgrade"],
                )
            )
        if kept:
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"{count(len(kept), 'package is', 'packages are')} kept back",
                    detail="apt upgrade won't install these because their dependencies "
                    "changed; after a release upgrade that's often a leftover of the "
                    "old release.",
                    evidence=truncate_evidence(kept),
                    remediation=[
                        f"See why: sudo apt-get -s install {' '.join(kept[:10])}",
                        "sudo apt full-upgrade",
                    ],
                )
            )
        if deferred:
            findings.append(
                Finding(
                    Severity.INFO,
                    f"{count(len(deferred), 'update is', 'updates are')} deferred by phasing",
                    detail="Ubuntu rolls out some updates gradually (phased updates); this "
                    "machine gets them later. Expected, nothing to do.",
                    evidence=truncate_evidence(deferred),
                    remediation=[
                        "Nothing to do; apt installs them once the phase reaches this machine"
                    ],
                )
            )
        if other:
            findings.append(
                Finding(
                    Severity.INFO,
                    f"{count(len(other), 'other package', 'other packages')} can be upgraded",
                    detail="Stragglers after a release upgrade are often packages whose "
                    "dependencies changed; a second full-upgrade pass usually picks them up.",
                    evidence=truncate_evidence([rows[n][0] for n in other]),
                    remediation=["sudo apt update && sudo apt full-upgrade"],
                )
            )
        return findings
