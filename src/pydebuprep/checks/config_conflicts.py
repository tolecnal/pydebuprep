from __future__ import annotations

import fnmatch
import os

from pydebuprep.checks.base import Check, Context, Option, count
from pydebuprep.model import Finding, Severity, truncate_evidence

CONFLICT_SUFFIXES = (
    ".dpkg-new",
    ".dpkg-old",
    ".dpkg-dist",
    ".dpkg-bak",
    ".ucf-new",
    ".ucf-old",
    ".ucf-dist",
)
CRITICAL_PATHS = [
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d/",
    "/etc/sudoers",
    "/etc/sudoers.d/",
]


def _original(path: str) -> str | None:
    for suffix in CONFLICT_SUFFIXES:
        if path.endswith(suffix):
            return path[: -len(suffix)]
    return None


class ConfigConflictsCheck(Check):
    id = "config-conflicts"
    title = "Unmerged configuration files"
    category = "packages"
    options = (
        Option(
            "critical_paths",
            CRITICAL_PATHS,
            "Config files whose unmerged updates are critical; a trailing / means a directory",
        ),
        Option(
            "ignore_paths",
            [],
            "Files to leave out, e.g. ones a configuration tool such as Ansible manages "
            "(shell-style patterns, matched against the config file or its leftover copy)",
        ),
    )

    def _ignored(self, path: str, original: str) -> bool:
        return any(
            fnmatch.fnmatchcase(path, p) or fnmatch.fnmatchcase(original, p)
            for p in self.opt("ignore_paths")
        )

    def _is_critical(self, original: str) -> bool:
        return any(
            original.startswith(p) if p.endswith("/") else original == p
            for p in self.opt("critical_paths")
        )

    def run(self, ctx: Context) -> list[Finding]:
        errors: list[str] = []
        leftovers = sorted(
            (path, orig)
            for path in ctx.system.walk_files("/etc", errors)
            if (orig := _original(path)) is not None and not self._ignored(path, orig)
        )
        findings = [
            Finding(
                Severity.CRITICAL,
                f"Unmerged package config for {orig}",
                detail="You kept your version during the upgrade; the package's new defaults "
                "were saved next to it. Security-relevant settings may have changed.",
                evidence=[os.path.basename(path)],
                remediation=[
                    f"diff -u {orig} {path}",
                    f"Merge the changes you want into {orig}, validate it "
                    "(sshd -t / visudo -c), then remove the leftover file",
                ],
            )
            for path, orig in leftovers
            if self._is_critical(orig)
        ]
        others = [path for path, orig in leftovers if not self._is_critical(orig)]
        if others:
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"{count(len(others), 'config file has', 'config files have')} "
                    "unmerged package versions",
                    detail="Each file was left next to a config you changed. Review the diffs, "
                    "merge what you want and delete the leftovers.",
                    evidence=truncate_evidence(others),
                    remediation=[
                        "For each file: diff -u ORIGINAL ORIGINAL.dpkg-dist (or the matching "
                        "suffix)",
                        "Merge wanted changes into ORIGINAL, then remove the leftover file",
                    ],
                )
            )
        if errors and not ctx.is_root:
            findings.append(
                Finding(
                    Severity.INFO,
                    "Some directories under /etc were not readable",
                    evidence=truncate_evidence(errors),
                    remediation=["Run as root for complete results"],
                )
            )
        return findings
