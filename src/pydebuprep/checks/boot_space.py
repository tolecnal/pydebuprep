from __future__ import annotations

from pydebuprep.checks._diskutil import THRESHOLD_OPTIONS, space_findings, validate_thresholds
from pydebuprep.checks.base import Check, Context
from pydebuprep.model import Finding

BOOT_PATHS = ("/boot", "/boot/efi")
REMEDIATION = {
    "/boot": [
        "List installed kernels: dpkg -l 'linux-image-*'",
        "sudo apt autoremove --purge",
    ],
    "/boot/efi": ["Remove stale vendor directories under /boot/efi/EFI/ you no longer boot"],
}


class BootSpaceCheck(Check):
    id = "boot-space"
    title = "Free space on /boot and the EFI partition"
    category = "boot"
    options = THRESHOLD_OPTIONS

    def validate(self) -> None:
        validate_thresholds(self)

    def run(self, ctx: Context) -> list[Finding]:
        root = ctx.system.disk_usage("/")
        findings = []
        for path in BOOT_PATHS:
            if not ctx.system.exists(path):
                continue
            usage = ctx.system.disk_usage(path)
            if usage is None or usage == root:
                continue
            findings += space_findings(
                path,
                usage,
                REMEDIATION[path],
                warning_pct=self.opt("warning_pct"),
                critical_pct=self.opt("critical_pct"),
            )
        return findings
