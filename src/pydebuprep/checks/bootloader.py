from __future__ import annotations

import re

from pydebuprep.checks.base import Check, Context
from pydebuprep.checks.kernel_running import installed_kernels
from pydebuprep.model import Finding, Severity, truncate_evidence

GRUB_CFG = "/boot/grub/grub.cfg"
EFI_DIR = "/sys/firmware/efi"
BOOT_ENTRY = re.compile(r"^Boot([0-9A-Fa-f]{4})")


class BootloaderCheck(Check):
    id = "bootloader"
    title = "Bootloader configuration"
    category = "boot"

    def run(self, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        sys = ctx.system
        verified = False
        grub = sys.read_text(GRUB_CFG)
        if grub is not None:
            verified = True
            kernels = installed_kernels(sys)
            if kernels and kernels[-1] not in grub:
                findings.append(
                    Finding(
                        Severity.WARNING,
                        f"grub.cfg does not reference newest kernel {kernels[-1]}",
                        detail="The next boot may start an old kernel.",
                        remediation=["sudo update-grub"],
                    )
                )
        elif sys.exists(GRUB_CFG):
            findings.append(
                Finding(
                    Severity.INFO,
                    f"{GRUB_CFG} is not readable",
                    remediation=["Run as root to verify the GRUB configuration"],
                )
            )
            verified = True
        if sys.exists(EFI_DIR) and sys.which("efibootmgr"):
            verified = True
            findings.extend(self._check_efi(ctx))
        if not verified:
            findings.append(
                Finding(
                    Severity.INFO,
                    "No GRUB config found; bootloader not verified",
                    remediation=["Check your bootloader's configuration by hand"],
                )
            )
        return findings

    def _check_efi(self, ctx: Context) -> list[Finding]:
        res = ctx.system.run(["efibootmgr", "-v"])
        if not res.ok:
            return [
                Finding(
                    Severity.INFO,
                    "efibootmgr could not read UEFI boot entries",
                    evidence=truncate_evidence(res.stderr.splitlines()),
                    remediation=["Run as root: sudo efibootmgr -v"],
                )
            ]
        lines = res.stdout.splitlines()
        current = next(
            (line.split(":", 1)[1].strip() for line in lines if line.startswith("BootCurrent:")),
            None,
        )
        entries = {m.group(1).upper() for m in map(BOOT_ENTRY.match, lines) if m}
        remediation = [
            "Inspect entries: sudo efibootmgr -v",
            "Reinstall the bootloader entry if needed, e.g. sudo grub-install (for GRUB on UEFI)",
        ]
        if current is None:
            return [
                Finding(
                    Severity.WARNING,
                    "UEFI firmware did not report which entry booted this system",
                    evidence=truncate_evidence(lines),
                    remediation=remediation,
                )
            ]
        if current.upper() not in entries:
            return [
                Finding(
                    Severity.WARNING,
                    f"UEFI boot entry {current} is no longer listed",
                    detail="The entry used for this boot has disappeared; the next boot may "
                    "fall back to another entry.",
                    evidence=truncate_evidence(lines),
                    remediation=remediation,
                )
            ]
        return []
