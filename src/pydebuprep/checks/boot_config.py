"""What a machine boots with: an initramfs per kernel, the kernel's command line and
Secure Boot. A machine can boot fine having lost a parameter a workload depends on."""

from __future__ import annotations

import fnmatch
from typing import Any

from pydebuprep.checks.base import Check, Context, Option, count
from pydebuprep.checks.kernel_running import installed_kernels
from pydebuprep.model import Finding, Severity, truncate_evidence

CMDLINE = "/proc/cmdline"
SECURE_BOOT_VAR = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
SECURE_BOOT_VALUE_AT = 4  # after the variable's 4 bytes of attributes


def _secure_boot(ctx: Context) -> bool | None:
    data = ctx.system.read_bytes(SECURE_BOOT_VAR) or b""
    return data[SECURE_BOOT_VALUE_AT] == 1 if len(data) > SECURE_BOOT_VALUE_AT else None


def _cmdline(ctx: Context) -> str | None:
    text = ctx.system.read_text(CMDLINE)
    return None if text is None else text.strip()


class BootConfigCheck(Check):
    id = "boot-config"
    title = "Initramfs, kernel command line and Secure Boot"
    category = "boot"
    options = (
        Option(
            "ignore_parameters",
            ["BOOT_IMAGE", "initrd"],
            "Kernel parameters left out of the comparison, by name (shell-style patterns)",
        ),
    )

    def run(self, ctx: Context) -> list[Finding]:
        missing = [
            kernel
            for kernel in installed_kernels(ctx.system)
            if not ctx.system.exists(f"/boot/initrd.img-{kernel}")
        ]
        if not missing:
            return []
        return [
            Finding(
                Severity.WARNING,
                f"{count(len(missing), 'kernel has', 'kernels have')} no initramfs",
                detail="A kernel that needs its initramfs to find the root filesystem won't boot.",
                evidence=truncate_evidence(missing),
                remediation=[f"sudo update-initramfs -c -k {kernel}" for kernel in missing[:5]],
            )
        ]

    def collect_baseline(self, ctx: Context) -> Any:
        return {"cmdline": _cmdline(ctx), "secure_boot": _secure_boot(ctx)}

    def _parameters(self, text: str) -> set[str]:
        return {
            word
            for word in text.split()
            if not any(
                fnmatch.fnmatchcase(word.partition("=")[0], p)
                for p in self.opt("ignore_parameters")
            )
        }

    def _cmdline_changes(self, ctx: Context, before: str) -> list[Finding]:
        now = _cmdline(ctx)
        if now is None:
            return []
        old, new = self._parameters(before), self._parameters(now)
        added = {word.partition("=")[0]: word for word in new - old}
        lost, gained = [], list(added.values())
        for word in sorted(old - new):
            replacement = added.get(word.partition("=")[0])
            if replacement is None:
                lost.append(f"removed: {word}")
            else:
                lost.append(f"changed: {word} to {replacement}")
                gained.remove(replacement)
        findings = []
        if lost:
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"{count(len(lost), 'kernel parameter was', 'kernel parameters were')} "
                    "removed or changed since the snapshot",
                    detail="The machine can boot without them, while what they enable, such as "
                    "IOMMU for a virtual machine, no longer works.",
                    evidence=truncate_evidence(lost),
                    remediation=[
                        "Check GRUB_CMDLINE_LINUX in /etc/default/grub and /etc/default/grub.d/",
                        "After changing them: sudo update-grub",
                    ],
                )
            )
        if gained:
            findings.append(
                Finding(
                    Severity.INFO,
                    f"{count(len(gained), 'kernel parameter is', 'kernel parameters are')} "
                    "new since the snapshot",
                    evidence=truncate_evidence(sorted(gained)),
                )
            )
        return findings

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        findings = []
        if before.get("cmdline") is not None:
            findings += self._cmdline_changes(ctx, before["cmdline"])
        old, now = before.get("secure_boot"), _secure_boot(ctx)
        if old is not None and now is not None and old != now:
            if old:
                findings.append(
                    Finding(
                        Severity.WARNING,
                        "Secure Boot was on before and is off now",
                        remediation=["Check the firmware's settings", "mokutil --sb-state"],
                    )
                )
            else:
                findings.append(Finding(Severity.INFO, "Secure Boot was off before and is on now"))
        return findings
