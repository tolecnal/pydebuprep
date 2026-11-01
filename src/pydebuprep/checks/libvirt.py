from __future__ import annotations

import html
import posixpath
import re

from pydebuprep.checks.base import Check, CheckSkipped, Context
from pydebuprep.model import Finding, Severity, truncate_evidence

DOMAINS = "/etc/libvirt/qemu"  # one <name>.xml per defined QEMU/KVM domain
AUTOSTART = f"{DOMAINS}/autostart"  # a link per domain that starts at boot
RUNNING = "/run/libvirt/qemu"  # libvirt's status file per running domain
MAX_DOMAINS = 500
# Read with regular expressions rather than an XML parser: the files are libvirt's
# own, and only these few elements matter.
DISK = re.compile(r"<disk\b.*?</disk>", re.DOTALL)
SOURCE = re.compile(r"<source\b[^>]*?\b(?:file|dev)=(['\"])(.*?)\1")
EMULATOR = re.compile(r"<emulator>\s*(.*?)\s*</emulator>", re.DOTALL)


def needed_files(xml: str) -> list[tuple[str, str]]:
    """The files a domain needs to start, as (what, path)."""
    needed = [("emulator", html.unescape(m)) for m in EMULATOR.findall(xml)]
    for disk in DISK.findall(xml):
        needed += [("disk", html.unescape(path)) for _, path in SOURCE.findall(disk)]
    return needed


class LibvirtCheck(Check):
    id = "libvirt"
    title = "libvirt virtual machines"
    category = "applications"
    requires_root = True  # /etc/libvirt/qemu and /run/libvirt/qemu are root's only

    def run(self, ctx: Context) -> list[Finding]:
        definitions = ctx.system.glob(f"{DOMAINS}/*.xml")[:MAX_DOMAINS]
        if not definitions:
            raise CheckSkipped(f"no libvirt QEMU domains in {DOMAINS}")
        stopped, missing = [], []
        autostart_missing = False
        for path in definitions:
            name = posixpath.basename(path).removesuffix(".xml")
            starts = ctx.system.exists(f"{AUTOSTART}/{name}.xml")
            if starts and not ctx.system.exists(f"{RUNNING}/{name}.xml"):
                stopped.append(name)
            label = f"{name} (starts at boot)" if starts else name
            gone = sorted(
                f"{label}: {what} {file}"
                for what, file in needed_files(ctx.system.read_text(path) or "")
                if not ctx.system.exists(file)
            )
            missing += gone
            autostart_missing |= starts and bool(gone)
        findings = []
        if missing:
            findings.append(
                Finding(
                    Severity.CRITICAL if autostart_missing else Severity.WARNING,
                    "Virtual machines use files that don't exist",
                    detail="A virtual machine won't start while its disk image, device or "
                    "emulator is missing. Upgrades sometimes rename emulators (such as "
                    "/usr/bin/kvm), and disks may live on a filesystem that isn't mounted.",
                    evidence=truncate_evidence(missing),
                    remediation=[
                        "Mount or restore the missing disks, or point the domain at the "
                        "right path: sudo virsh edit NAME",
                        "For a missing emulator, use the one this release installs, "
                        "e.g. /usr/bin/qemu-system-x86_64",
                    ],
                )
            )
        if stopped:
            findings.append(
                Finding(
                    Severity.WARNING,
                    "Virtual machines set to start at boot aren't running",
                    detail="libvirt starts them when it starts; they may have failed to "
                    "start, been shut down since, or libvirt itself isn't running.",
                    evidence=truncate_evidence(stopped),
                    remediation=[
                        *(f"sudo virsh start {n}" for n in stopped[:5]),
                        "sudo systemctl status libvirtd",
                    ],
                )
            )
        return findings
