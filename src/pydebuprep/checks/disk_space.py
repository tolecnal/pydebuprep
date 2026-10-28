from __future__ import annotations

from pydebuprep.checks._diskutil import space_findings
from pydebuprep.checks.base import Check, Context
from pydebuprep.model import Finding
from pydebuprep.system import DiskUsage

EXCLUDE = ("-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay", "-x", "efivarfs")
DF_SPACE = ("df", "-P", "-T", *EXCLUDE)
DF_INODES = ("df", "-P", "-i", *EXCLUDE)
REMEDIATION = [
    "Find what uses the space: sudo du -xh --max-depth=2 MOUNT | sort -h | tail",
    "Common culprits after an upgrade: sudo apt clean; sudo journalctl --vacuum-size=200M",
]


def _rows(text: str, mount_index: int) -> list[tuple[str, list[str]]]:
    rows = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) > mount_index:
            rows.append((" ".join(fields[mount_index:]), fields))
    return rows


def _int(value: str) -> int:
    return int(value) if value.isdigit() else 0


class DiskSpaceCheck(Check):
    id = "disk-space"
    title = "Free disk space and inodes"
    category = "storage"
    requires_commands = ("df",)

    def run(self, ctx: Context) -> list[Finding]:
        usage: dict[str, DiskUsage] = {}
        for mount, f in _rows(ctx.system.run(list(DF_SPACE)).stdout, 6):
            usage[mount] = DiskUsage(_int(f[2]) * 1024, _int(f[4]) * 1024, 0, 0)
        for mount, f in _rows(ctx.system.run(list(DF_INODES)).stdout, 5):
            entry = usage.setdefault(mount, DiskUsage(0, 0, 0, 0))
            entry.inodes_total, entry.inodes_free = _int(f[1]), _int(f[3])
        findings = []
        for mount, u in usage.items():
            if mount == "/boot" or mount.startswith("/boot/"):
                continue
            findings += space_findings(mount, u, [r.replace("MOUNT", mount) for r in REMEDIATION])
        return findings
