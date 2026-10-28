from __future__ import annotations

import fnmatch

from pydebuprep.checks._diskutil import THRESHOLD_OPTIONS, space_findings, validate_thresholds
from pydebuprep.checks.base import Check, Context, Option, run_checked
from pydebuprep.model import Finding
from pydebuprep.system import DiskUsage

EXCLUDE = ("-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay", "-x", "efivarfs")
# -l limits df to local filesystems, leaving out NFS, CIFS and other network mounts.
DF_SPACE = ("df", "-P", "-T", "-l", *EXCLUDE)
DF_INODES = ("df", "-P", "-i", "-l", *EXCLUDE)
DF_SPACE_ALL = ("df", "-P", "-T", *EXCLUDE)
DF_INODES_ALL = ("df", "-P", "-i", *EXCLUDE)
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
    options = (
        Option(
            "include_remote",
            False,
            "Also check network and FUSE filesystems (NFS, CIFS, sshfs, rclone, ...)",
        ),
        *THRESHOLD_OPTIONS,
        Option("exclude_mounts", [], "Mount points to leave out (shell-style patterns)"),
    )

    def validate(self) -> None:
        validate_thresholds(self)

    def _excluded(self, mount: str) -> bool:
        if mount == "/boot" or mount.startswith("/boot/"):
            return True  # boot-space covers these
        return any(fnmatch.fnmatchcase(mount, p) for p in self.opt("exclude_mounts"))

    def run(self, ctx: Context) -> list[Finding]:
        remote = self.opt("include_remote")
        space_argv, inode_argv = (DF_SPACE_ALL, DF_INODES_ALL) if remote else (DF_SPACE, DF_INODES)
        usage: dict[str, DiskUsage] = {}
        fuse: set[str] = set()
        # df exits 1 when some mount is unreadable but still reports the others.
        for mount, f in _rows(run_checked(ctx, space_argv, ok_codes=(0, 1)).stdout, 6):
            if f[1].startswith("fuse."):
                fuse.add(mount)
                if not remote:
                    continue  # rclone, sshfs, gvfs, ...: not local storage
            usage[mount] = DiskUsage(_int(f[2]) * 1024, _int(f[4]) * 1024, 0, 0)
        for mount, f in _rows(run_checked(ctx, inode_argv, ok_codes=(0, 1)).stdout, 5):
            if mount in fuse:
                continue  # FUSE filesystems report meaningless inode counts
            entry = usage.setdefault(mount, DiskUsage(0, 0, 0, 0))
            entry.inodes_total, entry.inodes_free = _int(f[1]), _int(f[3])
        findings = []
        for mount, u in usage.items():
            if self._excluded(mount):
                continue
            findings += space_findings(
                mount,
                u,
                [r.replace("MOUNT", mount) for r in REMEDIATION],
                warning_pct=self.opt("warning_pct"),
                critical_pct=self.opt("critical_pct"),
            )
        return findings
