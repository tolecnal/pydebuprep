"""Whether the storage under the filesystems is healthy: software RAID, LVM, encrypted devices,
swap, ZFS and Btrfs. All read from /proc, /sys and /etc, so no tool has to be installed and
no device is opened."""

from __future__ import annotations

import posixpath
import re
from typing import Any

from pydebuprep.checks.base import Check, Context, count, output_lines
from pydebuprep.checks.fstab import _unescape, swap_entries
from pydebuprep.model import Finding, Severity, truncate_evidence

MDSTAT = "/proc/mdstat"
CRYPTTAB = "/etc/crypttab"
SWAPS = "/proc/swaps"
ZFS_STATE = "/proc/spl/kstat/zfs/*/state"
BTRFS_DEVICES = "/sys/fs/btrfs/*/devinfo/*"
ARRAY = re.compile(r"^(md\S+) : (\S+)")
MEMBERS = re.compile(r"\[\d+/\d+\] \[([U_]+)\]")
ACTIVITY = re.compile(r"\b(resync|recovery|reshape|check)\s*=\s*([\d.]+%)")
# How fstab can name a swap device, and where the system links those names.
DEVICE_LINKS = {"UUID": "by-uuid", "LABEL": "by-label", "PARTUUID": "by-partuuid"}


def _arrays(ctx: Context) -> dict[str, dict[str, str]]:
    arrays: dict[str, dict[str, str]] = {}
    current: dict[str, str] = {}
    for line in (ctx.system.read_text(MDSTAT) or "").splitlines():
        array = ARRAY.match(line)
        if array:
            current = {"state": array.group(2), "members": "", "activity": ""}
            arrays[array.group(1)] = current
        elif members := MEMBERS.search(line):
            current["members"] = members.group(1)
        elif activity := ACTIVITY.search(line):
            current["activity"] = f"{activity.group(1)} = {activity.group(2)}"
    return arrays


def _open_encrypted(ctx: Context) -> list[str]:
    names = []
    for path in ctx.system.glob("/sys/block/dm-*/dm/name"):
        uuid = ctx.system.read_text(posixpath.join(posixpath.dirname(path), "uuid")) or ""
        if uuid.startswith("CRYPT-"):
            names.append((ctx.system.read_text(path) or "").strip())
    return sorted(names)


def _active_volumes(ctx: Context) -> list[str]:
    """Active LVM logical volumes. An internal device, such as a snapshot's -real or -cow, has
    a suffix after the volume's UUID. Read here because LVM's commands aren't read-only:
    even with --readonly they try to rewrite /run/lvm/hints."""
    names = []
    for path in ctx.system.glob("/sys/block/dm-*/dm/name"):
        uuid = (ctx.system.read_text(posixpath.join(posixpath.dirname(path), "uuid")) or "").strip()
        if uuid.startswith("LVM-") and "-" not in uuid[4:]:
            names.append((ctx.system.read_text(path) or "").strip())
    return sorted(names)


def _crypttab(ctx: Context) -> list[str]:
    """Names in /etc/crypttab that should be open: those not marked noauto."""
    names = []
    for line in (ctx.system.read_text(CRYPTTAB) or "").splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) >= 2 and not (len(fields) >= 4 and "noauto" in fields[3].split(",")):
            names.append(fields[0])
    return names


def _active_swaps(ctx: Context) -> list[str] | None:
    text = ctx.system.read_text(SWAPS)
    if text is None:
        return None
    return sorted(
        _unescape(line.split()[0].replace("\\040", " ")) for line in output_lines(text)[1:]
    )


def _swap_device(ctx: Context, source: str) -> str:
    kind, sep, value = source.partition("=")
    if sep and kind in DEVICE_LINKS:
        return ctx.system.realpath(f"/dev/disk/{DEVICE_LINKS[kind]}/{value}")
    return ctx.system.realpath(source)


def _pools(ctx: Context) -> dict[str, str]:
    return {
        path.split("/")[-2]: (ctx.system.read_text(path) or "").strip()
        for path in ctx.system.glob(ZFS_STATE)
    }


def _named(names: list[str], singular: str, plural: str, rest: str) -> str:
    return f"{count(len(names), singular, plural)} {rest}"


class StorageHealthCheck(Check):
    id = "storage-health"
    title = "RAID, LVM, encrypted devices, swap, ZFS and Btrfs"
    category = "storage"

    def run(self, ctx: Context) -> list[Finding]:
        return [
            *self._raid(ctx),
            *self._encrypted(ctx),
            *self._swap(ctx),
            *self._zfs(ctx),
            *self._btrfs(ctx),
        ]

    @staticmethod
    def _raid(ctx: Context) -> list[Finding]:
        degraded, rebuilding, resyncing = [], [], []
        for name, array in sorted(_arrays(ctx).items()):
            if array["state"] != "active":
                degraded.append(f"{name}: {array['state']}")
            elif "_" in array["members"]:
                if array["activity"]:
                    rebuilding.append(f"{name}: {array['activity']}")
                else:
                    degraded.append(f"{name}: [{array['members']}]")
            elif array["activity"]:
                resyncing.append(f"{name}: {array['activity']}")
        findings = []
        if degraded:
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    _named(degraded, "RAID array is", "RAID arrays are", "degraded"),
                    detail="Another failure can lose data. Fix this before rebooting.",
                    evidence=degraded,
                    remediation=["sudo mdadm --detail /dev/ARRAY", "cat /proc/mdstat"],
                )
            )
        if rebuilding:
            findings.append(
                Finding(
                    Severity.WARNING,
                    _named(rebuilding, "RAID array is", "RAID arrays are", "being rebuilt"),
                    detail="It has no redundancy until that finishes.",
                    evidence=rebuilding,
                    remediation=["Follow it with: cat /proc/mdstat"],
                )
            )
        if resyncing:
            findings.append(
                Finding(
                    Severity.INFO,
                    _named(resyncing, "RAID array is", "RAID arrays are", "resynchronising"),
                    evidence=resyncing,
                )
            )
        return findings

    @staticmethod
    def _encrypted(ctx: Context) -> list[Finding]:
        open_now = set(_open_encrypted(ctx))
        closed = [name for name in _crypttab(ctx) if name not in open_now]
        if not closed:
            return []
        return [
            Finding(
                Severity.WARNING,
                _named(
                    closed,
                    "encrypted device in crypttab isn't",
                    "encrypted devices in crypttab aren't",
                    "open",
                ),
                evidence=truncate_evidence(closed),
                remediation=["sudo cryptdisks_start NAME", "Check its entry in /etc/crypttab"],
            )
        ]

    @staticmethod
    def _swap(ctx: Context) -> list[Finding]:
        active = _active_swaps(ctx)
        if active is None:
            return []
        devices = {ctx.system.realpath(path) for path in active}
        missing = sorted(
            source
            for source, options in swap_entries(ctx)
            if "noauto" not in options.split(",") and _swap_device(ctx, source) not in devices
        )
        if not missing:
            return []
        return [
            Finding(
                Severity.WARNING,
                _named(
                    missing,
                    "swap entry in /etc/fstab isn't",
                    "swap entries in /etc/fstab aren't",
                    "active",
                ),
                evidence=truncate_evidence(missing),
                remediation=["sudo swapon --all --verbose", "swapon --show"],
            )
        ]

    @staticmethod
    def _zfs(ctx: Context) -> list[Finding]:
        unhealthy = [
            f"{name}: {state}" for name, state in sorted(_pools(ctx).items()) if state != "ONLINE"
        ]
        if not unhealthy:
            return []
        return [
            Finding(
                Severity.CRITICAL,
                _named(unhealthy, "ZFS pool isn't", "ZFS pools aren't", "healthy"),
                evidence=unhealthy,
                remediation=["sudo zpool status -v"],
            )
        ]

    @staticmethod
    def _btrfs(ctx: Context) -> list[Finding]:
        missing, errors = [], []
        for path in ctx.system.glob(BTRFS_DEVICES):
            parts = path.split("/")
            device = f"{parts[4]} device {parts[6]}"
            if (ctx.system.read_text(f"{path}/missing") or "").strip() == "1":
                missing.append(device)
            for line in output_lines(ctx.system.read_text(f"{path}/error_stats") or ""):
                fields = line.split()
                if len(fields) == 2 and fields[1] != "0":
                    errors.append(f"{device}: {line}")
        findings = []
        if missing:
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    _named(missing, "Btrfs device is", "Btrfs devices are", "missing"),
                    evidence=missing,
                    remediation=["sudo btrfs filesystem show"],
                )
            )
        if errors:
            devices = sorted({error.split(":")[0] for error in errors})
            findings.append(
                Finding(
                    Severity.WARNING,
                    _named(devices, "Btrfs device has", "Btrfs devices have", "recorded errors"),
                    evidence=truncate_evidence(errors),
                    remediation=["sudo btrfs device stats MOUNT"],
                )
            )
        return findings

    def collect_baseline(self, ctx: Context) -> Any:
        return {
            "arrays": sorted(_arrays(ctx)),
            "encrypted": _open_encrypted(ctx),
            "swaps": _active_swaps(ctx) or [],
            "pools": sorted(_pools(ctx)),
            "volumes": _active_volumes(ctx),
        }

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now = self.collect_baseline(ctx)
        rules = (
            ("arrays", Severity.CRITICAL, "RAID array", "RAID arrays", "is", "are", "gone"),
            ("encrypted", Severity.WARNING, "encrypted device", "encrypted devices", "isn't",
             "aren't", "open"),
            ("swaps", Severity.WARNING, "swap area", "swap areas", "isn't", "aren't", "active"),
            ("pools", Severity.CRITICAL, "ZFS pool", "ZFS pools", "is", "are", "gone"),
            ("volumes", Severity.WARNING, "LVM volume", "LVM volumes", "isn't", "aren't", "active"),
        )  # fmt: skip
        findings = []
        for key, severity, one, many, verb, verbs, state in rules:
            gone = sorted(set(before.get(key, [])) - set(now[key]))
            if gone:
                findings.append(
                    Finding(
                        severity,
                        f"{count(len(gone), one, many)} from before the upgrade "
                        f"{verb if len(gone) == 1 else verbs} {state}",
                        evidence=truncate_evidence(gone),
                    )
                )
        return findings
