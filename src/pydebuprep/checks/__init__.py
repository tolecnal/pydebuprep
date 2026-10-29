"""Registry of all checks, in no particular order (reports sort them)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pydebuprep.checks.apparmor import AppArmorCheck
from pydebuprep.checks.apt_autoremove import AptAutoremoveCheck
from pydebuprep.checks.apt_held import AptHeldCheck
from pydebuprep.checks.apt_lists_age import AptListsAgeCheck
from pydebuprep.checks.apt_sources import AptSourcesCheck
from pydebuprep.checks.apt_upgradable import AptUpgradableCheck
from pydebuprep.checks.base import Check
from pydebuprep.checks.boot_space import BootSpaceCheck
from pydebuprep.checks.boot_time import BootTimeCheck
from pydebuprep.checks.bootloader import BootloaderCheck
from pydebuprep.checks.config_conflicts import ConfigConflictsCheck
from pydebuprep.checks.cron import CronCheck
from pydebuprep.checks.debsums import DebsumsCheck
from pydebuprep.checks.disk_space import DiskSpaceCheck
from pydebuprep.checks.dkms import DkmsCheck
from pydebuprep.checks.dmesg_errors import DmesgErrorsCheck
from pydebuprep.checks.dpkg_audit import DpkgAuditCheck
from pydebuprep.checks.dpkg_rc import DpkgRcCheck
from pydebuprep.checks.firewall import FirewallCheck
from pydebuprep.checks.fstab import FstabCheck
from pydebuprep.checks.journal_errors import JournalErrorsCheck
from pydebuprep.checks.kernel_running import KernelRunningCheck
from pydebuprep.checks.needrestart import NeedrestartCheck
from pydebuprep.checks.network import NetworkCheck
from pydebuprep.checks.obsolete_packages import ObsoletePackagesCheck
from pydebuprep.checks.os_release import OsReleaseCheck
from pydebuprep.checks.ssh_server import SshServerCheck
from pydebuprep.checks.systemd_failed import SystemdFailedCheck
from pydebuprep.checks.systemd_timers import SystemdTimersCheck
from pydebuprep.checks.time_sync import TimeSyncCheck
from pydebuprep.checks.unattended_upgrades import UnattendedUpgradesCheck

ALL_CHECKS: list[type[Check]] = [
    OsReleaseCheck,
    AptSourcesCheck,
    AptListsAgeCheck,
    DpkgAuditCheck,
    AptUpgradableCheck,
    AptHeldCheck,
    AptAutoremoveCheck,
    DpkgRcCheck,
    ObsoletePackagesCheck,
    ConfigConflictsCheck,
    DebsumsCheck,
    KernelRunningCheck,
    NeedrestartCheck,
    DkmsCheck,
    BootloaderCheck,
    BootSpaceCheck,
    SystemdFailedCheck,
    SystemdTimersCheck,
    JournalErrorsCheck,
    DmesgErrorsCheck,
    BootTimeCheck,
    FstabCheck,
    DiskSpaceCheck,
    TimeSyncCheck,
    CronCheck,
    NetworkCheck,
    FirewallCheck,
    AppArmorCheck,
    UnattendedUpgradesCheck,
    SshServerCheck,
]


def get_checks(
    only: Sequence[str] | None = None,
    skip: Sequence[str] = (),
    settings: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[Check]:
    """Instantiate checks with their settings; raises ValueError for unknown ids or bad values."""
    settings = settings or {}
    known = {cls.id: cls for cls in ALL_CHECKS}
    for check_id in [*(only or []), *skip, *settings]:
        if check_id not in known:
            raise ValueError(f"unknown check: {check_id}")
    selected = [known[i] for i in only] if only else list(ALL_CHECKS)
    return [cls(settings.get(cls.id)) for cls in selected if cls.id not in skip]


def parse_check_option(text: str) -> tuple[str, str, str]:
    """Split a --check-option argument CHECK.OPTION=VALUE."""
    key, sep, value = text.partition("=")
    check_id, dot, name = key.partition(".")
    if not (sep and dot and check_id.strip() and name.strip()):
        raise ValueError(f"invalid --check-option {text!r}: expected CHECK.OPTION=VALUE")
    return check_id.strip(), name.strip(), value
