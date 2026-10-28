"""Registry of all checks, in no particular order (reports sort them)."""

from __future__ import annotations

from collections.abc import Sequence

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
from pydebuprep.checks.debsums import DebsumsCheck
from pydebuprep.checks.dkms import DkmsCheck
from pydebuprep.checks.dmesg_errors import DmesgErrorsCheck
from pydebuprep.checks.dpkg_audit import DpkgAuditCheck
from pydebuprep.checks.dpkg_rc import DpkgRcCheck
from pydebuprep.checks.journal_errors import JournalErrorsCheck
from pydebuprep.checks.kernel_running import KernelRunningCheck
from pydebuprep.checks.needrestart import NeedrestartCheck
from pydebuprep.checks.obsolete_packages import ObsoletePackagesCheck
from pydebuprep.checks.os_release import OsReleaseCheck
from pydebuprep.checks.systemd_failed import SystemdFailedCheck
from pydebuprep.checks.systemd_timers import SystemdTimersCheck

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
]


def get_checks(only: Sequence[str] | None = None, skip: Sequence[str] = ()) -> list[Check]:
    known = {cls.id: cls for cls in ALL_CHECKS}
    for check_id in [*(only or []), *skip]:
        if check_id not in known:
            raise ValueError(f"unknown check: {check_id}")
    selected = [known[i] for i in only] if only else list(ALL_CHECKS)
    return [cls() for cls in selected if cls.id not in skip]
