"""Registry of all checks, in no particular order (reports sort them)."""

from __future__ import annotations

from collections.abc import Sequence

from pydebuprep.checks.apt_autoremove import AptAutoremoveCheck
from pydebuprep.checks.apt_held import AptHeldCheck
from pydebuprep.checks.apt_lists_age import AptListsAgeCheck
from pydebuprep.checks.apt_sources import AptSourcesCheck
from pydebuprep.checks.apt_upgradable import AptUpgradableCheck
from pydebuprep.checks.base import Check
from pydebuprep.checks.dpkg_audit import DpkgAuditCheck
from pydebuprep.checks.dpkg_rc import DpkgRcCheck
from pydebuprep.checks.obsolete_packages import ObsoletePackagesCheck
from pydebuprep.checks.os_release import OsReleaseCheck

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
]


def get_checks(only: Sequence[str] | None = None, skip: Sequence[str] = ()) -> list[Check]:
    known = {cls.id: cls for cls in ALL_CHECKS}
    for check_id in [*(only or []), *skip]:
        if check_id not in known:
            raise ValueError(f"unknown check: {check_id}")
    selected = [known[i] for i in only] if only else list(ALL_CHECKS)
    return [cls() for cls in selected if cls.id not in skip]
