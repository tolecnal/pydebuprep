from __future__ import annotations

from pydebuprep.checks.base import Check, Context, Option
from pydebuprep.model import Finding, Severity

LISTS_DIR = "/var/lib/apt/lists"
MAX_AGE_DAYS = 7


class AptListsAgeCheck(Check):
    id = "apt-lists-age"
    title = "Age of downloaded package lists"
    category = "release"
    options = (Option("max_age_days", MAX_AGE_DAYS, "Report package lists older than this"),)

    def validate(self) -> None:
        if self.opt("max_age_days") < 0:
            raise ValueError("max_age_days must not be negative")

    def run(self, ctx: Context) -> list[Finding]:
        sys = ctx.system
        files = sys.glob(f"{LISTS_DIR}/*_InRelease") + sys.glob(f"{LISTS_DIR}/*_Release")
        mtimes = [m for m in (sys.mtime(f) for f in files) if m is not None]
        if not mtimes:
            return [
                Finding(
                    Severity.WARNING,
                    "No downloaded package lists",
                    detail=f"No Release files found in {LISTS_DIR}; package checks have no data.",
                    remediation=["sudo apt update"],
                )
            ]
        days = int((sys.now().timestamp() - max(mtimes)) // 86400)
        if days <= self.opt("max_age_days"):
            return []
        return [
            Finding(
                Severity.INFO,
                f"Package lists are {days} days old",
                detail="Upgradable and obsolete-package results are based on these lists "
                "and may be stale. pydebuprep never refreshes them itself.",
                remediation=["sudo apt update, then run pydebuprep again"],
            )
        ]
