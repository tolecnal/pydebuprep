from __future__ import annotations

from typing import Any

from pydebuprep.checks._systemd import active_services
from pydebuprep.checks.base import Check, CheckSkipped, Context
from pydebuprep.model import Finding, Severity

TIME_SERVICES = {
    "chrony.service": "chrony",
    "systemd-timesyncd.service": "systemd-timesyncd",
    "ntpsec.service": "ntpsec",
    "ntp.service": "ntp",
    "openntpd.service": "openntpd",
}


class TimeSyncCheck(Check):
    id = "time-sync"
    title = "Time synchronisation"
    category = "services"

    def _services(self, ctx: Context) -> list[str] | None:
        active = active_services(ctx)
        if active is None:
            return None
        return sorted(name for unit, name in TIME_SERVICES.items() if unit in active)

    def run(self, ctx: Context) -> list[Finding]:
        services = self._services(ctx)
        synced = ctx.system.clock_synchronized()
        if services is None and synced is None:
            raise CheckSkipped("neither systemd nor the kernel clock state is available")
        findings = []
        if services == []:
            findings.append(
                Finding(
                    Severity.WARNING,
                    "No time synchronisation service is running",
                    detail="Releases sometimes switch time services (ntp, chrony, "
                    "systemd-timesyncd); the old one may have been removed.",
                    remediation=[
                        "sudo apt install systemd-timesyncd   # or chrony",
                        "sudo systemctl enable --now systemd-timesyncd",
                    ],
                )
            )
        if synced is False:
            findings.append(
                Finding(
                    Severity.WARNING,
                    "The system clock is not synchronised",
                    detail="Right after boot this can take a few minutes. A wrong clock "
                    "breaks TLS, Kerberos, log correlation and scheduled jobs.",
                    remediation=["timedatectl status", "chronyc tracking   # with chrony"],
                )
            )
        return findings

    def collect_baseline(self, ctx: Context) -> Any:
        return {
            "services": self._services(ctx) or [],
            "synchronized": ctx.system.clock_synchronized(),
        }

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        old, now = before.get("services") or [], self._services(ctx) or []
        if not old or not now or old == now:
            return []  # a missing service is reported by run()
        return [
            Finding(
                Severity.INFO,
                f"Time synchronisation moved from {', '.join(old)} to {', '.join(now)}",
                remediation=["Check its configuration matches what you had: servers, pools"],
            )
        ]
