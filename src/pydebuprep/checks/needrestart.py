from __future__ import annotations

from pydebuprep.checks.base import Check, Context, count
from pydebuprep.model import Finding, Severity, truncate_evidence

PENDING_KERNEL = {"2": "an ABI-compatible kernel upgrade", "3": "a kernel version upgrade"}


class NeedrestartCheck(Check):
    id = "needrestart"
    title = "Services using outdated libraries"
    category = "services"
    requires_root = True
    requires_commands = ("needrestart",)
    install_hint = "sudo apt install needrestart"

    def run(self, ctx: Context) -> list[Finding]:
        out = ctx.system.run(["needrestart", "-b", "-r", "l"], timeout=120).stdout
        services: list[str] = []
        kernel_state = ""
        for line in out.splitlines():
            key, _, value = line.partition(":")
            if key == "NEEDRESTART-SVC":
                services.append(value.strip())
            elif key == "NEEDRESTART-KSTA":
                kernel_state = value.strip()
        findings = []
        if services:
            services.sort()
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"{count(len(services), 'service runs', 'services run')} outdated libraries",
                    detail="These were started before their libraries were upgraded and still "
                    "use the old copies in memory.",
                    evidence=truncate_evidence(services),
                    remediation=[
                        f"sudo systemctl restart {' '.join(services)}",
                        "Or reboot the system",
                    ],
                )
            )
        if kernel_state in PENDING_KERNEL:
            findings.append(
                Finding(
                    Severity.WARNING,
                    "needrestart reports a pending kernel upgrade",
                    detail=f"needrestart detected {PENDING_KERNEL[kernel_state]}.",
                    remediation=["sudo reboot"],
                )
            )
        return findings
