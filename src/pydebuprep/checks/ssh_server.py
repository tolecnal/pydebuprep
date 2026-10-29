from __future__ import annotations

from pydebuprep.checks.base import Check, Context, output_lines, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence

SSHD_TEST = ("sshd", "-t")
# sshd checks this after parsing its config; systemd creates the directory when ssh
# starts (RuntimeDirectory=sshd), so it's missing whenever sshd isn't running.
NO_RUNTIME_DIR = "Missing privilege separation directory"
AUTHORIZED_KEYS = ("/root/.ssh/authorized_keys*", "/home/*/.ssh/authorized_keys*")


def _has_dsa_key(text: str) -> bool:
    return any(
        "ssh-dss" in line.split() for line in text.splitlines() if not line.lstrip().startswith("#")
    )


class SshServerCheck(Check):
    id = "ssh-server"
    title = "SSH server configuration"
    category = "security"
    requires_root = True
    requires_commands = ("sshd",)

    def run(self, ctx: Context) -> list[Finding]:
        findings = []
        res = run_checked(ctx, SSHD_TEST, ok_codes=None)
        problems = [
            line
            for line in output_lines(res.stderr) or output_lines(res.stdout)
            if NO_RUNTIME_DIR not in line
        ]
        if not res.ok and problems:
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    "The SSH server configuration is invalid",
                    detail="sshd will refuse to start: restarting ssh or rebooting would lock "
                    "out remote logins.",
                    evidence=truncate_evidence(problems),
                    remediation=[
                        "sudo sshd -t",
                        "Fix the configuration before restarting ssh or rebooting; keep an "
                        "existing session open while you do",
                    ],
                )
            )
        elif problems:
            findings.append(
                Finding(
                    Severity.WARNING,
                    "sshd warns about its configuration",
                    detail="Options deprecated or removed in the new OpenSSH version.",
                    evidence=truncate_evidence(problems),
                    remediation=["sudo sshd -t", "Remove or update the options it names"],
                )
            )
        dsa = [
            path
            for pattern in AUTHORIZED_KEYS
            for path in ctx.system.glob(pattern)
            if _has_dsa_key(ctx.system.read_text(path) or "")
        ]
        if dsa:
            findings.append(
                Finding(
                    Severity.WARNING,
                    "DSA keys in authorized_keys no longer work",
                    detail="OpenSSH no longer accepts ssh-dss keys, so these users can't log "
                    "in with them.",
                    evidence=truncate_evidence(dsa),
                    remediation=["Have each user switch to a new key: ssh-keygen -t ed25519"],
                )
            )
        return findings
