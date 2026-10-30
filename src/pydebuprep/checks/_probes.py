"""Shared parts of the opt-in readiness probes (postgresql, mariadb, docker).

A probe talks to a running service, so the service may log the connection or count it
in its statistics; pydebuprep itself writes nothing. Probes are off unless enabled.
"""

from __future__ import annotations

from pydebuprep.checks.base import Option
from pydebuprep.model import Finding, Severity

PROBE_TIMEOUT = 10.0
PROBE_OPTION = Option(
    "probe", False, "Ask the server whether it answers (connects; off by default)"
)
CREDENTIALS_OPTION = Option(
    "credentials_file", "", "Credentials for the probe, if the default login doesn't work"
)
NEEDS_ROOT = Finding(
    Severity.INFO,
    "Readiness probes need root; not run",
    detail="The probe logs in as the service's administrative user, which needs root.",
    remediation=["Run as root: sudo pydebuprep report"],
)


def validate_credentials_file(path: str) -> None:
    if path and not path.startswith("/"):
        raise ValueError(f"credentials_file must be an absolute path: {path}")


def first_lines(text: str, limit: int = 3) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()][:limit]
