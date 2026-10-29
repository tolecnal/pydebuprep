from __future__ import annotations

import re

from pydebuprep.checks.base import Check, Context, run_checked
from pydebuprep.model import Finding, Severity

MARIADBD_VERSION = ("mariadbd", "--version")
UPGRADE_INFO = ("/var/lib/mysql/mariadb_upgrade_info", "/var/lib/mysql/mysql_upgrade_info")
MAJOR_MINOR = re.compile(r"(\d+)\.(\d+)")


def _major_minor(text: str) -> tuple[int, int] | None:
    m = MAJOR_MINOR.search(text)
    return (int(m.group(1)), int(m.group(2))) if m else None


class MariaDbCheck(Check):
    id = "mariadb"
    title = "MariaDB data directory"
    category = "applications"
    requires_root = True  # the data directory is readable by mysql and root only
    requires_commands = ("mariadbd",)

    def run(self, ctx: Context) -> list[Finding]:
        server_out = run_checked(ctx, MARIADBD_VERSION).stdout
        server = _major_minor(server_out.split("Ver", 1)[-1])
        info = next((t for p in UPGRADE_INFO if (t := ctx.system.read_text(p)) is not None), None)
        data = _major_minor(info) if info else None
        if server is None or data is None or data >= server:
            return []
        return [
            Finding(
                Severity.WARNING,
                f"MariaDB data was last upgraded for {data[0]}.{data[1]}; the server is "
                f"{server[0]}.{server[1]}",
                detail="System tables need upgrading after a new major version; until then "
                "some features and permissions may misbehave.",
                remediation=["sudo mariadb-upgrade"],
            )
        ]
