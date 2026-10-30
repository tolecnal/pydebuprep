from __future__ import annotations

import re

from pydebuprep.checks._probes import (
    CREDENTIALS_OPTION,
    PROBE_OPTION,
    PROBE_TIMEOUT,
    first_lines,
    validate_credentials_file,
)
from pydebuprep.checks._systemd import active_services
from pydebuprep.checks.base import Check, CheckSkipped, Context, run_checked
from pydebuprep.model import Finding, Severity
from pydebuprep.system import CommandResult

MARIADBD_VERSION = ("mariadbd", "--version")
UPGRADE_INFO = ("/var/lib/mysql/mariadb_upgrade_info", "/var/lib/mysql/mysql_upgrade_info")
MAJOR_MINOR = re.compile(r"(\d+)\.(\d+)")
# (server, admin tool, client) per flavour; MariaDB first, as it ships the MySQL names too.
FLAVOURS = {
    "MariaDB": ("mariadbd", ("mariadb-admin", "mysqladmin"), ("mariadb", "mysql")),
    "MySQL": ("mysqld", ("mysqladmin",), ("mysql",)),
}
QUERY = ("-N", "-B", "-e", "SELECT 1", "information_schema")
ACCESS_DENIED = "Access denied"
SERVICES = {"mariadb.service", "mysql.service", "mysqld.service"}


def _major_minor(text: str) -> tuple[int, int] | None:
    m = MAJOR_MINOR.search(text)
    return (int(m.group(1)), int(m.group(2))) if m else None


class MariaDbCheck(Check):
    id = "mariadb"
    title = "MariaDB and MySQL"
    category = "applications"
    requires_root = True  # the data directory is readable by mysql and root only
    options = (PROBE_OPTION, CREDENTIALS_OPTION)

    def validate(self) -> None:
        validate_credentials_file(self.opt("credentials_file"))

    def run(self, ctx: Context) -> list[Finding]:
        flavour = next(
            (name for name, (server, _, _) in FLAVOURS.items() if ctx.system.which(server)), None
        )
        if flavour is None:
            raise CheckSkipped("neither MariaDB nor MySQL is installed")
        if flavour == "MySQL" and not self.opt("probe"):
            raise CheckSkipped("MySQL has nothing to check here besides the readiness probe")
        findings = self._upgrade_info(ctx) if flavour == "MariaDB" else []
        if self.opt("probe"):
            findings += self._probe(ctx, flavour)
        return findings

    def _probe(self, ctx: Context, flavour: str) -> list[Finding]:
        """Does the server answer a ping, and does it run a query?"""
        _, admins, clients = FLAVOURS[flavour]
        admin = next((a for a in admins if ctx.system.which(a)), None)
        client = next((c for c in clients if ctx.system.which(c)), None)
        if admin is None or client is None:
            return []  # client tools not installed: nothing to ask with
        services = active_services(ctx)
        if services is not None and not SERVICES & services:
            return []  # not running (stopped on purpose, or only used in containers)
        creds = self.opt("credentials_file")
        defaults = [f"--defaults-extra-file={creds}"] if creds else []
        ping = ctx.system.run([admin, *defaults, "ping"], timeout=PROBE_TIMEOUT)
        if ping.returncode != 0:
            return [self._login(flavour, ping) or Finding(
                Severity.WARNING,
                f"The {flavour} server doesn't answer",
                detail=f"{admin} ping got no answer" + (" (timed out)." if ping.timed_out else "."),
                evidence=first_lines(ping.stderr + ping.stdout),
                remediation=[
                    "sudo systemctl status mariadb" if flavour == "MariaDB"
                    else "sudo systemctl status mysql",
                    "sudo journalctl -u mariadb -b" if flavour == "MariaDB"
                    else "sudo journalctl -u mysql -b",
                ],
            )]  # fmt: skip
        query = ctx.system.run([client, *defaults, *QUERY], timeout=PROBE_TIMEOUT)
        if query.returncode == 0 and query.stdout.strip() == "1":
            return []
        return [self._login(flavour, query) or Finding(
            Severity.WARNING,
            f"The {flavour} server answers but doesn't run queries",
            detail="It answered a ping, but SELECT 1 on information_schema failed"
            + (" (timed out)." if query.timed_out else "."),
            evidence=first_lines(query.stderr + query.stdout),
            remediation=[f"sudo {client} -e 'SELECT 1'", "Check the server's error log"],
        )]  # fmt: skip

    @staticmethod
    def _login(flavour: str, res: CommandResult) -> Finding | None:
        if ACCESS_DENIED not in res.stderr:
            return None
        return Finding(
            Severity.INFO,
            f"Couldn't log in to the {flavour} server to probe it",
            detail="The server answered but refused the probe's login (root over the Unix "
            "socket by default), so whether it serves queries isn't known.",
            evidence=first_lines(res.stderr),
            remediation=[
                "Set checks: mariadb: credentials_file: to an option file with [client] "
                "user= and password= (for example /etc/mysql/debian.cnf where it exists)"
            ],
        )

    @staticmethod
    def _upgrade_info(ctx: Context) -> list[Finding]:
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
