from __future__ import annotations

import re
from typing import Any

from pydebuprep.checks._probes import (
    CREDENTIALS_OPTION,
    NEEDS_ROOT,
    PROBE_OPTION,
    PROBE_TIMEOUT,
    first_lines,
    validate_credentials_file,
)
from pydebuprep.checks.base import Check, Context, count, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.system import AS_POSTGRES, PG_SOCKET_DIR, PSQL_FLAGS

PG_LSCLUSTERS = ("pg_lsclusters", "--no-header")
SERVER_BINARIES = "/usr/lib/postgresql/*/bin/postgres"
LOGIN_ERRORS = ("authentication failed", "no password supplied", "password authentication")
NOT_READY = {1: "rejecting connections (starting or shutting down)", 2: "not responding"}


def _clusters(ctx: Context) -> list[tuple[str, str, str]]:
    """(version, name, status) for each cluster pg_lsclusters lists."""
    return [(v, n, status) for v, n, _, status in _cluster_rows(ctx)]


def _cluster_rows(ctx: Context) -> list[tuple[str, str, str, str]]:
    """(version, name, port, status) for each cluster pg_lsclusters lists."""
    clusters = []
    for line in run_checked(ctx, PG_LSCLUSTERS).stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0].replace(".", "").isdigit():
            clusters.append((fields[0], fields[1], fields[2], fields[3]))
    return clusters


def _pgpass_user(text: str | None) -> str | None:
    """The user of the first entry of a .pgpass file (host:port:database:user:password)."""
    for line in (text or "").splitlines():
        fields = line.split(":")
        if line.strip() and not line.startswith("#") and len(fields) >= 5 and fields[3] != "*":
            return fields[3]
    return None


def _newest_server(ctx: Context) -> str | None:
    versions = [
        m.group(1)
        for path in ctx.system.glob(SERVER_BINARIES)
        if (m := re.search(r"/postgresql/([\d.]+)/bin/", path))
    ]
    return max(versions, key=lambda v: [int(p) for p in v.split(".")]) if versions else None


def _starts_automatically(ctx: Context, version: str, name: str) -> bool:
    text = ctx.system.read_text(f"/etc/postgresql/{version}/{name}/start.conf") or "auto"
    words = [
        line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")
    ]
    return (words[0] if words else "auto") == "auto"


class PostgresqlCheck(Check):
    id = "postgresql"
    title = "PostgreSQL clusters"
    category = "applications"
    requires_commands = ("pg_lsclusters",)
    options = (PROBE_OPTION, CREDENTIALS_OPTION)

    def validate(self) -> None:
        validate_credentials_file(self.opt("credentials_file"))

    def run(self, ctx: Context) -> list[Finding]:
        findings = self._versions(ctx)
        if self.opt("probe"):
            findings += self._probe(ctx)
        return findings

    def _probe(self, ctx: Context) -> list[Finding]:
        """Each online cluster: does it accept connections, and does it answer a query?"""
        online = [(v, n, port) for v, n, port, status in _cluster_rows(ctx) if status == "online"]
        if not online:
            return []
        if not ctx.is_root:
            return [NEEDS_ROOT]
        creds = self.opt("credentials_file")
        user = _pgpass_user(ctx.system.read_text(creds)) if creds else None
        if creds and user is None:
            return [
                Finding(
                    Severity.INFO,
                    f"Can't use the PostgreSQL credentials file {creds}",
                    detail="It's missing, unreadable, or has no entry with a user name "
                    "(host:port:database:user:password).",
                    remediation=[f"sudo ls -l {creds}", "See: man psql (the .pgpass file)"],
                )
            ]
        findings = []
        for version, name, port in online:
            label = f"{version}/{name}"
            ready = ctx.system.run(
                ["pg_isready", "-h", PG_SOCKET_DIR, "-p", port], timeout=PROBE_TIMEOUT
            )
            if ready.returncode != 0:
                findings.append(
                    Finding(
                        Severity.WARNING,
                        f"PostgreSQL cluster {label} doesn't accept connections",
                        detail="pg_lsclusters lists it as online, but pg_isready says it is "
                        f"{NOT_READY.get(ready.returncode, 'not reachable')}.",
                        evidence=first_lines(ready.stdout + ready.stderr),
                        remediation=[
                            f"sudo systemctl status postgresql@{version}-{name}",
                            f"sudo tail -n 50 /var/log/postgresql/postgresql-{version}-{name}.log",
                        ],
                    )
                )
                continue
            if user:
                conninfo = (
                    f"host={PG_SOCKET_DIR} port={port} dbname=postgres user={user} passfile={creds}"
                )
                argv = [*PSQL_FLAGS, "-d", conninfo, "-c", "SELECT 1"]
            else:
                argv = [*AS_POSTGRES, *PSQL_FLAGS, "-h", PG_SOCKET_DIR, "-p", port,
                        "-d", "postgres", "-c", "SELECT 1"]  # fmt: skip
            res = ctx.system.run(argv, timeout=PROBE_TIMEOUT)
            if res.returncode == 0 and res.stdout.strip() == "1":
                continue
            if any(e in res.stderr for e in LOGIN_ERRORS):
                findings.append(
                    Finding(
                        Severity.INFO,
                        f"Couldn't log in to PostgreSQL cluster {label} to probe it",
                        detail="The server answered but refused the probe's login, so "
                        "whether it serves queries isn't known.",
                        evidence=first_lines(res.stderr),
                        remediation=[
                            "Set checks: postgresql: credentials_file: to a .pgpass file "
                            "for a user that may connect to the postgres database"
                        ],
                    )
                )
                continue
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"PostgreSQL cluster {label} accepts connections but doesn't answer queries",
                    detail="It answered pg_isready but a SELECT 1 on the postgres database "
                    "failed" + (" (timed out)." if res.timed_out else "."),
                    evidence=first_lines(res.stderr),
                    remediation=[
                        f"sudo tail -n 50 /var/log/postgresql/postgresql-{version}-{name}.log",
                        f"sudo -u postgres psql -p {port} -c 'SELECT 1'",
                    ],
                )
            )
        return findings

    def _versions(self, ctx: Context) -> list[Finding]:
        clusters = _clusters(ctx)
        newest = _newest_server(ctx)
        findings = []
        for version, name, status in clusters:
            if newest and float(version) < float(newest):
                migrated = any(v == newest and n == name for v, n, _ in clusters)
                findings.append(
                    Finding(
                        Severity.WARNING,
                        f"PostgreSQL cluster {version}/{name} still uses version {version}; "
                        f"{newest} is installed",
                        detail="A release upgrade installs the new server but leaves existing "
                        "clusters on the old version until they are migrated.",
                        remediation=[
                            f"Check {newest}/{name} has your data, then: sudo pg_dropcluster "
                            f"{version} {name}"
                            if migrated
                            else f"sudo pg_upgradecluster {version} {name}",
                            "See /usr/share/doc/postgresql-common/README.Debian.gz",
                        ],
                    )
                )
            elif status != "online" and _starts_automatically(ctx, version, name):
                findings.append(
                    Finding(
                        Severity.WARNING,
                        f"PostgreSQL cluster {version}/{name} is down",
                        detail="Its start.conf says it should start automatically.",
                        remediation=[
                            f"sudo systemctl status postgresql@{version}-{name}",
                            f"sudo tail -n 50 /var/log/postgresql/postgresql-{version}-{name}.log",
                        ],
                    )
                )
        return findings

    def collect_baseline(self, ctx: Context) -> Any:
        return sorted(f"{v}/{n}" for v, n, status in _clusters(ctx) if status.startswith("online"))

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now = set(self.collect_baseline(ctx))
        gone = sorted(c for c in before if c not in now)
        if not gone:
            return []
        return [
            Finding(
                Severity.WARNING,
                "PostgreSQL clusters online before the upgrade aren't now",
                detail=f"{count(len(gone), 'cluster')}; a migrated cluster may have a new version.",
                evidence=truncate_evidence(gone),
                remediation=["pg_lsclusters"],
            )
        ]
