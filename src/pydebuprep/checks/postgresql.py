from __future__ import annotations

import re
from typing import Any

from pydebuprep.checks.base import Check, Context, count, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence

PG_LSCLUSTERS = ("pg_lsclusters", "--no-header")
SERVER_BINARIES = "/usr/lib/postgresql/*/bin/postgres"


def _clusters(ctx: Context) -> list[tuple[str, str, str]]:
    """(version, name, status) for each cluster pg_lsclusters lists."""
    clusters = []
    for line in run_checked(ctx, PG_LSCLUSTERS).stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0].replace(".", "").isdigit():
            clusters.append((fields[0], fields[1], fields[3]))
    return clusters


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

    def run(self, ctx: Context) -> list[Finding]:
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
