"""What a web server's configuration points at, for the nginx and apache checks.

Both read the configuration files only: `nginx -t` and `apachectl -t` would say more,
but they write PID files, caches, logs and run directories. What an upgrade typically
breaks shows in the files: links in *-enabled/ left behind by a removed package,
modules that are gone, and sockets of a service that moved (php7.4-fpm.sock after PHP
became 8.2).
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

from pydebuprep.checks.base import Context
from pydebuprep.model import Finding, Severity, truncate_evidence

# Configurations to follow at most, against include loops and enormous trees.
MAX_FILES = 500
GLOB = re.compile(r"[*?\[]")
SOCKET = re.compile(r"unix:(/[^\s:;|\"']+)")


@dataclass(frozen=True)
class Ref:
    """A file or socket the configuration names: PATH, from DIRECTIVE (as written) in
    the configuration file SOURCE."""

    path: str
    directive: str
    source: str

    @property
    def where(self) -> str:
        return f"({self.directive} in {self.source})"


def resolve(base: str, path: str) -> str:
    return posixpath.normpath(posixpath.join(base, path))


def socket_path(argument: str) -> str | None:
    """The socket a `unix:/path` argument names; None for anything else, or a path
    built from variables, which only the server knows."""
    match = SOCKET.search(argument)
    return match.group(1) if match and "$" not in argument else None


def include(ctx: Context, ref: Ref, *, optional: bool = False) -> tuple[list[str], list[str]]:
    """The files REF includes that exist, and a line of evidence for each that doesn't. A
    pattern that matches nothing includes nothing; so does a missing OPTIONAL file."""
    if GLOB.search(ref.path):
        matches = ctx.system.glob(ref.path)[:MAX_FILES]
    elif optional and not ctx.system.exists(ref.path):
        return [], []
    else:
        matches = [ref.path]
    found, missing = [], []
    for path in matches:
        if ctx.system.exists(path):
            found.append(path)
            continue
        target = ctx.system.readlink(path)
        if target is None:
            missing.append(f"{path} doesn't exist {ref.where}")
        else:
            missing.append(f"{path}: a link to {target}, which doesn't exist {ref.where}")
    return found, missing


def missing_sockets(ctx: Context, refs: list[Ref]) -> list[str]:
    """A line of evidence for each socket in REFS that doesn't exist, naming the sockets
    that do exist next to it (a service upgraded to a new version often moved there)."""
    lines = []
    first = {(r.path, r.source): r for r in reversed(refs)}  # once per socket and file
    for ref in sorted(first.values(), key=lambda r: (r.path, r.source)):
        if ctx.system.exists(ref.path):
            continue
        folder = posixpath.dirname(ref.path)
        there = [posixpath.basename(p) for p in ctx.system.glob(f"{folder}/*.sock")]
        hint = f"; {folder} has {', '.join(there)}" if there else ""
        lines.append(f"{ref.path} {ref.where}{hint}")
    return lines


def findings(
    server: str, service: str, config_dir: str, *,
    includes: list[str], modules: list[str], sockets: list[str],
) -> list[Finding]:  # fmt: skip
    """The findings of SERVER (its systemd SERVICE, configured in CONFIG_DIR) from the
    evidence lines of missing includes, modules and sockets."""
    found = []
    if includes:
        found.append(
            Finding(
                Severity.CRITICAL,
                f"{server} includes files that don't exist",
                detail=f"{server} refuses to start or reload while an included file is "
                "missing. A link in an *-enabled directory often outlives the package that "
                "provided its target.",
                evidence=truncate_evidence(includes),
                remediation=[
                    f"List the broken links: sudo find {config_dir} -xtype l",
                    "Remove links whose package is gone (or reinstall the package), and fix "
                    "or remove includes of files that no longer exist",
                    f"Then: sudo systemctl reload {service}",
                ],
            )
        )
    if modules:
        found.append(
            Finding(
                Severity.CRITICAL,
                f"{server} loads modules that don't exist",
                detail=f"{server} refuses to start or reload while a module it loads is "
                "missing, usually because the module's package was removed or renamed in "
                "the new release.",
                evidence=truncate_evidence(modules),
                remediation=[
                    "Install the module's package for this release, or disable the module",
                    f"Then: sudo systemctl reload {service}",
                ],
            )
        )
    if sockets:
        found.append(
            Finding(
                Severity.WARNING,
                f"{server} passes requests to sockets that don't exist",
                detail="Requests sent there fail (502 Bad Gateway). After an upgrade a "
                "service often listens on a new socket, such as the next PHP version's "
                "FPM; or the service isn't running.",
                evidence=truncate_evidence(sockets),
                remediation=[
                    "Point the configuration at the socket that exists now, or start the "
                    "service that provides it",
                    f"Then: sudo systemctl reload {service}",
                ],
            )
        )
    return found
