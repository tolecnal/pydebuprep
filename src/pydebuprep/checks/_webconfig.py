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
from typing import Any

from pydebuprep.checks._listeners import listening_sockets, unit_listeners
from pydebuprep.checks.base import Context
from pydebuprep.model import Finding, Severity, truncate_evidence

# Configurations to follow at most, against include loops and enormous trees.
MAX_FILES = 500
GLOB = re.compile(r"[*?\[]")
SOCKET = re.compile(r"unix:(/[^\s:;|\"']+)")
# PHP is the one thing Debian and Ubuntu version in module and file names: php7.4.load,
# libphp8.2.so, php8.2-fpm.conf. An upgrade replacing one version with another is a
# change, not a loss.
PHP_VERSION = re.compile(r"php\d+(?:\.\d+)?")


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


def unversioned(name: str) -> str:
    """NAME with any PHP version replaced by `php*`."""
    return PHP_VERSION.sub("php*", name)


def _listeners(ctx: Context, unit: str) -> list[str]:
    """The ports UNIT's processes listen on; empty unless root and the unit is active."""
    from pydebuprep.checks.systemd_critical import unit_states  # avoids an import cycle

    if not ctx.is_root:
        return []  # other users' /proc/<pid>/fd links can't be read
    state = unit_states(ctx, [unit]).get(unit, {})
    if state.get("ActiveState") != "active":
        return []
    return unit_listeners(ctx.system, state.get("ControlGroup", ""), listening_sockets(ctx.system))


def web_baseline(
    ctx: Context, unit: str, cfg_files: list[str], modules: list[str], *, listeners: bool = True
) -> dict[str, list[str]]:
    """What a snapshot keeps of a web server: the modules it loads (file names), the
    configuration files it reads and, as root, the ports its unit listens on (looked
    up only with LISTENERS)."""
    return {
        "modules": sorted({posixpath.basename(m) for m in modules}),
        "files": list(cfg_files),
        "listeners": _listeners(ctx, unit) if listeners else [],
    }


def had_listeners(before: Any) -> bool:
    """Whether a snapshot recorded listeners, so they need looking up now."""
    return isinstance(before, dict) and bool(_strings(before, "listeners"))


def _strings(before: dict[Any, Any], key: str) -> list[str]:
    value = before.get(key)
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _by_key(names: list[str]) -> dict[str, str]:
    return {unversioned(n): n for n in names}


def web_compare(
    ctx: Context, server: str, unit: str, before: dict[Any, Any], now: dict[str, list[str]]
) -> list[Finding]:
    """What SERVER lost since the snapshot (BEFORE, a dict of unchecked values)
    compared with NOW (web_baseline)."""
    found = []
    old, new = _by_key(_strings(before, "modules")), _by_key(now["modules"])
    lost = sorted(old[k] for k in old.keys() - new.keys())
    changed = sorted(f"{old[k]} → {new[k]}" for k in old.keys() & new.keys() if old[k] != new[k])
    if lost:
        found.append(
            Finding(
                Severity.WARNING,
                f"{server} no longer loads modules it loaded before the upgrade",
                detail="The upgrade removed or disabled them; what they provided (a "
                "language, authentication, a protocol) no longer works.",
                evidence=truncate_evidence(lost),
                remediation=[
                    "Install the module's package for this release and enable it again, "
                    "or confirm it's no longer needed"
                ],
            )
        )
    if changed:
        found.append(
            Finding(
                Severity.INFO,
                f"{server} loads a new version of modules",
                detail="Expected after a release upgrade; check that the sites using them work.",
                evidence=truncate_evidence(changed),
            )
        )
    files = sorted(
        f
        for f in _strings(before, "files")
        if unversioned(f) not in {unversioned(n) for n in now["files"]}
    )
    if files:
        found.append(
            Finding(
                Severity.WARNING,
                f"{server} no longer reads configuration files it read before the upgrade",
                detail="Sites or settings in them are gone: their package was removed, their "
                "link in an *-enabled directory was dropped, or an include no longer matches.",
                evidence=truncate_evidence(files),
                remediation=["Enable them again, or confirm they're no longer needed"],
            )
        )
    if ctx.is_root:
        ports = sorted(set(_strings(before, "listeners")) - set(now["listeners"]))
        if ports:
            found.append(
                Finding(
                    Severity.CRITICAL,
                    f"{server} listened on {', '.join(ports)} before the upgrade, not now",
                    detail="Clients of these ports can't connect.",
                    remediation=[f"systemctl status {unit}", "ss -tlpn"],
                )
            )
    return found
