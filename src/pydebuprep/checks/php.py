"""PHP extensions enabled before the upgrade that aren't enabled now.

A release upgrade moves PHP to a new version (7.4 → 8.2), and each extension is a
package of its own per version (php7.4-mysql, php8.2-mysql). The new version's
extensions are only installed if something pulls them in, so a site that worked
before fails with "Call to undefined function mysqli_connect()" after. Extensions are
enabled per SAPI by the ini files in /etc/php/<version>/<sapi>/conf.d/.
"""

from __future__ import annotations

import posixpath
import re
from typing import Any

from pydebuprep.checks.base import Check, CheckSkipped, Context
from pydebuprep.model import Finding, Severity, truncate_evidence

CONF_DIR = "/etc/php"
SAPIS = ("apache2", "cli", "fpm")
VERSION = re.compile(r"\d+\.\d+")
EXTENSION = re.compile(r"^\s*(?:zend_)?extension\s*=\s*[\"']?([^\"'\s;]+)", re.M)
# Extensions that became part of PHP itself, so they have no ini file from that version on.
BUILT_IN_SINCE = {"json": (8, 0)}
# Extensions packaged under another name (php8.2-mysql provides mysqli and pdo_mysql).
PACKAGES = {
    "mysqli": "mysql",
    "pdo_mysql": "mysql",
    "mysqlnd": "mysql",
    "pdo_pgsql": "pgsql",
    "pdo_sqlite": "sqlite3",
}

Extensions = dict[str, dict[str, list[str]]]  # version -> SAPI -> extension names


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(p) for p in text.split("."))


def enabled_extensions(ctx: Context) -> Extensions:
    """The extensions each installed PHP version enables for each SAPI."""
    found: Extensions = {}
    for sapi in SAPIS:
        for path in ctx.system.glob(f"{CONF_DIR}/*/{sapi}/conf.d/*.ini"):
            version = path.split("/")[3]
            if not VERSION.fullmatch(version):
                continue
            names = found.setdefault(version, {}).setdefault(sapi, [])
            for value in EXTENSION.findall(ctx.system.read_text(path) or ""):
                names.append(posixpath.basename(value).removesuffix(".so"))
    return {
        v: {s: sorted(set(names)) for s, names in sorted(sapis.items())}
        for v, sapis in sorted(found.items(), key=lambda item: _version(item[0]))
    }


def _by_sapi(extensions: Any) -> dict[str, dict[str, set[str]]]:
    """SAPI -> version -> extensions, from a snapshot's value (anything malformed is
    left out)."""
    result: dict[str, dict[str, set[str]]] = {}
    if not isinstance(extensions, dict):
        return result
    for version, sapis in extensions.items():
        if not (isinstance(version, str) and VERSION.fullmatch(version)) or not isinstance(
            sapis, dict
        ):
            continue
        for sapi, names in sapis.items():
            if sapi in SAPIS and isinstance(names, list):
                result.setdefault(sapi, {})[version] = {n for n in names if isinstance(n, str)}
    return result


def _built_in(extension: str, versions: list[str]) -> bool:
    since = BUILT_IN_SINCE.get(extension)
    return since is not None and all(_version(v) >= since for v in versions)


class PhpCheck(Check):
    id = "php"
    title = "PHP extensions"
    category = "applications"

    def run(self, ctx: Context) -> list[Finding]:
        if not ctx.system.exists(CONF_DIR):
            raise CheckSkipped("PHP is not installed")
        return []

    def collect_baseline(self, ctx: Context) -> Any | None:
        if not ctx.system.exists(CONF_DIR):
            return None
        return enabled_extensions(ctx)

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        then, now = _by_sapi(before), _by_sapi(enabled_extensions(ctx))
        missing, installs, gone = [], [], []
        for sapi, versions in sorted(then.items()):
            enabled = set().union(*versions.values())
            if not enabled:
                continue
            current = sorted(now.get(sapi, {}), key=_version)
            if not current:
                gone.append(sapi)
                continue
            have = set().union(*now[sapi].values())
            lost = sorted(e for e in enabled - have if not _built_in(e, current))
            if lost:
                old = ", ".join(sorted(versions, key=_version))
                missing.append(f"{sapi}: {', '.join(lost)} (enabled for PHP {old})")
                newest = current[-1]
                installs += [f"php{newest}-{PACKAGES.get(e, e)}" for e in lost]
        found = []
        if missing:
            found.append(
                Finding(
                    Severity.WARNING,
                    "PHP extensions enabled before the upgrade aren't enabled now",
                    detail="Each PHP version has its own extension packages; the new "
                    "version's are only installed if something asked for them. Code that "
                    "uses these extensions fails until they are.",
                    evidence=truncate_evidence(missing),
                    remediation=[
                        f"sudo apt install {' '.join(sorted(set(installs)))}",
                        "Then restart PHP-FPM or reload the web server",
                    ],
                )
            )
        found += [
            Finding(
                Severity.WARNING,
                f"PHP {sapi} is no longer installed for any PHP version",
                detail="It was installed before the upgrade; sites served through it no "
                "longer run PHP.",
                remediation=[f"sudo apt install php-{sapi}" if sapi != "apache2" else
                             "sudo apt install libapache2-mod-php"],
            )
            for sapi in gone
        ]  # fmt: skip
        return found
