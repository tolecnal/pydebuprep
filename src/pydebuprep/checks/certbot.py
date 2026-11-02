"""certbot renewals that will fail, and certificates certbot hasn't renewed.

A renewal runs weeks after the upgrade, with whatever the upgrade left: a DNS plugin
installed with pip for the old Python, or certbot's own virtualenv built on a Python
that is gone, fails then, and the certificate expires. Read from certbot's renewal
configurations and Python's package metadata; certbot itself is never run.
"""

from __future__ import annotations

import posixpath
import re

from pydebuprep.checks._tls import CERT_OPTIONS, certificate_findings, validate_cert_days
from pydebuprep.checks.base import Check, CheckSkipped, Context
from pydebuprep.model import Finding, Severity, truncate_evidence

CONF_DIR = "/etc/letsencrypt"
RENEWAL_DIR = f"{CONF_DIR}/renewal"
CERTBOT_PATHS = ("/usr/bin/certbot", "/usr/local/bin/certbot")
SNAP_CERTBOT = "/snap/bin/certbot"
OPT_CERTBOT = "/opt/*/bin/certbot"  # certbot's own instructions for pip install it there
SYSTEM_PYTHON = "/usr/bin/python3"
DIST_PACKAGES = "/usr/lib/python3/dist-packages"
PYTHON_NAME = re.compile(r"python(\d+\.\d+)")
BUILT_IN = {"standalone", "webroot", "manual", "null"}
VENV_VERSION = re.compile(r"^\s*(?:version|version_info)\s*=\s*(\d+)\.(\d+)", re.M)
VENV_HOME = re.compile(r"^\s*home\s*=\s*(\S+)", re.M)
DRY_RUN = "Then confirm renewals work: sudo certbot renew --dry-run"


def _settings(text: str, section: str | None) -> dict[str, str]:
    """key = value lines of SECTION (None: the lines before the first section)."""
    found: dict[str, str] = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
        elif "=" in line and not line.startswith("#") and current == section:
            key, _, value = line.partition("=")
            found[key.strip()] = value.strip()
    return found


def renewal_plugins(text: str) -> tuple[str | None, str | None]:
    """The (authenticator, installer) of a renewal configuration; None for none."""
    params = _settings(text, "renewalparams")
    installer = params.get("installer")
    return params.get("authenticator"), None if installer in (None, "None") else installer


def interpreter(text: str) -> str | None:
    """The Python a script's #! line runs, or None without one."""
    first = text.splitlines()[0] if text else ""
    if not first.startswith("#!"):
        return None
    words = first[2:].split()
    if words[:1] == ["/usr/bin/env"]:
        program = next((w for w in words[1:] if not w.startswith("-")), None)
        return f"/usr/bin/{program}" if program else None
    return words[0] if words else None


def _venv(ctx: Context, python: str) -> tuple[str, str | None, str | None] | None:
    """(directory, X.Y, home) of the virtualenv PYTHON belongs to, or None."""
    root = posixpath.dirname(posixpath.dirname(python))
    text = ctx.system.read_text(f"{root}/pyvenv.cfg")
    if text is None:
        return None
    version = VENV_VERSION.search(text)
    home = VENV_HOME.search(text)
    return (
        root,
        f"{version.group(1)}.{version.group(2)}" if version else None,
        home.group(1) if home else None,
    )


def _python_version(ctx: Context, python: str) -> str | None:
    """X.Y of a system Python, from its name or the name it links to (python3 →
    python3.11)."""
    for name in (python, ctx.system.readlink(python) or ""):
        match = PYTHON_NAME.fullmatch(posixpath.basename(name))
        if match:
            return match.group(1)
    return None


def site_dirs(ctx: Context, python: str) -> list[str]:
    """Where PYTHON finds installed packages (glob patterns)."""
    venv = _venv(ctx, python)
    if venv is None:
        # Only the current Python's /usr/local directory: one left by the old Python
        # after an upgrade (apt never cleans /usr/local) isn't what certbot loads.
        version = _python_version(ctx, python)
        return [DIST_PACKAGES, f"/usr/local/lib/python{version or '3.*'}/dist-packages"]
    root, version, _ = venv
    return [f"{root}/lib/python{version or '3*'}/site-packages"]


def installed_plugins(ctx: Context, dirs: list[str]) -> set[str]:
    """The certbot plugins whose packages are in DIRS."""
    names: set[str] = set()
    for folder in dirs:
        for kind in ("dist-info", "egg-info"):
            for path in ctx.system.glob(f"{folder}/*.{kind}/entry_points.txt"):
                names |= set(_settings(ctx.system.read_text(path) or "", "certbot.plugins"))
    return names


class CertbotCheck(Check):
    id = "certbot"
    title = "certbot renewals"
    category = "applications"
    options = CERT_OPTIONS

    def validate(self) -> None:
        validate_cert_days(self.opt("cert_warning_days"), self.opt("cert_critical_days"))

    def run(self, ctx: Context) -> list[Finding]:
        renewals = ctx.system.glob(f"{RENEWAL_DIR}/*.conf")
        if not renewals:
            raise CheckSkipped("certbot has no renewals configured")
        texts = {path: ctx.system.read_text(path) or "" for path in renewals}
        found = self._installation(ctx, texts)
        certificates = [
            (
                _settings(text, None).get("cert")
                or f"{CONF_DIR}/live/{posixpath.basename(path).removesuffix('.conf')}/cert.pem",
                f"(renewal/{posixpath.basename(path)})",
            )
            for path, text in texts.items()
        ]
        found += certificate_findings(
            ctx, "certbot", certificates,
            warning_days=self.opt("cert_warning_days"),
            critical_days=self.opt("cert_critical_days"),
        )  # fmt: skip
        return found

    def _installation(self, ctx: Context, texts: dict[str, str]) -> list[Finding]:
        candidates = [*CERTBOT_PATHS, *ctx.system.glob(OPT_CERTBOT)]
        script = next((p for p in candidates if ctx.system.exists(p)), None)
        if script is None:
            if ctx.system.exists(SNAP_CERTBOT):
                return [
                    Finding(
                        Severity.INFO,
                        "certbot is a snap; its plugins aren't checked",
                        detail="Snap plugins are snaps of their own, connected to certbot's.",
                    )
                ]
            return [
                Finding(
                    Severity.WARNING,
                    "certbot renewals are configured but certbot wasn't found",
                    detail="Nothing on this host renews these certificates, unless certbot "
                    "runs somewhere else (in a container with /etc/letsencrypt mounted, say).",
                    evidence=truncate_evidence(sorted(texts)),
                    remediation=["sudo apt install certbot", DRY_RUN],
                )
            ]
        python = interpreter(ctx.system.read_text(script) or "") or SYSTEM_PYTHON
        if problem := self._missing_interpreter(ctx, script, python):
            return [
                Finding(
                    Severity.CRITICAL,
                    "certbot's Python interpreter is missing",
                    detail="certbot can't start, so no certificate is renewed.",
                    evidence=[problem],
                    remediation=[
                        "Reinstall certbot (sudo apt install --reinstall certbot, or recreate "
                        "its virtualenv with the current Python)",
                        DRY_RUN,
                    ],
                )
            ]
        return self._plugins(ctx, texts, python)

    @staticmethod
    def _missing_interpreter(ctx: Context, script: str, python: str) -> str | None:
        if not ctx.system.exists(python):
            return f"{python} doesn't exist (#! line of {script})"
        venv = _venv(ctx, python)
        if venv is not None:
            _, version, home = venv
            base = f"{home}/python{version}"
            if version and home and not ctx.system.exists(base):
                return (
                    f"{python}: the virtualenv was made with Python {version}, and {base} is gone"
                )
        return None

    @staticmethod
    def _plugins(ctx: Context, texts: dict[str, str], python: str) -> list[Finding]:
        installed = installed_plugins(ctx, site_dirs(ctx, python))
        missing = []
        for path, text in texts.items():
            for role, name in zip(
                ("authenticator", "installer"), renewal_plugins(text), strict=True
            ):
                if name and name not in BUILT_IN and name not in installed:
                    missing.append(f"{posixpath.basename(path)}: {role} {name}")
        if not missing:
            return []
        return [
            Finding(
                Severity.CRITICAL,
                "certbot renewals use plugins that aren't installed",
                detail="The next renewal of these certificates fails. A plugin installed "
                "with pip belongs to the Python it was installed for, which the upgrade "
                "may have replaced.",
                evidence=truncate_evidence(missing),
                remediation=[
                    "Install the plugins for this release (sudo apt install "
                    "python3-certbot-dns-NAME, python3-certbot-nginx, python3-certbot-apache)",
                    DRY_RUN,
                ],
            )
        ]
