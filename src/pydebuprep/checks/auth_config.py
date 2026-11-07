"""The chain a login depends on: sudoers, PAM's modules and the name service's. A valid
sshd configuration doesn't help if the PAM module it ends up in is gone. Nothing is looked
up, so no directory server is contacted."""

from __future__ import annotations

from typing import Any

from pydebuprep.checks.base import Check, Context, output_lines, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence

VISUDO = ("visudo", "-c")
PAM_DIR = "/etc/pam.d"
NSSWITCH = "/etc/nsswitch.conf"
PAM_TYPES = frozenset({"auth", "account", "password", "session"})
PAM_MODULE_DIRS = ("/lib/*/security", "/usr/lib/*/security", "/lib/security", "/usr/lib/security")
NSS_LIBRARY_DIRS = ("/lib/*", "/usr/lib/*", "/lib", "/usr/lib")
OPTIONAL = "optional"  # PAM carries on without it
IGNORED = "ignored"
SKIPPED = frozenset({OPTIONAL, IGNORED})  # losing one of these isn't worth reporting
INCLUDING = frozenset({"include", "substack"})  # these name another file, not a module
# Without these, people can't log in, or can't get root.
LOGIN_PATHS = frozenset(
    {
        "common-auth", "common-account", "common-password", "common-session",
        "common-session-noninteractive", "sshd", "sudo", "su", "login", "other",
    }
)  # fmt: skip
# Where a missing module changes who can log in or what resolves. Stock files also name db and
# nis for others, such as protocols and netgroup, which are normally absent and don't matter.
NSS_DATABASES = frozenset({"passwd", "group", "shadow", "gshadow", "hosts", "sudoers"})
# Part of glibc since 2.34, older than every release pydebuprep supports.
NSS_BUILT_IN = frozenset({"files", "dns"})


def _pam_modules(text: str) -> list[tuple[str, str]]:
    """(module, control) for each line of a PAM service file. A leading - on the type means
    the module may be missing, and so does module_unknown=ignore: both count as IGNORED."""
    modules = []
    for line in text.splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) < 3 or fields[0].lstrip("-") not in PAM_TYPES:
            continue
        at = 1
        if fields[1].startswith("["):  # [success=ok default=ignore]: words up to the bracket
            while at < len(fields) - 1 and not fields[at].endswith("]"):
                at += 1
        control = " ".join(fields[1 : at + 1])
        module = fields[at + 1] if at + 1 < len(fields) else ""
        if control not in INCLUDING and module.endswith(".so"):
            ignored = fields[0].startswith("-") or "module_unknown=ignore" in control
            modules.append((module, IGNORED if ignored else control))
    return modules


def _pam_services(ctx: Context) -> dict[str, list[tuple[str, str]]]:
    """Service -> its modules. A name with a dot is a leftover, such as x.dpkg-old."""
    services = {}
    for path in ctx.system.glob(f"{PAM_DIR}/*"):
        name = path.rsplit("/", 1)[1]
        if "." not in name:
            services[name] = _pam_modules(ctx.system.read_text(path) or "")
    return services


def _nss_services(ctx: Context) -> dict[str, list[str]]:
    """Database -> the services nsswitch.conf names for it."""
    databases = {}
    for line in (ctx.system.read_text(NSSWITCH) or "").splitlines():
        name, colon, rest = line.split("#", 1)[0].partition(":")
        if colon and name.strip() in NSS_DATABASES:
            databases[name.strip()] = [w for w in rest.split() if not w.startswith("[")]
    return databases


def _pam_module_exists(ctx: Context, module: str) -> bool:
    if module.startswith("/"):
        return ctx.system.exists(module)
    return any(ctx.system.glob(f"{folder}/{module}") for folder in PAM_MODULE_DIRS)


def _nss_service_exists(ctx: Context, service: str) -> bool:
    name = f"libnss_{service}.so.2"
    return service in NSS_BUILT_IN or any(
        ctx.system.glob(f"{folder}/{name}") for folder in NSS_LIBRARY_DIRS
    )


class AuthConfigCheck(Check):
    id = "auth-config"
    title = "sudoers, PAM and the name service"
    category = "security"

    def run(self, ctx: Context) -> list[Finding]:
        return [*self._sudoers(ctx), *self._pam(ctx), *self._nss(ctx)]

    @staticmethod
    def _sudoers(ctx: Context) -> list[Finding]:
        if not (ctx.is_root and ctx.system.which("visudo")):
            return []
        res = run_checked(ctx, VISUDO, ok_codes=None)
        if res.returncode == 0:
            return []
        return [
            Finding(
                Severity.CRITICAL,
                "The sudoers configuration is invalid",
                detail="sudo refuses to run, so nobody can get root that way. Keep a root "
                "session open while you fix it.",
                evidence=truncate_evidence(output_lines(res.stdout + res.stderr)),
                remediation=["sudo visudo -c", "Fix it with: sudo visudo"],
            )
        ]

    @staticmethod
    def _pam(ctx: Context) -> list[Finding]:
        checked: dict[str, bool] = {}
        missing = []
        severity = Severity.WARNING
        for service, modules in sorted(_pam_services(ctx).items()):
            for module, control in modules:
                if control == IGNORED:
                    continue
                if module not in checked:
                    checked[module] = _pam_module_exists(ctx, module)
                if not checked[module]:
                    missing.append(f"{service}: {module}")
                    if service in LOGIN_PATHS and control != OPTIONAL:
                        severity = Severity.CRITICAL
        if not missing:
            return []
        return [
            Finding(
                severity,
                "PAM uses modules that don't exist",
                detail="If a line that needs it isn't optional, this can lock people out. Keep "
                "a root session open while you fix it.",
                evidence=truncate_evidence(missing),
                remediation=[
                    "Find the package: apt-file search MODULE",
                    "Install it, or remove the line: sudo pam-auth-update",
                ],
            )
        ]

    @staticmethod
    def _nss(ctx: Context) -> list[Finding]:
        missing = sorted(
            f"{database}: {service}"
            for database, services in _nss_services(ctx).items()
            for service in services
            if not _nss_service_exists(ctx, service)
        )
        if not missing:
            return []
        return [
            Finding(
                Severity.WARNING,
                "The name service uses modules that don't exist",
                detail="They're skipped without a word, so users or hosts they provide can't "
                "be found.",
                evidence=truncate_evidence(missing),
                remediation=["Install the module's package, such as libnss-sss or libnss-ldapd"],
            )
        ]

    def collect_baseline(self, ctx: Context) -> Any:
        return {
            "pam": {
                service: sorted({m for m, control in modules if control not in SKIPPED})
                for service, modules in _pam_services(ctx).items()
            },
            "nss": _nss_services(ctx),
        }

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now = self.collect_baseline(ctx)
        lost_pam = sorted(
            f"{service}: {module}"
            for service, modules in before.get("pam", {}).items()
            if service in LOGIN_PATHS
            for module in set(modules) - set(now["pam"].get(service, []))
        )
        lost_nss = sorted(
            f"{database}: {service}"
            for database, services in before.get("nss", {}).items()
            for service in set(services) - set(now["nss"].get(database, []))
        )
        findings = []
        if lost_pam:
            findings.append(
                Finding(
                    Severity.WARNING,
                    "PAM login paths lost modules since the snapshot",
                    detail="`pam-auth-update` can drop a profile, such as LDAP or SSSD, whose "
                    "package changed.",
                    evidence=truncate_evidence(lost_pam),
                    remediation=["sudo pam-auth-update"],
                )
            )
        if lost_nss:
            findings.append(
                Finding(
                    Severity.WARNING,
                    "The name service lost modules since the snapshot",
                    evidence=truncate_evidence(lost_nss),
                    remediation=["Check /etc/nsswitch.conf"],
                )
            )
        return findings
