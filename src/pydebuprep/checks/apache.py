from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from pydebuprep.checks._tls import (
    CERT_OPTIONS,
    TLS_PROBE_OPTION,
    TlsSite,
    apache_protocols,
    certificate_findings,
    dhparam_findings,
    name_findings,
    protocol_findings,
    served_findings,
    validate_cert_days,
)
from pydebuprep.checks._webconfig import (
    CONFIG_TEST_OPTION,
    MAX_FILES,
    MAX_STATEMENTS,
    Ref,
    config_test_findings,
    findings,
    had_listeners,
    include,
    missing_sockets,
    resolve,
    socket_path,
    truncated_finding,
    web_baseline,
    web_compare,
)
from pydebuprep.checks.base import Check, CheckSkipped, Context
from pydebuprep.model import Finding, Severity, truncate_evidence

SERVER_ROOT = "/etc/apache2"  # relative Include and LoadModule paths start here
MAIN = f"{SERVER_ROOT}/apache2.conf"
WORD = re.compile(r'"((?:\\.|[^"\\])*)"|(\S+)')
ENABLED_DIRS = ("conf-enabled", "sites-enabled")  # Debian includes only *.conf from these
VHOST_OPEN, VHOST_CLOSE = "<virtualhost", "</virtualhost"

CONFIG_TEST = ("apache2ctl", "-t")
CONFIG_TEST_BINARY = "/usr/sbin/apache2ctl"
CONFIG_TEST_ERROR = re.compile(r".")
CONFIG_TEST_WARNING = re.compile(r"\bAH\d{5}:")


def directives(text: str) -> Iterator[tuple[str, list[str]]]:
    """The directives of an Apache configuration as (name, arguments); comments left
    out, continued lines joined. Of the section tags only <VirtualHost ...> and
    </VirtualHost> are kept (named "<virtualhost" and "</virtualhost")."""
    for raw in text.replace("\\\n", " ").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("<"):
            words = line.strip("<>").split()
            tag = "<" + (words[0].lower() if words else "")
            if tag in (VHOST_OPEN, VHOST_CLOSE):
                yield tag, words[1:]
            continue
        words = [m.group(1) if m.group(1) is not None else m.group(2) for m in WORD.finditer(line)]
        yield words[0], words[1:]


def address(spec: str) -> tuple[str, int] | None:
    """(address as written, "" for any; port) of `*:443`, `_default_:443`, `[::]:443`
    or `10.0.0.1:443`; None without a port."""
    host, colon, port = spec.rpartition(":")
    if not colon or not port.isdigit() or (host.startswith("[") and not host.endswith("]")):
        return None
    return ("" if host in ("*", "_default_") else host), int(port)


def server_name(value: str) -> str:
    """The host of a ServerName, which may be written [scheme://]host[:port]."""
    host = value.partition("://")[2] or value
    name, colon, port = host.rpartition(":")
    return name if colon and port.isdigit() else host


@dataclass
class _VirtualHost:
    source: str
    listen: list[tuple[str, int]]
    names: list[str] = field(default_factory=list)
    ssl: bool = False
    certificates: list[str] = field(default_factory=list)

    def site(self) -> TlsSite | None:
        if not self.ssl or not self.certificates or not self.listen:
            return None
        return TlsSite(self.source, tuple(self.names), tuple(self.certificates), tuple(self.listen))


@dataclass
class ApacheConfig:
    files: list[str] = field(default_factory=list)
    truncated: bool = False
    includes: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    sockets: list[Ref] = field(default_factory=list)
    module_paths: list[str] = field(default_factory=list)
    sites: list[TlsSite] = field(default_factory=list)
    certificates: list[tuple[str, str]] = field(default_factory=list)
    dhparams: list[tuple[str, str]] = field(default_factory=list)
    protocols: list[tuple[frozenset[str], str]] = field(default_factory=list)
    listens: list[tuple[str, int]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


class _Walker:
    """Reads apache2.conf and expands each Include where it stands, so a directive in
    an included file belongs to the virtual host that included it."""

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self.cfg = ApacheConfig()
        self.vhosts: list[_VirtualHost] = []
        self.current: _VirtualHost | None = None
        self.parsed: dict[str, list[tuple[str, list[str]]]] = {}
        self.count = 0

    def walk(self, path: str, including: tuple[str, ...] = ()) -> None:
        if path in including:
            return
        if path not in self.parsed:
            if len(self.parsed) >= MAX_FILES:
                self.cfg.truncated = True
                return
            self.parsed[path] = list(directives(self.ctx.system.read_text(path) or ""))
            self.cfg.files.append(path)
        for name, args in self.parsed[path]:
            self.count += 1
            if self.count > MAX_STATEMENTS:
                self.cfg.truncated = True
                return
            self.directive(name, args, path, (*including, path))

    def directive(self, name: str, args: list[str], path: str, chain: tuple[str, ...]) -> None:
        cfg, lower, where = self.cfg, name.lower(), f"({name} in {path})"
        # Not built from variables, or from mod_macro parameters (@name, %name)
        literal = bool(args) and not any(c in args[-1] for c in "$@%")
        if lower == VHOST_OPEN:
            self.current = _VirtualHost(path, [a for s in args if (a := address(s))])
            self.vhosts.append(self.current)
        elif lower == VHOST_CLOSE:
            self.current = None
        elif lower in ("include", "includeoptional") and args and "$" not in args[0]:
            ref = Ref(resolve(SERVER_ROOT, args[0]), f"{name} {args[0]}", path)
            found, missing = include(self.ctx, ref, optional=lower == "includeoptional")
            cfg.includes += missing
            for included in found:
                self.walk(included, chain)
        elif lower == "loadmodule" and len(args) > 1 and "$" not in args[1]:
            module = resolve(SERVER_ROOT, args[1])
            cfg.module_paths.append(module)
            if not self.ctx.system.exists(module):
                cfg.modules.append(f"{module} doesn't exist ({name} {args[0]} in {path})")
        elif lower in ("sslcertificatefile", "sslcertificatechainfile") and literal:
            certificate = resolve(SERVER_ROOT, args[0])
            cfg.certificates.append((certificate, where))
            if self.current is not None and lower == "sslcertificatefile":
                self.current.certificates.append(certificate)
        elif lower == "sslopensslconfcmd" and args[:1] == ["DHParameters"] and literal:
            cfg.dhparams.append((resolve(SERVER_ROOT, args[-1]), where))
        elif lower == "sslprotocol":
            cfg.protocols.append((apache_protocols(args), where))
        elif (
            lower == "listen" and args and (found_address := address(args[0]) or self.port(args[0]))
        ):
            cfg.listens.append(found_address)
        elif self.current is not None and lower in ("servername", "serveralias", "sslengine"):
            self.vhost_directive(self.current, lower, args)
        else:
            cfg.sockets += [Ref(s, name, path) for a in args if (s := socket_path(a))]

    @staticmethod
    def port(spec: str) -> tuple[str, int] | None:
        return ("", int(spec)) if spec.isdigit() else None

    @staticmethod
    def vhost_directive(vhost: _VirtualHost, lower: str, args: list[str]) -> None:
        if lower == "servername":
            vhost.names += [server_name(args[0])] if args else []
        elif lower == "serveralias":
            vhost.names += args
        else:
            vhost.ssl = bool(args) and args[0].lower() == "on"

    def result(self) -> ApacheConfig:
        cfg = self.cfg
        cfg.includes = list(dict.fromkeys(cfg.includes))
        cfg.modules = list(dict.fromkeys(cfg.modules))
        cfg.sites = [s for vhost in self.vhosts if (s := vhost.site())]
        for folder in ENABLED_DIRS:
            for path in self.ctx.system.glob(f"{SERVER_ROOT}/{folder}/*"):
                if not path.endswith(".conf") and path not in cfg.files:
                    cfg.skipped.append(path)
        return cfg


def read_config(ctx: Context) -> ApacheConfig:
    """What Apache's configuration names, starting at apache2.conf."""
    walker = _Walker(ctx)
    walker.walk(MAIN)
    return walker.result()


def skipped_finding(paths: list[str]) -> list[Finding]:
    if not paths:
        return []
    return [
        Finding(
            Severity.WARNING,
            "Apache ignores files in sites-enabled or conf-enabled",
            detail="Apache 2.4 on Debian and Ubuntu includes only *.conf files from these "
            "directories, so a site or configuration whose name doesn't end in .conf "
            "(common before Apache 2.4) is silently left out.",
            evidence=truncate_evidence(sorted(paths)),
            remediation=[
                "Rename the file in sites-available or conf-available to end in .conf, "
                "then enable it again: sudo a2dissite OLD && sudo a2ensite OLD.conf "
                "(a2disconf/a2enconf for conf-enabled)",
                "Then: sudo systemctl reload apache2",
            ],
        )
    ]


class ApacheCheck(Check):
    id = "apache"
    title = "Apache configuration references"
    category = "applications"
    options = (*CERT_OPTIONS, TLS_PROBE_OPTION, CONFIG_TEST_OPTION)

    def collect_baseline(self, ctx: Context) -> Any | None:
        if not ctx.system.exists(MAIN):
            return None
        cfg = read_config(ctx)
        return web_baseline(ctx, "apache2.service", cfg.files, cfg.module_paths)

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        if not isinstance(before, dict):
            return []
        cfg = read_config(ctx)
        now = web_baseline(
            ctx, "apache2.service", cfg.files, cfg.module_paths, listeners=had_listeners(before)
        )
        return web_compare(ctx, "Apache", "apache2.service", before, now)

    def validate(self) -> None:
        validate_cert_days(self.opt("cert_warning_days"), self.opt("cert_critical_days"))

    def run(self, ctx: Context) -> list[Finding]:
        if not ctx.system.exists(MAIN):
            raise CheckSkipped("Apache is not installed")
        cfg = read_config(ctx)
        found = findings(
            "Apache", "apache2", SERVER_ROOT,
            includes=cfg.includes, modules=cfg.modules, sockets=missing_sockets(ctx, cfg.sockets),
        )  # fmt: skip
        found += skipped_finding(cfg.skipped)
        found += certificate_findings(
            ctx, "Apache", cfg.certificates,
            warning_days=self.opt("cert_warning_days"),
            critical_days=self.opt("cert_critical_days"),
        )  # fmt: skip
        found += dhparam_findings(ctx, "Apache", cfg.dhparams)
        found += dhparam_findings(ctx, "Apache", cfg.certificates, required=False)
        found += protocol_findings("Apache", cfg.protocols)
        found += name_findings(ctx, "Apache", cfg.sites)
        if self.opt("tls_probe"):
            found += served_findings(ctx, "Apache", "apache2", cfg.sites)
        if self.opt("config_test") and ctx.system.exists(CONFIG_TEST_BINARY):
            found += config_test_findings(
                ctx, "Apache", CONFIG_TEST, error=CONFIG_TEST_ERROR, warning=CONFIG_TEST_WARNING
            )
        if cfg.truncated:
            found.append(truncated_finding("Apache"))
        return found
