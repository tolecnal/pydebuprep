from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from pydebuprep.checks._tls import (
    CERT_OPTIONS,
    TLS_PROBE_OPTION,
    TlsSite,
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
from pydebuprep.model import Finding

CONF_DIR = "/etc/nginx"  # relative include paths start here
PREFIX = "/usr/share/nginx"  # relative load_module paths start here (Debian's --prefix)
MAIN = f"{CONF_DIR}/nginx.conf"
TOKEN = re.compile(r'"((?:\\.|[^"\\])*)"|\'((?:\\.|[^\'\\])*)\'|#[^\n]*|([{};])|([^\s{};"\'#]+)')
DEFAULT_PORT = 80

CONFIG_TEST = ("nginx", "-t")
CONFIG_TEST_BINARY = "/usr/sbin/nginx"
CONFIG_TEST_ERROR = re.compile(r"\[(emerg|crit|alert)\]")
CONFIG_TEST_WARNING = re.compile(r"\[warn\]")


def statements(text: str) -> Iterator[tuple[str, list[str]]]:
    """The statements of an nginx configuration as (terminator, words): ";" ends a
    directive, "{" opens a block (its words are the block's name and arguments), "}"
    closes one (no words, unless a directive before it lacked its ";")."""
    words: list[str] = []
    for match in TOKEN.finditer(text):
        double, single, punctuation, word = match.groups()
        if punctuation:
            yield punctuation, words
            words = []
        elif double is not None or single is not None or word is not None:
            words.append(next(w for w in (double, single, word) if w is not None))
    if words:
        yield ";", words


def listen_address(args: list[str]) -> tuple[str, int] | None:
    """(address as written, "" for any; port) of a `listen` directive; None for a unix
    socket or an argument that isn't an address."""
    spec = args[0]
    if spec.startswith("unix:"):
        return None
    if spec.isdigit():
        return "", int(spec)
    host, colon, port = spec.rpartition(":")
    if not colon or (host.startswith("[") and not host.endswith("]")):  # no port, or "[::1]"
        host, port = spec, str(DEFAULT_PORT)
    if not port.isdigit():
        return None
    return ("" if host == "*" else host), int(port)


def literal_path(path: str) -> bool:
    """A path nginx reads as is: not built from variables, not inline data or an engine."""
    return "$" not in path and not path.startswith(("data:", "engine:"))


@dataclass
class _Server:
    source: str
    names: list[str] = field(default_factory=list)
    listen: list[tuple[tuple[str, int], bool]] = field(default_factory=list)  # (addr, ssl)
    certificates: list[str] = field(default_factory=list)
    ssl_on: bool = False

    def site(self, inherited: tuple[str, ...]) -> TlsSite | None:
        tls = [addr for addr, ssl in self.listen if ssl or self.ssl_on]
        certificates = tuple(self.certificates) or inherited
        if not tls or not certificates:
            return None
        return TlsSite(self.source, tuple(self.names), certificates, tuple(tls))


@dataclass
class NginxConfig:
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


class _Walker:
    """Reads nginx.conf and expands each include where it stands, so a directive in an
    included snippet belongs to the server block that included it."""

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self.cfg = NginxConfig()
        self.blocks: list[str] = []
        self.servers: list[_Server] = []
        self.current: _Server | None = None
        self.http_certificates: list[str] = []
        self.parsed: dict[str, list[tuple[str, list[str]]]] = {}
        self.count = 0

    def walk(self, path: str, including: tuple[str, ...] = ()) -> None:
        if path in including:
            return
        if path not in self.parsed:
            if len(self.parsed) >= MAX_FILES:
                self.cfg.truncated = True
                return
            self.parsed[path] = list(statements(self.ctx.system.read_text(path) or ""))
            self.cfg.files.append(path)
        for end, words in self.parsed[path]:
            self.count += 1
            if self.count > MAX_STATEMENTS:
                self.cfg.truncated = True
                return
            if end == "{":
                self.enter(words, path)
            elif end == "}":
                self.leave()
            elif words:
                self.directive(words[0], words[1:], path, (*including, path))

    def enter(self, words: list[str], path: str) -> None:
        name = words[0] if words else ""
        if name == "server" and self.blocks == ["http"]:
            self.current = _Server(path)
            self.servers.append(self.current)
        self.blocks.append(name)

    def leave(self) -> None:
        if self.blocks and self.blocks.pop() == "server" and self.blocks == ["http"]:
            self.current = None

    def directive(self, name: str, args: list[str], path: str, chain: tuple[str, ...]) -> None:
        if not args:
            return
        cfg, where = self.cfg, f"({name} in {path})"
        if name == "include" and "$" not in args[0]:
            ref = Ref(resolve(CONF_DIR, args[0]), f"include {args[0]}", path)
            found, missing = include(self.ctx, ref)
            cfg.includes += missing
            for included in found:
                self.walk(included, chain)
        elif name == "load_module" and "$" not in args[0]:
            module = resolve(PREFIX, args[0])
            cfg.module_paths.append(module)
            if not self.ctx.system.exists(module):
                cfg.modules.append(f"{module} doesn't exist (load_module {args[0]} in {path})")
        elif name.endswith("_pass") or name == "server":
            cfg.sockets += [Ref(s, name, path) for a in args if (s := socket_path(a))]
        elif name == "ssl_certificate" and literal_path(args[0]):
            certificate = resolve(CONF_DIR, args[0])
            cfg.certificates.append((certificate, where))
            if self.current is not None:
                self.current.certificates.append(certificate)
            elif self.blocks == ["http"]:
                self.http_certificates.append(certificate)
        elif name == "ssl_dhparam" and literal_path(args[0]):
            cfg.dhparams.append((resolve(CONF_DIR, args[0]), where))
        elif name == "ssl_protocols":
            cfg.protocols.append((frozenset(args), where))
        elif self.current is not None:
            self.server_directive(self.current, name, args)

    @staticmethod
    def server_directive(server: _Server, name: str, args: list[str]) -> None:
        if name == "server_name":
            server.names += args
        elif name == "listen" and (address := listen_address(args)):
            server.listen.append((address, "ssl" in args[1:]))
        elif name == "ssl" and args[0] == "on":
            server.ssl_on = True

    def result(self) -> NginxConfig:
        cfg = self.cfg
        cfg.includes = list(dict.fromkeys(cfg.includes))
        cfg.modules = list(dict.fromkeys(cfg.modules))
        cfg.sites = [s for srv in self.servers if (s := srv.site(tuple(self.http_certificates)))]
        return cfg


def read_config(ctx: Context) -> NginxConfig:
    """What nginx's configuration names, starting at nginx.conf."""
    walker = _Walker(ctx)
    walker.walk(MAIN)
    return walker.result()


class NginxCheck(Check):
    id = "nginx"
    title = "nginx configuration references"
    category = "applications"
    options = (*CERT_OPTIONS, TLS_PROBE_OPTION, CONFIG_TEST_OPTION)

    def collect_baseline(self, ctx: Context) -> Any | None:
        if not ctx.system.exists(MAIN):
            return None
        cfg = read_config(ctx)
        return web_baseline(ctx, "nginx.service", cfg.files, cfg.module_paths)

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        if not isinstance(before, dict):
            return []
        cfg = read_config(ctx)
        now = web_baseline(
            ctx, "nginx.service", cfg.files, cfg.module_paths, listeners=had_listeners(before)
        )
        return web_compare(ctx, "nginx", "nginx.service", before, now)

    def validate(self) -> None:
        validate_cert_days(self.opt("cert_warning_days"), self.opt("cert_critical_days"))

    def run(self, ctx: Context) -> list[Finding]:
        if not ctx.system.exists(MAIN):
            raise CheckSkipped("nginx is not installed")
        cfg = read_config(ctx)
        found = findings(
            "nginx", "nginx", CONF_DIR,
            includes=cfg.includes, modules=cfg.modules, sockets=missing_sockets(ctx, cfg.sockets),
        )  # fmt: skip
        found += certificate_findings(
            ctx, "nginx", cfg.certificates,
            warning_days=self.opt("cert_warning_days"),
            critical_days=self.opt("cert_critical_days"),
        )  # fmt: skip
        found += dhparam_findings(ctx, "nginx", cfg.dhparams)
        found += protocol_findings("nginx", cfg.protocols)
        found += name_findings(ctx, "nginx", cfg.sites)
        if self.opt("tls_probe"):
            found += served_findings(ctx, "nginx", "nginx", cfg.sites)
        if self.opt("config_test") and ctx.system.exists(CONFIG_TEST_BINARY):
            found += config_test_findings(
                ctx, "nginx", CONFIG_TEST, error=CONFIG_TEST_ERROR, warning=CONFIG_TEST_WARNING
            )
        if cfg.truncated:
            found.append(truncated_finding("nginx"))
        return found
