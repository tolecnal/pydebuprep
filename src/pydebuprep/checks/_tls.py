"""TLS findings shared by the nginx, apache and certbot checks.

Certificates are read through System like every other file (never by a command that
opens the path itself) and parsed by _x509. What counts as refused is what OpenSSL's
default security level 2 on Debian and Ubuntu refuses: MD5 and SHA-1 signatures, RSA
and DSA keys under 2048 bits, EC keys under 224 bits, DH parameters under 2048 bits,
and protocols older than TLS 1.2. A server refuses to load such a certificate, or
clients can't connect with such a protocol.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass

from pydebuprep.checks._listeners import listening_addresses
from pydebuprep.checks._x509 import Certificate, CertificateError, dh_bits, parse_pem
from pydebuprep.checks.base import Context, Option
from pydebuprep.model import Finding, Severity, truncate_evidence

REFUSED_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})
ALL_PROTOCOLS = frozenset({"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"})  # Apache's "all"
PROTOCOL_NAMES = {p.lower(): p for p in ("SSLv2", "SSLv3", *sorted(ALL_PROTOCOLS))}
MIN_RSA_BITS = 2048
MIN_EC_BITS = 224
MIN_DH_BITS = 2048
WEAK_HASHES = {"md5": "MD5", "sha1": "SHA-1"}
MAX_DAYS = 365

CERT_OPTIONS = (
    Option(
        "cert_warning_days", 28, "Warn when a TLS certificate expires within this many days"
    ),
    Option(
        "cert_critical_days", 14,
        "Critical when a TLS certificate expires within this many days (below the warning)",
    ),
)  # fmt: skip


TLS_PROBE_OPTION = Option(
    "tls_probe", True,
    "Connect to each TLS site on this host with its name (SNI) and compare the "
    "certificate it serves with the file",
)  # fmt: skip
MAX_PROBES = 50
PROBE_TIMEOUT = 5.0
# A wildcard listen is reached on loopback, if one of these listens on its port.
ANY_IPV4 = "0.0.0.0"  # nosec B104 # an address read from configs and /proc, never bound
LOOPBACK_V4 = ("127.0.0.1", (ANY_IPV4, "127.0.0.1"))
WILDCARDS = {"": LOOPBACK_V4, "*": LOOPBACK_V4, ANY_IPV4: LOOPBACK_V4, "::": ("::1", ("::", "::1"))}


@dataclass(frozen=True)
class TlsSite:
    """A TLS server block or virtual host: its configuration file, names, certificate
    and TLS listen addresses (address as written, "" for any; port)."""

    source: str
    names: tuple[str, ...]
    certificate: str
    listen: tuple[tuple[str, int], ...]


def validate_cert_days(warning: int, critical: int) -> None:
    for name, value in (("cert_warning_days", warning), ("cert_critical_days", critical)):
        if not 1 <= value <= MAX_DAYS:
            raise ValueError(f"{name} must be between 1 and {MAX_DAYS}, got {value}")
    if critical >= warning:
        raise ValueError(
            f"cert_critical_days ({critical}) must be below cert_warning_days ({warning})"
        )


def _first(paths: Sequence[tuple[str, str]]) -> dict[str, str]:
    """Each path once, with the first place that names it."""
    seen: dict[str, str] = {}
    for path, where in paths:
        seen.setdefault(path, where)
    return seen


def weakness(cert: Certificate) -> str | None:
    """Why OpenSSL refuses this certificate, or None."""
    if cert.signature_hash in WEAK_HASHES:
        return f"signed with {WEAK_HASHES[cert.signature_hash]}"
    if cert.key_type in ("rsa", "dsa") and 0 < cert.key_bits < MIN_RSA_BITS:
        return f"{cert.key_type.upper()} {cert.key_bits} bits"
    if cert.key_type == "ec" and 0 < cert.key_bits < MIN_EC_BITS:
        return f"EC {cert.key_bits} bits"
    return None


INSPECT = "Inspect one: openssl x509 -noout -dates -subject -ext subjectAltName -in PATH"


def certificate_findings(
    ctx: Context, server: str, paths: Sequence[tuple[str, str]], *,
    warning_days: int, critical_days: int,
) -> list[Finding]:  # fmt: skip
    """Expiry and refused crypto of each certificate in PATHS ((path, where) pairs)."""
    now = ctx.system.now()
    invalid, critical, warning, unreadable, needs_root, weak = [], [], [], [], [], []
    for path, where in _first(paths).items():
        data = ctx.system.read_bytes(path)
        if data is None:
            if ctx.is_root:
                unreadable.append(f"{path}: can't be read {where}")
            else:
                needs_root.append(f"{path} {where}")
            continue
        try:
            leaf = parse_pem(data)[0]
        except CertificateError as exc:
            unreadable.append(f"{path}: {exc} {where}")
            continue
        days = (leaf.not_after - now).days
        if now < leaf.not_before:
            invalid.append(f"{path}: not valid before {leaf.not_before:%Y-%m-%d} {where}")
        elif now >= leaf.not_after:
            invalid.append(f"{path}: expired {leaf.not_after:%Y-%m-%d} {where}")
        elif days <= critical_days:
            critical.append(f"{path}: expires {leaf.not_after:%Y-%m-%d} ({days} days) {where}")
        elif days <= warning_days:
            warning.append(f"{path}: expires {leaf.not_after:%Y-%m-%d} ({days} days) {where}")
        if reason := weakness(leaf):
            weak.append(f"{path}: {reason} {where}")
    renew = ["Renew the certificates, then reload the server", INSPECT]
    found = []
    if invalid:
        found.append(
            Finding(
                Severity.CRITICAL,
                f"{server} uses expired or not yet valid certificates",
                detail="Clients refuse the connection.",
                evidence=truncate_evidence(invalid),
                remediation=renew,
            )
        )
    for days, lines, severity in ((critical_days, critical, Severity.CRITICAL),
                                  (warning_days, warning, Severity.WARNING)):  # fmt: skip
        if lines:
            found.append(
                Finding(
                    severity,
                    f"{server} has certificates expiring within {days} days",
                    detail="An automatically renewed certificate is normally renewed 30 days "
                    "before it expires; this one wasn't, or isn't renewed automatically.",
                    evidence=truncate_evidence(lines),
                    remediation=renew,
                )
            )
    if unreadable:
        found.append(
            Finding(
                Severity.CRITICAL,
                f"{server} names certificates that can't be read",
                detail=f"{server} refuses to start or reload without them.",
                evidence=truncate_evidence(unreadable),
                remediation=["Restore the files, or point the configuration at the right ones"],
            )
        )
    if weak:
        found.append(
            Finding(
                Severity.CRITICAL,
                f"{server} uses keys or signatures OpenSSL refuses",
                detail="At its default security level OpenSSL refuses SHA-1 and MD5 "
                "signatures, RSA and DSA keys under 2048 bits and EC keys under 224 bits, so "
                f"{server} can't load these certificates.",
                evidence=truncate_evidence(weak),
                remediation=["Issue new certificates with a 2048-bit or larger key", INSPECT],
            )
        )
    if needs_root:
        found.append(
            Finding(
                Severity.INFO,
                f"{server}'s certificates were not checked (needs root)",
                detail="These certificates can only be read as root.",
                evidence=truncate_evidence(needs_root),
                remediation=["Run as root: sudo pydebuprep report"],
            )
        )
    return found


def dhparam_findings(
    ctx: Context, server: str, paths: Sequence[tuple[str, str]], *, required: bool = True
) -> list[Finding]:
    """DH parameter files OpenSSL refuses. With REQUIRED off (parameters appended to a
    certificate file), a file without parameters is fine. Unreadable files are reported
    only as root: the certificate findings say what wasn't checked."""
    lines = []
    for path, where in _first(paths).items():
        data = ctx.system.read_bytes(path)
        if data is None:
            if ctx.is_root and required:
                lines.append(f"{path}: can't be read {where}")
            continue
        try:
            bits = dh_bits(data)
        except CertificateError as exc:
            lines.append(f"{path}: {exc} {where}")
            continue
        if bits is None:
            if required:
                lines.append(f"{path}: no DH parameters in the file {where}")
        elif bits < MIN_DH_BITS:
            lines.append(f"{path}: {bits} bits {where}")
    if not lines:
        return []
    return [
        Finding(
            Severity.CRITICAL,
            f"{server} uses DH parameters OpenSSL refuses",
            detail="OpenSSL refuses DH parameters under 2048 bits at its default security "
            f"level, and {server} can't load a missing or unreadable file.",
            evidence=truncate_evidence(lines),
            remediation=["Generate new ones: openssl dhparam -out PATH 2048"],
        )
    ]


def protocol_findings(server: str, settings: Sequence[tuple[frozenset[str], str]]) -> list[Finding]:
    """Protocol settings ((enabled protocols, where) pairs) that OpenSSL refuses."""
    only: list[str] = []
    some: list[str] = []
    for protocols, where in settings:
        refused = protocols & REFUSED_PROTOCOLS
        if not refused:
            continue
        line = f"{' '.join(sorted(protocols))} {where}"
        (only if refused == protocols else some).append(line)
    fix = ["Enable TLSv1.2 and TLSv1.3 (for nginx: ssl_protocols TLSv1.2 TLSv1.3;)"]
    found = []
    if only:
        found.append(
            Finding(
                Severity.CRITICAL,
                f"{server} enables only TLS protocols OpenSSL refuses",
                detail="OpenSSL no longer negotiates SSL, TLS 1.0 or TLS 1.1 by default, so "
                "no client can connect.",
                evidence=truncate_evidence(only),
                remediation=fix,
            )
        )
    if some:
        found.append(
            Finding(
                Severity.WARNING,
                f"{server} enables TLS protocols OpenSSL refuses",
                detail="OpenSSL no longer negotiates SSL, TLS 1.0 or TLS 1.1 by default; "
                "listing them does nothing.",
                evidence=truncate_evidence(some),
                remediation=fix,
            )
        )
    return found


def apache_protocols(words: Sequence[str]) -> frozenset[str]:
    """The protocols an SSLProtocol directive enables."""
    enabled: set[str] = set()
    for word in words:
        name = word.lstrip("+-")
        names = ALL_PROTOCOLS if name.lower() == "all" else {PROTOCOL_NAMES.get(name.lower(), name)}
        if word.startswith("-"):
            enabled -= names
        else:
            enabled |= names
    return frozenset(enabled)


def name_matches(name: str, cert: Certificate) -> bool:
    """Whether CERT covers NAME (RFC 6125: a wildcard stands for one whole left-most
    label; the subject CN counts only without SAN DNS names)."""
    name = name.lower().rstrip(".")
    patterns = cert.dns_names or ((cert.subject_cn,) if cert.subject_cn else ())
    for pattern in (p.lower().rstrip(".") for p in patterns):
        if pattern.startswith("*."):
            label, _, rest = name.partition(".")
            if label and rest == pattern[2:]:
                return True
        elif pattern == name:
            return True
    return False


def matchable(name: str) -> bool:
    """A literal host name: not nginx's catch-all `_`, a regex, a wildcard or a suffix."""
    return (
        bool(name)
        and name != "_"
        and "*" not in name
        and "~" not in name
        and not name.startswith(".")
    )


def name_findings(ctx: Context, server: str, sites: Sequence[TlsSite]) -> list[Finding]:
    """Server names that their site's certificate doesn't cover."""
    lines = []
    for site in sites:
        data = ctx.system.read_bytes(site.certificate)
        try:
            leaf = parse_pem(data)[0] if data is not None else None
        except CertificateError:
            leaf = None  # reported by certificate_findings
        if leaf is None:
            continue
        lines += [
            f"{name} isn't covered by {site.certificate} ({site.source})"
            for name in site.names
            if matchable(name) and not name_matches(name, leaf)
        ]
    if not lines:
        return []
    return [
        Finding(
            Severity.WARNING,
            f"{server} has certificates that don't cover their server names",
            detail="Clients visiting these names get a certificate warning.",
            evidence=truncate_evidence(lines),
            remediation=["Add the names to the certificate, or remove them from the site", INSPECT],
        )
    ]


def _target(address: str, port: int, listening: set[tuple[str, int]]) -> str | None:
    """The IP address to probe a site's listen ADDRESS:PORT on, or None if nothing on
    this host listens there (or the address isn't an IP address)."""
    address = address.strip("[]")
    if address in WILDCARDS:
        loopback, listeners = WILDCARDS[address]
        return loopback if any((a, port) in listening for a in listeners) else None
    try:
        normal = ipaddress.ip_address(address).compressed
    except ValueError:
        return None
    return normal if (normal, port) in listening else None


def probe_targets(
    sites: Sequence[TlsSite], listening: set[tuple[str, int]]
) -> list[tuple[str, int, str, TlsSite]]:
    """(address, port, server name, site) to probe: one per address, port and name,
    only where this host listens, at most MAX_PROBES."""
    targets: dict[tuple[str, int, str], TlsSite] = {}
    for site in sites:
        name = next((n for n in site.names if matchable(n)), None)
        if name is None:
            continue
        for address, port in site.listen:
            host = _target(address, port, listening)
            if host is not None:
                targets.setdefault((host, port, name), site)
    return [(h, p, n, s) for (h, p, n), s in list(targets.items())[:MAX_PROBES]]


def served_findings(
    ctx: Context, server: str, service: str, sites: Sequence[TlsSite]
) -> list[Finding]:
    """Sites serving another certificate than the file they name: the server wasn't
    reloaded after the certificate was renewed."""
    differ, errors = [], []
    for host, port, name, site in probe_targets(sites, listening_addresses(ctx.system)):
        served, error = ctx.system.tls_peer_certificate(host, port, name, PROBE_TIMEOUT)
        if served is None:
            errors.append(f"{name} on {host}:{port}: {error}")
            continue
        data = ctx.system.read_bytes(site.certificate)
        try:
            on_disk = parse_pem(data)[0].sha256 if data is not None else None
        except CertificateError:
            on_disk = None  # reported by certificate_findings
        digest = hashlib.sha256(served).hexdigest()
        if on_disk is not None and digest != on_disk:
            differ.append(
                f"{name} on {host}:{port} serves {digest[:16]}…, "
                f"{site.certificate} is {on_disk[:16]}…"
            )
    found = []
    if differ:
        found.append(
            Finding(
                Severity.WARNING,
                f"{server} serves different certificates than its configuration names",
                detail=f"The certificate files changed (a renewal, usually) and {server} "
                "wasn't reloaded, so it still serves the old ones, which expire.",
                evidence=truncate_evidence(differ),
                remediation=[f"sudo systemctl reload {service}"],
            )
        )
    if errors:
        found.append(
            Finding(
                Severity.INFO,
                f"{server}: some TLS sites didn't answer the probe",
                detail="Their served certificate couldn't be compared with the file.",
                evidence=truncate_evidence(errors),
            )
        )
    return found
