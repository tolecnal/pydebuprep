"""TLS findings shared by the nginx, apache and certbot checks.

Certificates are read through System like every other file (never by a command that
opens the path itself) and parsed by _x509. What counts as refused is what OpenSSL's
default security level 2 on Debian and Ubuntu refuses: MD5 and SHA-1 signatures, RSA
and DSA keys under 2048 bits, EC keys under 224 bits, DH parameters under 2048 bits,
and protocols older than TLS 1.2. A server refuses to load such a certificate, or
clients can't connect with such a protocol.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

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
