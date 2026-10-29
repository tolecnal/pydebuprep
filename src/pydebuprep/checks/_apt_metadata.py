"""apt-sources, continued: signing keys, downloaded metadata, the security archive.

Everything here works from files already on disk. pydebuprep never runs apt update,
so whether a repository is reachable right now can't be known; the findings say so.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING

from pydebuprep.checks.base import count
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.system import System

if TYPE_CHECKING:  # pragma: no cover - typing only; apt_sources imports this module
    from pydebuprep.checks.apt_sources import SourceEntry

LISTS_DIR = "/var/lib/apt/lists"
LEGACY_KEYRING = "/etc/apt/trusted.gpg"
# Characters apt's URItoFileName escapes as %xx (QuoteString), besides control and
# non-ASCII bytes; '/' then becomes '_'.
QUOTED = set('\\|{}[]<>"^~_=!@#$%&*')
NETWORK_SCHEMES = ("http", "https", "ftp")
NOT_LIVE = (
    "This is based on the files from the last apt update; pydebuprep never runs it, so "
    "whether the repository works right now isn't known."
)


def list_file(uri: str, suite: str, name: str) -> str | None:
    """Where apt keeps a repository's NAME (InRelease, Release) file, or None if unknown.

    Unknown: local, cdrom and mirror+ sources, and flat repositories (suite ending in /).
    """
    scheme, _, rest = uri.partition(":")
    if scheme not in NETWORK_SCHEMES or not rest.startswith("//") or suite.endswith("/"):
        return None
    authority, _, path = rest[2:].partition("/")
    authority = authority.rsplit("@", 1)[-1]  # apt drops user:password@
    full = f"{authority}/{path}".rstrip("/") + f"/dists/{suite}/{name}"
    quoted = "".join(
        f"%{ord(c):02x}" if c in QUOTED or ord(c) <= 0x20 or ord(c) >= 0x7F else c for c in full
    )
    return f"{LISTS_DIR}/{quoted.replace('/', '_')}"


def parse_release(text: str) -> dict[str, str]:
    """The single-line fields of a Release or InRelease file (Suite, Codename, ...)."""
    lines = text.splitlines()
    if lines and lines[0].startswith("-----BEGIN PGP SIGNED MESSAGE"):
        lines = lines[lines.index("") + 1 :] if "" in lines else []
    fields: dict[str, str] = {}
    for line in lines:
        if line.startswith("-----BEGIN PGP SIGNATURE"):
            break
        if line[:1] in (" ", "\t") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        if value.strip():
            fields[key.strip()] = value.strip()
    return fields


def keyring_paths(signed_by: str) -> list[str] | None:
    """Keyring files a Signed-By value names; None when it holds an inline key or
    fingerprints, which aren't files."""
    if not signed_by or signed_by.startswith("-----BEGIN"):
        return None
    items = signed_by.replace(",", " ").split()
    paths = [i for i in items if i.startswith("/")]
    return paths if paths and len(paths) == len(items) else None


def keyring_findings(system: System, entries: Sequence[SourceEntry]) -> list[Finding]:
    missing: dict[str, list[SourceEntry]] = {}
    for e in entries:
        paths = keyring_paths(e.signed_by)
        if paths and not any(system.exists(p) for p in paths):
            missing.setdefault(", ".join(paths), []).append(e)
    return [
        Finding(
            Severity.CRITICAL,
            f"Signing keyring {path} is missing",
            detail="apt refuses repositories whose Signed-By keyring doesn't exist: "
            "it gets no updates from them. " + NOT_LIVE,
            evidence=truncate_evidence([e.describe() for e in items]),
            remediation=[
                "Reinstall the vendor's keyring package, or download its key again "
                f"from the vendor to {path}",
                "sudo apt update",
            ],
        )
        for path, items in sorted(missing.items())
    ]


def legacy_keyring_finding(system: System) -> list[Finding]:
    if not system.read_text(LEGACY_KEYRING):
        return []
    return [
        Finding(
            Severity.WARNING,
            f"Keys in the legacy keyring {LEGACY_KEYRING}",
            detail="apt-key is gone and newer apt versions warn about, or ignore, keys "
            "there. Each repository should name its own key with Signed-By.",
            remediation=[
                "List the keys: gpg --show-keys /etc/apt/trusted.gpg",
                "Export each vendor's key to /etc/apt/keyrings/VENDOR.gpg, add "
                "signed-by=/etc/apt/keyrings/VENDOR.gpg to its source, then remove "
                "/etc/apt/trusted.gpg",
            ],
        )
    ]


def metadata_findings(
    system: System, entries: Sequence[SourceEntry], now: datetime
) -> list[Finding]:
    """Repositories without downloaded metadata, serving another release, or expired.

    Entries whose keyring is missing are left out: that is reported on its own, and
    apt can't verify their metadata anyway.
    """
    if not system.glob(f"{LISTS_DIR}/*Release"):
        return []  # apt update never ran: apt-lists-age reports it
    missing, mismatched, expired = [], [], []
    seen: set[tuple[str, str]] = set()
    for e in entries:
        key = (e.norm_uri, e.suite)
        paths = keyring_paths(e.signed_by)
        if key in seen or (paths and not any(system.exists(p) for p in paths)):
            continue
        seen.add(key)
        texts = [
            system.read_text(f)
            for name in ("InRelease", "Release")
            if (f := list_file(e.uri, e.suite, name)) is not None
        ]
        if not texts:
            continue  # not a network repository: apt keeps no lists for it
        text = next((t for t in texts if t is not None), None)
        if text is None:
            missing.append(e)
            continue
        fields = parse_release(text)
        names = {fields.get("Suite"), fields.get("Codename")} - {None}
        if names and e.suite not in names:
            mismatched.append(
                f"{e.uri} {e.suite}: the repository says Suite {fields.get('Suite', '?')}, "
                f"Codename {fields.get('Codename', '?')}"
            )
        until = _date(fields.get("Valid-Until"))
        if until is not None and until < now:
            expired.append(f"{e.uri} {e.suite}: valid until {fields['Valid-Until']}")
    findings = []
    if missing:
        findings.append(
            Finding(
                Severity.WARNING,
                f"No downloaded metadata for {count(len(missing), 'repository', 'repositories')}",
                detail="The last apt update didn't get these repositories' Release files: "
                "a missing or wrong signing key, a suite the vendor doesn't publish, or a "
                "network problem. " + NOT_LIVE,
                evidence=truncate_evidence([e.describe() for e in missing]),
                remediation=["sudo apt update   # and read the errors it prints"],
            )
        )
    if mismatched:
        findings.append(
            Finding(
                Severity.WARNING,
                f"{count(len(mismatched), 'repository serves', 'repositories serve')} "
                "a different release than configured",
                detail="apt warns about a conflicting distribution: the source names one "
                "release, the repository another, so packages may not match this "
                "system. " + NOT_LIVE,
                evidence=truncate_evidence(mismatched),
                remediation=[
                    "Set each source's suite to what the vendor publishes for "
                    "this release, then sudo apt update"
                ],
            )
        )
    if expired:
        findings.append(
            Finding(
                Severity.WARNING,
                f"Metadata of {count(len(expired), 'repository', 'repositories')} has expired",
                detail="apt rejects Release files past their Valid-Until date, so these "
                "repositories deliver no updates until refreshed. " + NOT_LIVE,
                evidence=truncate_evidence(expired),
                remediation=["sudo apt update", "Check the system clock: timedatectl"],
            )
        )
    return findings


def _date(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        return parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None


def security_finding(codename: str, distro: Sequence[SourceEntry]) -> list[Finding]:
    """The distribution archive is there, but its security updates aren't."""
    if not distro or any(
        e.suite.endswith("-security") or e.suite.endswith("/updates") for e in distro
    ):
        return []
    return [
        Finding(
            Severity.WARNING,
            f"No security updates repository for {codename}",
            detail="The distribution archive is configured but its security archive "
            "isn't, so security fixes arrive late or not at all.",
            evidence=truncate_evidence(sorted({e.describe() for e in distro})),
            remediation=[
                f"Add {codename}-security (Debian: http://security.debian.org/debian-security; "
                f"Ubuntu: http://security.ubuntu.com/ubuntu) next to the archive",
                "sudo apt update",
            ],
        )
    ]
