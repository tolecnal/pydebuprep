"""apt-sources, continued: signing keys, downloaded metadata, the security archive.

Everything here works from files already on disk. pydebuprep never runs apt update,
so whether a repository is reachable right now can't be known; the findings say so.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Sequence
from typing import TYPE_CHECKING

from pydebuprep.checks.base import count
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.system import System

if TYPE_CHECKING:  # pragma: no cover - typing only; apt_sources imports this module
    from pydebuprep.checks.apt_sources import SourceEntry

LISTS_DIR = "/var/lib/apt/lists"
LEGACY_KEYRING = "/etc/apt/trusted.gpg"
DEFAULT_KEYRINGS = ("/etc/apt/trusted.gpg.d/*.gpg", "/etc/apt/trusted.gpg.d/*.asc")
ARMOR_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
ARMOR_END = "-----END PGP PUBLIC KEY BLOCK-----"
VERIFY_TIMEOUT = 30.0
# Lines in sqv's or gpgv's error output that say why verification failed.
VERDICTS = (
    "BAD signature",
    "Can't check",
    "No public key",
    "Missing key",
    "manipulated",
    "expired",
    "revoked",
)
# Characters apt's URItoFileName escapes as %xx (QuoteString), besides control and
# non-ASCII bytes; '/' then becomes '_'.
QUOTED = set('\\|{}[]<>"^~_=!@#$%&*')
NETWORK_SCHEMES = ("http", "https", "ftp")
NO_SECURITY_ARCHIVE = {"sid", "unstable", "experimental"}
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
    if not signed_by or signed_by.strip().startswith("-----BEGIN"):
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


def metadata_findings(system: System, entries: Sequence[SourceEntry]) -> list[Finding]:
    """Repositories without downloaded metadata, or serving another release.

    Valid-Until isn't checked: a local Release past it only means apt update hasn't run
    lately (apt rejects expired files and keeps the old one), which apt-lists-age reports.

    Entries whose keyring is missing are left out: that is reported on its own, and
    apt can't verify their metadata anyway.
    """
    if not system.glob(f"{LISTS_DIR}/*Release"):
        return []  # apt update never ran: apt-lists-age reports it
    missing: list[SourceEntry] = []
    mismatched: list[str] = []
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
        # Like apt's CheckDist: a vendor suite such as jammy/mongodb-org/7.0 also
        # matches without its last path element.
        if names and not {e.suite, e.suite.rsplit("/", 1)[0]} & names:
            mismatched.append(
                f"{e.uri} {e.suite}: the repository says Suite {fields.get('Suite', '?')}, "
                f"Codename {fields.get('Codename', '?')}"
            )
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
    return findings


def security_finding(codename: str, distro: Sequence[SourceEntry]) -> list[Finding]:
    """The distribution archive is there, but its security updates aren't."""
    if not distro or any(
        e.suite.endswith("-security") or e.suite.endswith("/updates") for e in distro
    ):
        return []
    if all(e.suite_base in NO_SECURITY_ARCHIVE for e in distro):
        return []  # Debian unstable has no security archive
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


def dearmor(text: str) -> bytes | None:
    """The binary form of ASCII-armored public keys (gpgv can't read armor), or None.

    Also takes a deb822 inline key, whose lines were joined with spaces and whose blank
    line is a lone '.'.
    """
    keys = b""
    for block in text.split(ARMOR_BEGIN)[1:]:
        body = block.split(ARMOR_END, 1)[0].strip()
        lines = body.replace(" . ", "\n\n").replace(" ", "\n").splitlines()
        if "" in lines:  # armor headers (Version:, Comment:) end at the first blank line
            lines = lines[lines.index("") + 1 :]
        data = "".join(line for line in lines if line and not line.startswith("="))
        try:
            keys += base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError):
            return None
    return keys or None


def _keyrings(system: System, entry: SourceEntry) -> list[bytes] | None:
    """The keys apt would verify ENTRY with, in binary form; None if they can't be had."""
    signed_by = entry.signed_by.strip()
    if signed_by.startswith("-----BEGIN"):
        key = dearmor(signed_by)
        return None if key is None else [key]
    if signed_by:
        paths = keyring_paths(signed_by)
        if paths is None:
            return None  # fingerprints: not verified here
    else:
        paths = [LEGACY_KEYRING] + [p for pattern in DEFAULT_KEYRINGS for p in system.glob(pattern)]
    rings = []
    for path in paths:
        data = system.read_bytes(path)
        if not data:
            continue
        if data.lstrip().startswith(ARMOR_BEGIN.encode()):
            data = dearmor(data.decode("ascii", errors="replace")) or b""
        if data:
            rings.append(data)
    return rings or None


def signature_findings(system: System, entries: Sequence[SourceEntry]) -> list[Finding]:
    """Downloaded InRelease files that no longer verify against the configured keys.

    apt verified each file when it downloaded it, so a failure means the keys changed
    since: the next apt update will reject the repository. Uses sqv (Debian 13) or gpgv;
    keys are copied to a private scratch directory as binary, since gpgv can't read
    armored keys and keyrings may live anywhere.
    """
    program = next((p for p in ("sqv", "gpgv") if system.which(p)), None)
    if program is None:
        return []
    targets = []
    seen: set[tuple[str, str]] = set()
    for e in entries:
        path = list_file(e.uri, e.suite, "InRelease")
        if (e.norm_uri, e.suite) in seen or path is None or system.read_text(path) is None:
            continue
        seen.add((e.norm_uri, e.suite))
        rings = _keyrings(system, e)
        if rings is not None:
            targets.append((e, path, rings))
    if not targets:
        return []
    failed = []
    with system.scratch_dir() as scratch:
        for n, (e, path, rings) in enumerate(targets):
            argv = [program]
            for i, ring in enumerate(rings):
                argv += ["--keyring", system.write_scratch(scratch, f"key-{n}-{i}.gpg", ring)]
            if program == "sqv":
                argv += ["--cleartext", "--output", f"{scratch}/out-{n}"]
            res = system.run([*argv, path], timeout=VERIFY_TIMEOUT)
            if res.timed_out or res.returncode == 0:
                continue
            reason = _verdict(res.stderr)
            failed.append(f"{e.uri} {e.suite}: {reason or f'exit status {res.returncode}'}")
    if not failed:
        return []
    return [
        Finding(
            Severity.CRITICAL,
            f"Metadata of {count(len(failed), 'repository', 'repositories')} doesn't "
            "verify against its keys",
            detail="apt checked these files when it downloaded them, so the keys changed "
            "since (removed, replaced or expired): the next apt update will reject these "
            "repositories and they get no updates.",
            evidence=truncate_evidence(failed),
            remediation=[
                "Get the vendor's current key (reinstall its keyring package, or download "
                "it again) and point Signed-By at it",
                "sudo apt update",
            ],
        )
    ]


def _verdict(stderr: str) -> str:
    """The line of a verifier's error output that says why, without its gpgv: prefix."""
    lines = [ln.strip().removeprefix("gpgv:").strip() for ln in stderr.splitlines()]
    lines = [ln for ln in lines if ln]
    chosen = [ln for ln in lines if any(v in ln for v in VERDICTS)]
    return (chosen or lines or [""])[-1]
