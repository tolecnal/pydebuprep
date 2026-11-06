"""Package settings an upgrade can change quietly: APT pinning, foreign architectures,
dpkg's diversions and the alternatives system. All read from their files."""

from __future__ import annotations

import hashlib
from typing import Any

from pydebuprep.checks.base import Check, Context, count, output_lines
from pydebuprep.model import Finding, Severity, truncate_evidence

PREFERENCES = "/etc/apt/preferences"
ARCHITECTURES = "/var/lib/dpkg/arch"
DIVERSIONS = "/var/lib/dpkg/diversions"
ALTERNATIVES = "/var/lib/dpkg/alternatives"
ALTERNATIVE_LINKS = "/etc/alternatives"
LOCAL_DIVERSION = ":"  # dpkg's name for a diversion an administrator made


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _preferences(ctx: Context) -> dict[str, str]:
    digests = {}
    for path in [PREFERENCES, *ctx.system.glob(f"{PREFERENCES}.d/*")]:
        data = ctx.system.read_bytes(path)
        if data is not None:
            digests[path] = _digest(data)
    return digests


def _architectures(ctx: Context) -> list[str]:
    return output_lines(ctx.system.read_text(ARCHITECTURES) or "")


def _diversions(ctx: Context) -> dict[str, str]:
    """Diverted file -> the package that diverts it. The file has three lines for each:
    the file, where it's diverted to, and the package."""
    lines = (ctx.system.read_text(DIVERSIONS) or "").splitlines()
    return {lines[i]: lines[i + 2] for i in range(0, len(lines) - 2, 3)}


def _alternatives(ctx: Context) -> dict[str, tuple[str, str | None]]:
    """Alternative -> its mode (auto or manual) and where its link points."""
    found = {}
    for path in ctx.system.glob(f"{ALTERNATIVES}/*"):
        name = path.rsplit("/", 1)[1]
        mode = (ctx.system.read_text(path) or "").partition("\n")[0].strip()
        found[name] = (mode, ctx.system.readlink(f"{ALTERNATIVE_LINKS}/{name}"))
    return found


def _changes(before: dict[str, Any], now: dict[str, Any], key: str) -> tuple[list[str], list[str]]:
    """What is in BEFORE[KEY] and not in NOW, and the other way round."""
    old, new = set(before[key]), set(now[key])
    return sorted(old - new), sorted(new - old)


class PackageConfigCheck(Check):
    id = "package-config"
    title = "APT pinning, architectures, diversions and alternatives"
    category = "packages"

    def run(self, ctx: Context) -> list[Finding]:
        broken = [
            f"{name}: {target}"
            for name, (_, target) in sorted(_alternatives(ctx).items())
            if target is not None and not ctx.system.exists(f"{ALTERNATIVE_LINKS}/{name}")
        ]
        if not broken:
            return []
        return [
            Finding(
                Severity.WARNING,
                f"{count(len(broken), 'alternative points', 'alternatives point')} to nothing",
                detail="The command it provides fails; its package may have been removed.",
                evidence=truncate_evidence(broken),
                remediation=["sudo update-alternatives --config NAME"],
            )
        ]

    def collect_baseline(self, ctx: Context) -> Any:
        return {
            "preferences": _preferences(ctx),
            "architectures": _architectures(ctx),
            "diversions": _diversions(ctx),
            "alternatives": {k: list(v) for k, v in _alternatives(ctx).items()},
        }

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now = self.collect_baseline(ctx)
        findings = []
        if "preferences" in before:
            findings += _preference_changes(before["preferences"], now["preferences"])
        if "architectures" in before:
            findings += _architecture_changes(before, now)
        if "diversions" in before:
            findings += _diversion_changes(before["diversions"], now["diversions"])
        if "alternatives" in before:
            findings += _alternative_changes(before["alternatives"], now["alternatives"])
        return findings


def _preference_changes(old: dict[str, str], new: dict[str, str]) -> list[Finding]:
    gone = sorted(set(old) - set(new))
    changed = sorted(path for path in new if old.get(path) != new[path])
    findings = []
    if gone:
        findings.append(
            Finding(
                Severity.WARNING,
                f"{count(len(gone), 'APT pinning file is', 'APT pinning files are')} gone",
                detail="Packages they pinned may now come from another source or version.",
                evidence=truncate_evidence(gone),
                remediation=["See what APT would pick now: apt policy PACKAGE"],
            )
        )
    if changed:
        findings.append(
            Finding(
                Severity.INFO,
                f"{count(len(changed), 'APT pinning file is', 'APT pinning files are')} "
                "new or changed",
                evidence=truncate_evidence(changed),
                remediation=["See what APT would pick now: apt policy PACKAGE"],
            )
        )
    return findings


def _architecture_changes(before: dict[str, Any], now: dict[str, Any]) -> list[Finding]:
    gone, added = _changes(before, now, "architectures")
    findings = []
    if gone:
        findings.append(
            Finding(
                Severity.WARNING,
                f"{count(len(gone), 'package architecture is', 'package architectures are')} "
                "no longer enabled",
                evidence=gone,
                remediation=["sudo dpkg --add-architecture ARCHITECTURE"],
            )
        )
    if added:
        findings.append(
            Finding(
                Severity.INFO,
                f"{count(len(added), 'package architecture is', 'package architectures are')} "
                "newly enabled",
                evidence=added,
            )
        )
    return findings


def _diversion_changes(old: dict[str, str], new: dict[str, str]) -> list[Finding]:
    # Packages' own diversions come and go with them; an administrator's shouldn't.
    gone = sorted(
        path for path, owner in old.items() if owner == LOCAL_DIVERSION and path not in new
    )
    moved = sorted(
        f"{path}: {owner} to {new[path]}"
        for path, owner in old.items()
        if path in new and new[path] != owner
    )
    findings = []
    if gone:
        findings.append(
            Finding(
                Severity.WARNING,
                f"{count(len(gone), 'local diversion is', 'local diversions are')} gone",
                detail="A file you diverted is back under its package's control, so an upgrade "
                "can overwrite your version.",
                evidence=truncate_evidence(gone),
                remediation=["See the current ones: dpkg-divert --list"],
            )
        )
    if moved:
        findings.append(
            Finding(
                Severity.INFO,
                f"{count(len(moved), 'diversion has a new owner', 'diversions have new owners')}",
                evidence=truncate_evidence(moved),
            )
        )
    return findings


def _alternative_changes(
    old: dict[str, list[str | None]], new: dict[str, list[str | None]]
) -> list[Finding]:
    chosen: list[str] = []
    automatic: list[str] = []
    for name, (mode, target) in sorted(old.items()):
        current = new.get(name)
        if mode == "manual" and current is None:
            chosen.append(f"{name}: {target}, now gone")
        elif current is not None and current[1] != target:
            line = f"{name}: {target} to {current[1]}"
            (chosen if mode == "manual" else automatic).append(line)
    findings = []
    if chosen:
        findings.append(
            Finding(
                Severity.WARNING,
                f"{count(len(chosen), 'alternative', 'alternatives')} chosen by hand "
                f"{'is' if len(chosen) == 1 else 'are'} different now",
                evidence=truncate_evidence(chosen),
                remediation=["sudo update-alternatives --config NAME"],
            )
        )
    if automatic:
        findings.append(
            Finding(
                Severity.INFO,
                count(
                    len(automatic), "automatic alternative points", "automatic alternatives point"
                )
                + " elsewhere",
                detail="Usually expected in a release upgrade: a newer version took over.",
                evidence=truncate_evidence(automatic),
            )
        )
    return findings
