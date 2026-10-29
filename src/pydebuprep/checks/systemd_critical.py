from __future__ import annotations

import fnmatch
from collections.abc import Sequence

from pydebuprep.checks._systemd import run_systemctl
from pydebuprep.checks.base import Check, CommandFailed, Context, Option
from pydebuprep.model import Finding, Severity
from pydebuprep.system import MAX_UNITS, SHOW_UNITS, UNIT_NAME

BUILTIN = ("ssh.service", "cron.service", "systemd-journald.service")
TIME_SYNC = ("systemd-timesyncd.service", "chrony.service", "ntpsec.service")
# Unit file states that satisfy "enabled": static, generated and alias units can't be
# enabled, and indirect ones are enabled through another unit.
ENABLED_STATES = {"enabled", "enabled-runtime", "static", "indirect", "generated", "alias"}
TRANSITIONAL = {"activating", "deactivating", "reloading"}
PROCESS_NOTE = "An active unit shows the process is running, not that the service works."

UnitState = dict[str, str]


def plain_unit(name: str) -> bool:
    return not name.startswith("-") and bool(UNIT_NAME.match(name))


def parse_show(text: str) -> list[UnitState]:
    """`systemctl show` output for several units: one KEY=VALUE block per unit, in order."""
    blocks: list[UnitState] = []
    current: UnitState = {}
    for line in text.splitlines():
        if not line.strip():
            if current:
                blocks.append(current)
                current = {}
            continue
        key, _, value = line.partition("=")
        current[key] = value
    if current:
        blocks.append(current)
    return blocks


def unit_states(ctx: Context, units: Sequence[str]) -> dict[str, UnitState]:
    """Properties of each unit, keyed by the name asked for (an alias keeps its name)."""
    states: dict[str, UnitState] = {}
    for start in range(0, len(units), MAX_UNITS):
        chunk = list(units[start : start + MAX_UNITS])
        blocks = parse_show(run_systemctl(ctx, (*SHOW_UNITS, *chunk)).stdout)
        if not blocks:
            return {}  # no output at all: nothing is known about any unit
        if len(blocks) != len(chunk):
            raise CommandFailed(f"systemctl show returned {len(blocks)} units for {len(chunk)}")
        states.update(zip(chunk, blocks, strict=True))
    return states


def _words(state: UnitState, key: str) -> list[str]:
    return [u for u in state.get(key, "").split() if plain_unit(u)]


def _finding(severity: Severity, title: str, remediation: list[str], detail: str = "") -> Finding:
    return Finding(
        severity, title, detail=f"{detail} {PROCESS_NOTE}".strip(), remediation=remediation
    )


class SystemdCriticalCheck(Check):
    id = "systemd-critical-services"
    title = "Critical systemd units"
    category = "services"
    requires_commands = ("systemctl",)
    options = (
        Option("required_active", [], "Units that must be running (or socket-activated)"),
        Option("required_enabled", [], "Units that must be enabled"),
        Option("builtin", True, "Also require ssh, cron, journald and time sync where installed"),
        Option("ignore_units", [], "Units to leave out (shell-style patterns)"),
    )

    def validate(self) -> None:
        for name in ("required_active", "required_enabled"):
            bad = [u for u in self.opt(name) if not plain_unit(u)]
            if bad:
                raise ValueError(f"{name}: not a unit name: {', '.join(bad)}")

    def _ignored(self, unit: str) -> bool:
        return any(fnmatch.fnmatchcase(unit, p) for p in self.opt("ignore_units"))

    def effective_units(self) -> list[str]:
        builtin = (*BUILTIN, *TIME_SYNC) if self.opt("builtin") else ()
        units = (*builtin, *self.opt("required_active"), *self.opt("required_enabled"))
        return [u for u in dict.fromkeys(units) if not self._ignored(u)]

    def run(self, ctx: Context) -> list[Finding]:
        units = self.effective_units()
        if not units:
            return []
        states = unit_states(ctx, units)
        if not states:
            return []
        configured = {*self.opt("required_active"), *self.opt("required_enabled")}
        builtin = set(BUILTIN) if self.opt("builtin") else set()
        need_active = {*builtin, *self.opt("required_active")}
        need_enabled = {*builtin, *self.opt("required_enabled")}
        checked = [
            u
            for u in units
            if (u in configured or u in builtin)
            and (u in configured or states[u].get("LoadState") != "not-found")
        ]
        time_sync = [u for u in TIME_SYNC if u in states and states[u].get("LoadState") == "loaded"]
        related = self._related(ctx, [states[u] for u in (*checked, *time_sync)])
        findings: list[Finding] = []
        for u in checked:
            st = states[u]
            load = st.get("LoadState", "")
            if load == "not-found":
                stem = u.rsplit(".", 1)[0]
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        f"{u} does not exist",
                        [f"systemctl list-unit-files '{stem}*'"],
                        "It is required here; the upgrade may have renamed or removed it.",
                    )
                )
            elif load == "masked":
                findings.append(
                    _finding(Severity.CRITICAL, f"{u} is masked", [f"sudo systemctl unmask {u}"])
                )
            elif load != "loaded":
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        f"{u} can't be loaded ({load})",
                        [f"systemctl status {u}", f"systemd-analyze verify {u}"],
                    )
                )
            else:
                if u in need_active:
                    findings.extend(self._active(u, st, related))
                if u in need_enabled:
                    findings.extend(self._enabled(u, st, related))
        findings.extend(self._time_sync(time_sync, states, related))
        return findings

    def _related(self, ctx: Context, states: list[UnitState]) -> dict[str, UnitState]:
        names = sorted(
            {
                d
                for st in states
                for key in ("TriggeredBy", "Requires", "BindsTo")
                for d in _words(st, key)
            }
        )
        return unit_states(ctx, names) if names else {}

    @staticmethod
    def _active(u: str, st: UnitState, related: dict[str, UnitState]) -> list[Finding]:
        active = st.get("ActiveState", "")
        if active == "failed":
            return [
                _finding(
                    Severity.CRITICAL,
                    f"{u} failed",
                    [f"systemctl status {u}", f"journalctl -u {u} -b"],
                )
            ]
        if active == "active":
            deps = [
                d
                for d in (*_words(st, "Requires"), *_words(st, "BindsTo"))
                if related.get(d, {}).get("ActiveState") in ("inactive", "failed")
            ]
            return [
                _finding(
                    Severity.WARNING,
                    f"{u} is running but needs {d}, which is {related[d]['ActiveState']}",
                    [f"systemctl list-dependencies {u}", f"systemctl status {d}"],
                )
                for d in deps
            ]
        if active in TRANSITIONAL:
            return [_finding(Severity.WARNING, f"{u} is {active}", [f"systemctl status {u}"])]
        if st.get("ConditionResult") == "no":
            return []  # skipped by a condition (e.g. not in a container): by design
        triggers = _words(st, "TriggeredBy")
        if any(related.get(t, {}).get("ActiveState") == "active" for t in triggers):
            return []  # socket-activated: starts on the first connection
        if triggers:
            return [
                _finding(
                    Severity.CRITICAL,
                    f"{u} is socket-activated but {triggers[0]} isn't listening",
                    [f"sudo systemctl start {triggers[0]}"],
                )
            ]
        return [_finding(Severity.CRITICAL, f"{u} is not running", [f"sudo systemctl start {u}"])]

    @staticmethod
    def _enabled(u: str, st: UnitState, related: dict[str, UnitState]) -> list[Finding]:
        if st.get("UnitFileState") in ENABLED_STATES:
            return []
        if any(
            related.get(t, {}).get("UnitFileState") in ENABLED_STATES
            for t in _words(st, "TriggeredBy")
        ):
            return []
        return [
            _finding(
                Severity.WARNING,
                f"{u} is not enabled",
                [f"sudo systemctl enable {u}"],
                f"Its unit file state is {st.get('UnitFileState') or 'unknown'}, so it won't "
                "start at boot.",
            )
        ]

    def _time_sync(
        self, loaded: list[str], states: dict[str, UnitState], related: dict[str, UnitState]
    ) -> list[Finding]:
        if not loaded or any(not self._active(u, states[u], related) for u in loaded):
            return []
        return [
            Finding(
                Severity.CRITICAL,
                "No time synchronisation service is running",
                detail=f"Installed: {', '.join(loaded)}. {PROCESS_NOTE}",
                evidence=[f"{u}: {states[u].get('ActiveState', '')}" for u in sorted(loaded)],
                remediation=[f"sudo systemctl start {loaded[0]}", "timedatectl status"],
            )
        ]
