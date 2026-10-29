from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

from fakes import FakeSystem
from pydebuprep.checks.base import Context
from pydebuprep.checks.systemd_critical import SystemdCriticalCheck, parse_show
from pydebuprep.model import Severity, Status
from pydebuprep.osinfo import detect_os
from pydebuprep.runner import run_check
from pydebuprep.system import SHOW_UNITS, CommandResult

from .helpers import OS_RELEASES, titles

NOT_FOUND = {
    "LoadState": "not-found",
    "ActiveState": "inactive",
    "SubState": "dead",
    "UnitFileState": "",
    "ConditionResult": "no",
}


def unit(**props: str) -> dict[str, str]:
    return {
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "UnitFileState": "enabled",
        "ConditionResult": "yes",
        **props,
    }


HEALTHY = {
    "ssh.service": unit(),
    "cron.service": unit(),
    "systemd-journald.service": unit(UnitFileState="static"),
    "systemd-timesyncd.service": unit(),
}


def block(name: str, props: dict[str, str]) -> str:
    full = {
        "Id": name,
        "Names": name,
        "TriggeredBy": "",
        "Requires": "",
        "BindsTo": "",
        "ControlGroup": f"/system.slice/{name}",
        **props,
    }
    return "\n".join(f"{k}={v}" for k, v in full.items()) + "\n"


class UnitsSystem(FakeSystem):
    """Answers SHOW_UNITS from a table of units; anything not in it is not-found."""

    def __init__(self, units: dict[str, dict[str, str]], **kw: Any) -> None:
        super().__init__(**kw)
        self.units = units

    def run(self, argv: Sequence[str], timeout: float = 30.0) -> CommandResult:
        args = tuple(argv)
        if args[: len(SHOW_UNITS)] != SHOW_UNITS:
            return super().run(argv, timeout)
        self.calls.append(args)
        names = args[len(SHOW_UNITS) :]
        text = "\n".join(block(n, self.units.get(n, NOT_FOUND)) for n in names)
        return CommandResult(args, 0, text, "")


def ctx(units: dict[str, dict[str, str]] | None = None, **kw: Any) -> Context:
    files = {"/etc/os-release": OS_RELEASES["trixie"], **kw.pop("files", {})}
    system = UnitsSystem({**HEALTHY, **(units or {})}, files=files, **kw)
    return Context(system, detect_os(system))


def findings(units: dict[str, dict[str, str]] | None = None, **opts: Any) -> list[Any]:
    return SystemdCriticalCheck(opts).run(ctx(units))


def test_parse_show_blocks_in_order() -> None:
    text = "\nId=a.service\nLoadState=loaded\n\n\nId=b.service\nLoadState=not-found\nNames=\n"
    assert parse_show(text) == [
        {"Id": "a.service", "LoadState": "loaded"},
        {"Id": "b.service", "LoadState": "not-found", "Names": ""},
    ]


def test_all_builtin_units_healthy_no_findings() -> None:
    assert findings() == []


def test_builtin_units_not_installed_are_ignored() -> None:
    assert findings({"ssh.service": NOT_FOUND, "cron.service": NOT_FOUND}) == []


def test_configured_unit_not_found_is_critical() -> None:
    (f,) = findings(required_active=["nginx.service"])
    assert (f.severity, f.title) == (Severity.CRITICAL, "nginx.service does not exist")
    assert f.remediation == ["systemctl list-unit-files 'nginx*'"]


def test_masked_unit_is_critical_with_unmask() -> None:
    (f,) = findings(
        {"ssh.service": unit(LoadState="masked", ActiveState="inactive", UnitFileState="masked")}
    )
    assert (f.severity, f.title) == (Severity.CRITICAL, "ssh.service is masked")
    assert f.remediation == ["sudo systemctl unmask ssh.service"]


def test_unit_that_fails_to_load_is_critical() -> None:
    (f,) = findings({"cron.service": unit(LoadState="bad-setting", ActiveState="inactive")})
    assert (f.severity, f.title) == (
        Severity.CRITICAL,
        "cron.service can't be loaded (bad-setting)",
    )


def test_failed_unit_is_critical() -> None:
    (f,) = findings({"cron.service": unit(ActiveState="failed", SubState="failed")})
    assert (f.severity, f.title) == (Severity.CRITICAL, "cron.service failed")
    assert f.remediation == ["systemctl status cron.service", "journalctl -u cron.service -b"]


def test_inactive_required_unit_is_critical() -> None:
    (f,) = findings({"cron.service": unit(ActiveState="inactive", SubState="dead")})
    assert (f.severity, f.title) == (Severity.CRITICAL, "cron.service is not running")
    assert f.remediation == ["sudo systemctl start cron.service"]


def test_socket_activated_service_is_fine() -> None:
    units = {
        "ssh.service": unit(
            ActiveState="inactive",
            SubState="dead",
            UnitFileState="disabled",
            TriggeredBy="ssh.socket",
        ),
        "ssh.socket": unit(SubState="listening"),
    }
    assert findings(units) == []


def test_socket_not_listening_is_critical() -> None:
    units = {
        "ssh.service": unit(ActiveState="inactive", SubState="dead", TriggeredBy="ssh.socket"),
        "ssh.socket": unit(ActiveState="inactive", SubState="dead"),
    }
    (f,) = findings(units)
    assert (f.severity, f.title) == (
        Severity.CRITICAL,
        "ssh.service is socket-activated but ssh.socket isn't listening",
    )
    assert f.remediation == ["sudo systemctl start ssh.socket"]


def test_transitional_state_is_warning() -> None:
    (f,) = findings({"cron.service": unit(ActiveState="activating", SubState="start")})
    assert (f.severity, f.title) == (Severity.WARNING, "cron.service is activating")


def test_running_with_inactive_dependency_warns() -> None:
    units = {
        "cron.service": unit(Requires="sysinit.target -.mount data.mount"),
        "sysinit.target": unit(SubState="active"),
        "data.mount": unit(ActiveState="inactive", SubState="dead"),
    }
    (f,) = findings(units)
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "cron.service is running but needs data.mount, which is inactive",
    )


def test_disabled_required_enabled_unit_warns() -> None:
    (f,) = findings({"cron.service": unit(UnitFileState="disabled")})
    assert (f.severity, f.title) == (Severity.WARNING, "cron.service is not enabled")
    assert f.remediation == ["sudo systemctl enable cron.service"]
    for state in ("static", "indirect", "enabled-runtime", "generated", "alias"):
        assert findings({"cron.service": unit(UnitFileState=state)}) == [], state


def test_configured_lists_are_separate() -> None:
    units = {
        "nginx.service": unit(UnitFileState="disabled"),
        "backup.service": unit(ActiveState="inactive", SubState="dead"),
    }
    # Only required running: disabled is fine. Only required enabled: inactive is fine.
    assert findings(units, required_active=["nginx.service"]) == []
    assert findings(units, required_enabled=["backup.service"]) == []
    assert titles(findings(units, required_enabled=["nginx.service"])) == [
        "nginx.service is not enabled"
    ]


def test_time_sync_one_active_is_enough() -> None:
    units = {
        "systemd-timesyncd.service": unit(ActiveState="inactive", SubState="dead"),
        "chrony.service": unit(),
    }
    assert findings(units) == []


def test_time_sync_none_active_is_one_finding() -> None:
    units = {
        "systemd-timesyncd.service": unit(ActiveState="inactive", SubState="dead"),
        "chrony.service": unit(ActiveState="failed", SubState="failed"),
    }
    (f,) = findings(units)
    assert (f.severity, f.title) == (
        Severity.CRITICAL,
        "No time synchronisation service is running",
    )
    assert f.evidence == ["chrony.service: failed", "systemd-timesyncd.service: inactive"]


def test_time_sync_not_installed_is_fine() -> None:
    assert findings({"systemd-timesyncd.service": NOT_FOUND}) == []


def test_condition_skipped_unit_is_not_a_finding() -> None:
    units = {
        "systemd-timesyncd.service": unit(
            ActiveState="inactive", SubState="dead", ConditionResult="no"
        )
    }
    assert findings(units) == []


def test_duplicate_units_reported_once() -> None:
    c = ctx({"cron.service": unit(ActiveState="inactive", SubState="dead")})
    check = SystemdCriticalCheck(
        {"required_active": ["cron.service", "cron.service"], "required_enabled": ["cron.service"]}
    )
    assert titles(check.run(c)) == ["cron.service is not running"]
    first_query = c.system.calls[0][len(SHOW_UNITS) :]  # type: ignore[attr-defined]
    assert first_query.count("cron.service") == 1


def test_invalid_unit_name_rejected() -> None:
    with pytest.raises(ValueError, match="required_active"):
        SystemdCriticalCheck({"required_active": ["ssh; rm"]})
    with pytest.raises(ValueError, match="required_enabled"):
        SystemdCriticalCheck({"required_enabled": ["-H"]})


def test_without_systemd_is_skipped() -> None:
    files = {"/etc/os-release": OS_RELEASES["trixie"]}
    no_systemd = CommandResult((), 1, "", "System has not been booted with systemd\n")

    class NoSystemd(FakeSystem):
        def run(self, argv: Sequence[str], timeout: float = 30.0) -> CommandResult:
            return no_systemd

    system = NoSystemd(files=files)
    assert run_check(SystemdCriticalCheck(), Context(system, detect_os(system))).status is (
        Status.SKIPPED
    )


def test_builtin_false_and_ignore_units() -> None:
    broken = {"cron.service": unit(ActiveState="failed"), "ssh.service": unit(ActiveState="failed")}
    assert titles(findings(broken)) == ["ssh.service failed", "cron.service failed"]
    assert titles(findings(broken, ignore_units=["ssh.*"])) == ["cron.service failed"]
    assert findings(broken, builtin=False) == []
    assert titles(findings(broken, builtin=False, required_active=["cron.service"])) == [
        "cron.service failed"
    ]


def test_active_wording_is_process_state() -> None:
    (f,) = findings({"cron.service": unit(UnitFileState="disabled")})
    assert f.detail.endswith(
        "An active unit shows the process is running, not that the service works."
    )


def test_unexpected_show_output_is_an_error() -> None:
    class Short(UnitsSystem):
        def run(self, argv: Sequence[str], timeout: float = 30.0) -> CommandResult:
            return CommandResult(tuple(argv), 0, "Id=ssh.service\nLoadState=loaded\n", "")

    system = Short(HEALTHY, files={"/etc/os-release": OS_RELEASES["trixie"]})
    result = run_check(SystemdCriticalCheck(), Context(system, detect_os(system)))
    assert result.status is Status.ERROR


def test_empty_show_output_means_nothing_known() -> None:
    class Empty(UnitsSystem):
        def run(self, argv: Sequence[str], timeout: float = 30.0) -> CommandResult:
            return CommandResult(tuple(argv), 0, "", "")

    system = Empty(HEALTHY, files={"/etc/os-release": OS_RELEASES["trixie"]})
    assert SystemdCriticalCheck().run(Context(system, detect_os(system))) == []
