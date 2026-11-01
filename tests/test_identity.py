"""The machine ID a report carries: an app-specific hash of /etc/machine-id."""

from __future__ import annotations

import dataclasses
import json

import pytest

from conftest import make_sample_report
from fakes import FakeSystem
from pydebuprep.identity import APP_ID, app_specific_id, machine_id
from pydebuprep.model import Report
from pydebuprep.render import render
from pydebuprep.render._common import clean_report
from pydebuprep.reportfile import ReportFileError, report_from_dict
from pydebuprep.schema import report_schema

MACHINE = "0123456789abcdef0123456789abcdef"
# What `systemd-id128 machine-id -a e44561703c184c26a2c15fb541fc276a` prints on a
# machine whose /etc/machine-id is MACHINE.
EXPECTED = "97550a10b77649e0b7a4f6565cb35289"


def test_app_id_never_changes() -> None:
    # Changing it would give every host a new ID in the portal.
    assert APP_ID == "e44561703c184c26a2c15fb541fc276a"


def test_app_specific_id_matches_systemd() -> None:
    assert app_specific_id(MACHINE) == EXPECTED
    assert app_specific_id(MACHINE.upper() + "\n") == EXPECTED


@pytest.mark.parametrize(
    "text", ["", "uninitialized\n", MACHINE[:-1], MACHINE + "0", "g" * 32, "0" * 32]
)
def test_unusable_machine_ids_give_none(text: str) -> None:
    assert app_specific_id(text) is None


def test_machine_id_reads_etc_machine_id() -> None:
    system = FakeSystem(files={"/etc/machine-id": MACHINE + "\n"})
    assert machine_id(system) == EXPECTED
    assert machine_id(system) != MACHINE  # the real ID never leaves the host


def test_machine_id_falls_back_to_dbus() -> None:
    system = FakeSystem(files={"/var/lib/dbus/machine-id": MACHINE + "\n"})
    assert machine_id(system) == EXPECTED


def test_machine_id_is_none_without_one() -> None:
    assert machine_id(FakeSystem()) is None
    assert machine_id(FakeSystem(files={"/etc/machine-id": "uninitialized\n"})) is None


# --- in the report ------------------------------------------------------------------


def _report(**host: object) -> Report:
    report = make_sample_report()
    return dataclasses.replace(report, host=dataclasses.replace(report.host, **host))


def test_host_writes_machine_id_only_when_known() -> None:
    assert _report(machine_id=EXPECTED).host.to_dict()["machine_id"] == EXPECTED
    assert "machine_id" not in _report().host.to_dict()


def test_schema_accepts_a_machine_id_and_reports_without_one() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    check = jsonschema.Draft202012Validator(report_schema())
    check.validate(json.loads(render(_report(machine_id=EXPECTED), "json")))
    check.validate(json.loads(render(_report(), "json")))
    data = json.loads(render(_report(), "json"))
    data["host"]["machine_id"] = MACHINE[:-1]
    assert not check.is_valid(data)


def test_saved_reports_keep_the_machine_id() -> None:
    data = _report(machine_id=EXPECTED).to_dict()
    assert report_from_dict(data).host.machine_id == EXPECTED
    del data["host"]["machine_id"]
    assert report_from_dict(data).host.machine_id is None


@pytest.mark.parametrize("value", [5, "not-hex", MACHINE.upper()])
def test_saved_reports_refuse_a_malformed_machine_id(value: object) -> None:
    data = _report().to_dict()
    data["host"]["machine_id"] = value
    with pytest.raises(ReportFileError, match=r"host\.machine_id"):
        report_from_dict(data)


def test_rendered_reports_keep_the_machine_id() -> None:
    assert clean_report(_report(machine_id=EXPECTED)).host.machine_id == EXPECTED
    for fmt in ("text", "markdown", "html"):
        assert EXPECTED in render(_report(machine_id=EXPECTED), fmt), fmt
