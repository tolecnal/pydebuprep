"""A report run with a config fetched from a URL says so, and says when it is stale."""

from __future__ import annotations

import dataclasses
import json
import re
from typing import Any

import pytest

from conftest import make_sample_report
from pydebuprep.model import ConfigInfo
from pydebuprep.render import render
from pydebuprep.render._common import config_line
from pydebuprep.reportfile import ReportFileError, load_report, report_from_dict

URL = "https://portal.example/api/v1/configs/web/default"
REMOTE = ConfigInfo(URL, "2026-10-29T14:02:00+00:00", False)
STALE = dataclasses.replace(REMOTE, stale=True)


def test_local_config_adds_no_key() -> None:
    assert "config" not in json.loads(render(make_sample_report(), "json"))


@pytest.mark.parametrize("fmt", ["json", "yaml"])
def test_config_round_trips(fmt: str) -> None:
    report = dataclasses.replace(make_sample_report(), config=STALE)
    assert load_report(render(report, fmt)) == report


def test_config_line() -> None:
    assert config_line(make_sample_report()) is None
    assert config_line(dataclasses.replace(make_sample_report(), config=REMOTE)) == (
        f"Config: {URL} (fetched 2026-10-29T14:02:00+00:00)"
    )
    assert config_line(dataclasses.replace(make_sample_report(), config=STALE)) == (
        f"Config from {URL} could not be fetched; used the copy fetched on "
        "2026-10-29T14:02:00+00:00 — it may not be the latest"
    )


@pytest.mark.parametrize("fmt", ["text", "markdown", "html", "jira", "confluence"])
def test_stale_note_in_every_header(fmt: str) -> None:
    out = render(dataclasses.replace(make_sample_report(), config=STALE), fmt)
    assert "could not be fetched" in out
    assert out.index("could not be fetched") < out.index("Repository still targets bookworm")


@pytest.mark.parametrize("fmt", ["text", "markdown", "html", "jira", "confluence"])
def test_no_config_line_for_a_local_config(fmt: str) -> None:
    assert "Config" not in render(make_sample_report(), fmt).split("Summary")[0]


@pytest.mark.parametrize(
    ("bad", "error"),
    [
        (
            {"source": 1, "fetched_at": "2026-10-29T14:02:00+00:00", "stale": False},
            "config.source: expected a string",
        ),
        (
            {"source": "u", "fetched_at": "2026-10-29T14:02:00+00:00", "stale": "no"},
            "config.stale: expected true or false",
        ),
        ({"source": "u", "stale": True}, "config.fetched_at: missing"),
        ("x", "config: expected a mapping"),
    ],
)
def test_bad_config_field(bad: Any, error: str) -> None:
    data = json.loads(render(make_sample_report(), "json")) | {"config": bad}
    with pytest.raises(ReportFileError, match=re.escape(error)):
        report_from_dict(data)


def test_null_config_reads_as_none() -> None:
    data = json.loads(render(make_sample_report(), "json")) | {"config": None}
    assert report_from_dict(data).config is None
