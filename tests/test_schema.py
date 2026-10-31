"""The published JSON Schemas of the report and config formats."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from conftest import make_sample_report
from pydebuprep import checks, model
from pydebuprep.config import REPORT_HELP, UPLOAD_HELP, example_config
from pydebuprep.render import render
from pydebuprep.schema import config_schema, main, report_schema

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schema"


@pytest.mark.parametrize(("name", "schema"), [("report", report_schema), ("config", config_schema)])
def test_published_files_match_the_code(name: str, schema: Any) -> None:
    published = (SCHEMA_DIR / f"{name}.schema.json").read_text()
    assert published == json.dumps(schema(), indent=2, sort_keys=True) + "\n", (
        "regenerate with: make generated"
    )


def test_ids_and_draft() -> None:
    for name, schema in (("report", report_schema()), ("config", config_schema())):
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["$id"] == f"https://pydebuprep.app/schema/{name}.schema.json"


@pytest.mark.parametrize(
    ("cls", "where"),
    [
        (model.Report, None),
        (model.Host, "host"),
        (model.BaselineInfo, "baseline"),
        (model.Summary, "summary"),
        (model.CheckResult, "result"),
        (model.Finding, "finding"),
        (model.ConfigInfo, "config"),
    ],
)
def test_every_model_field_is_in_the_schema(cls: type, where: str | None) -> None:
    schema = report_schema()
    obj = schema if where is None else schema["$defs"][where]
    fields = {f.name for f in dataclasses.fields(cls)}
    assert fields <= set(obj["properties"]), fields - set(obj["properties"])


def test_report_schema_version_is_pinned() -> None:
    assert report_schema()["properties"]["schema_version"] == {"const": model.SCHEMA_VERSION}


def test_every_check_and_option_in_the_config_schema() -> None:
    types = {bool: "boolean", int: "integer", float: "number", str: "string"}
    props = config_schema()["properties"]["checks"]["properties"]
    assert set(props) == {cls.id for cls in checks.ALL_CHECKS}
    for cls in checks.ALL_CHECKS:
        options = props[cls.id]["properties"]
        assert options["enabled"]["type"] == "boolean"
        for option in cls.options:
            entry = options[option.name]
            if isinstance(option.default, list):
                assert entry["items"] == {"type": "string"}
            else:
                assert entry["type"] == types[type(option.default)]
            assert entry["description"] == option.help


def test_report_and_upload_keys_in_the_config_schema() -> None:
    props = config_schema()["properties"]
    assert set(props["report"]["properties"]) == set(REPORT_HELP)
    assert set(props["upload"]["properties"]) == set(UPLOAD_HELP)
    assert set(props) == {"report", "logs", "checks", "upload"}


def test_main_prints_a_schema(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["report"]) == 0
    assert json.loads(capsys.readouterr().out) == report_schema()
    assert main(["config"]) == 0
    assert json.loads(capsys.readouterr().out) == config_schema()
    assert main(["nope"]) == 2
    assert main([]) == 2


# --- validation with a real JSON Schema validator ---------------------------------


@pytest.fixture
def validator() -> Any:
    jsonschema = pytest.importorskip("jsonschema")
    return jsonschema.Draft202012Validator


def test_sample_reports_validate(validator: Any) -> None:
    check = validator(report_schema())
    report = make_sample_report()
    check.validate(json.loads(render(report, "json")))
    remote = dataclasses.replace(
        report, config=model.ConfigInfo("https://p/c", "2026-10-30T09:00:00+00:00", True)
    )
    check.validate(json.loads(render(remote, "json", todo=True)))


def test_a_report_may_gain_fields(validator: Any) -> None:
    data = json.loads(render(make_sample_report(), "json")) | {"added_later": 1}
    validator(report_schema()).validate(data)


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": "2"},
        {"summary": {"critical": "many"}},
        {"results": [{"id": "x"}]},
        {"config": {"source": "u"}},
    ],
)
def test_broken_reports_fail(validator: Any, change: dict[str, Any]) -> None:
    data = json.loads(render(make_sample_report(), "json")) | change
    assert not validator(report_schema()).is_valid(data)


def test_example_config_validates(validator: Any) -> None:
    validator(config_schema()).validate(yaml.safe_load(example_config()))
    validator(config_schema()).validate({})


@pytest.mark.parametrize(
    "config",
    [
        {"unknown": {}},
        {"report": {"format": "pdf"}},
        {"checks": {"no-such-check": {}}},
        {"checks": {"disk-space": {"warning_pct": "lots"}}},
        {"upload": {"url": 5}},
    ],
)
def test_bad_configs_fail(validator: Any, config: dict[str, Any]) -> None:
    assert not validator(config_schema()).is_valid(config)


def test_references_must_be_web_links(validator: Any) -> None:
    data = json.loads(render(make_sample_report(), "json"))
    data["results"][0]["findings"][0]["references"] = ["javascript:alert(1)"]
    assert not validator(report_schema()).is_valid(data)


def test_the_package_is_typed() -> None:
    assert (ROOT / "src" / "pydebuprep" / "py.typed").exists()
    assert "py.typed" in (ROOT / "setup.cfg").read_text()
