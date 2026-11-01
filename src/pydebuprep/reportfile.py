"""Read back a report saved as JSON or YAML, so it can be rendered in another format.

Only the machine formats hold the whole report; text, HTML, Markdown, Jira and
Confluence are renderings and can't be read back. Report files may come from other
hosts, so the input is validated field by field and YAML is loaded with safe_load.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from typing import Any, TypeVar

from pydebuprep.deps import require_yaml
from pydebuprep.identity import MACHINE_ID
from pydebuprep.model import (
    SCHEMA_VERSION,
    BaselineInfo,
    CheckResult,
    ConfigInfo,
    Finding,
    Host,
    Report,
    Severity,
    Status,
    Summary,
)
from pydebuprep.render._common import safe_url

NOT_A_REPORT = (
    "not a pydebuprep report: expected a JSON or YAML report (from --format json or "
    "--format yaml); text, HTML, Markdown, Jira and Confluence reports can't be read back"
)

BASELINE_FIELDS = ("path", "created_at", "os_version", "hostname")
SUMMARY_FIELDS = ("critical", "warning", "info", "ok", "skipped", "error", "exit_code")

E = TypeVar("E", bound=Enum)


class ReportFileError(ValueError):
    pass


def load_report(text: str) -> Report:
    """Parse a JSON or YAML report; raises ReportFileError saying what is wrong."""
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ReportFileError(
                f"not valid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})"
            ) from None
    else:
        yaml = require_yaml()
        try:
            data = yaml.safe_load(stripped)
        except yaml.YAMLError:
            raise ReportFileError(NOT_A_REPORT) from None
    if not isinstance(data, dict) or "schema_version" not in data:
        raise ReportFileError(NOT_A_REPORT)
    return report_from_dict(data)


def report_from_dict(data: dict[str, Any]) -> Report:
    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        raise ReportFileError(
            f"schema_version: unsupported version {version!r} "
            f"(this pydebuprep reads version {SCHEMA_VERSION})"
        )
    tool = _field(data, "tool", "")
    if not isinstance(tool, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in tool.items()
    ):
        raise ReportFileError("tool: expected a mapping of strings")
    generated_at = _str(_field(data, "generated_at", ""), "generated_at")
    try:
        datetime.fromisoformat(generated_at)
    except ValueError:
        raise ReportFileError(f"generated_at: not an ISO 8601 time: {generated_at!r}") from None
    baseline = _field(data, "baseline", "")
    results = _field(data, "results", "")
    if not isinstance(results, list):
        raise ReportFileError("results: expected a list")
    return Report(
        tool=dict(tool),
        generated_at=generated_at,
        host=_host(_map(_field(data, "host", ""), "host"), "host"),
        baseline=None if baseline is None else _baseline(_map(baseline, "baseline"), "baseline"),
        summary=_summary(_map(_field(data, "summary", ""), "summary"), "summary"),
        results=[_result(_map(r, f"results[{i}]"), f"results[{i}]") for i, r in enumerate(results)],
        schema_version=SCHEMA_VERSION,
        config=None if data.get("config") is None else _config(_map(data["config"], "config")),
    )


def _config(d: dict[str, Any]) -> ConfigInfo:
    return ConfigInfo(
        source=_str(_field(d, "source", "config"), "config.source"),
        fetched_at=_str(_field(d, "fetched_at", "config"), "config.fetched_at"),
        stale=_bool(_field(d, "stale", "config"), "config.stale"),
    )


def _host(d: dict[str, Any], path: str) -> Host:
    return Host(
        hostname=_str(_field(d, "hostname", path), f"{path}.hostname"),
        os_id=_str(_field(d, "os_id", path), f"{path}.os_id"),
        os_version=_str(_field(d, "os_version", path), f"{path}.os_version"),
        codename=_str(_field(d, "codename", path), f"{path}.codename"),
        kernel=_str(_field(d, "kernel", path), f"{path}.kernel"),
        is_root=_bool(_field(d, "is_root", path), f"{path}.is_root"),
        machine_id=_machine_id(d.get("machine_id"), f"{path}.machine_id"),
    )


def _machine_id(value: Any, path: str) -> str | None:
    if value is not None and not (isinstance(value, str) and MACHINE_ID.fullmatch(value)):
        raise ReportFileError(f"{path}: expected 32 lower-case hexadecimal digits")
    return value


def _baseline(d: dict[str, Any], path: str) -> BaselineInfo:
    return BaselineInfo(**{k: _str(_field(d, k, path), f"{path}.{k}") for k in BASELINE_FIELDS})


def _summary(d: dict[str, Any], path: str) -> Summary:
    return Summary(**{k: _int(_field(d, k, path), f"{path}.{k}") for k in SUMMARY_FIELDS})


def _result(d: dict[str, Any], path: str) -> CheckResult:
    diff = d.get("baseline_diff")
    if diff is not None and not isinstance(diff, list):
        raise ReportFileError(f"{path}.baseline_diff: expected a list or null")
    return CheckResult(
        id=_str(_field(d, "id", path), f"{path}.id"),
        title=_str(_field(d, "title", path), f"{path}.title"),
        category=_str(_field(d, "category", path), f"{path}.category"),
        status=_enum(_field(d, "status", path), Status, f"{path}.status"),
        findings=_findings(d.get("findings", []), f"{path}.findings"),
        baseline_diff=None if diff is None else _findings(diff, f"{path}.baseline_diff"),
        skipped_reason=_opt_str(d.get("skipped_reason"), f"{path}.skipped_reason"),
        error=_opt_str(d.get("error"), f"{path}.error"),
    )


def _findings(items: Any, path: str) -> list[Finding]:
    if not isinstance(items, list):
        raise ReportFileError(f"{path}: expected a list")
    return [_finding(_map(f, f"{path}[{i}]"), f"{path}[{i}]") for i, f in enumerate(items)]


def _finding(d: dict[str, Any], path: str) -> Finding:
    return Finding(
        severity=_enum(_field(d, "severity", path), Severity, f"{path}.severity"),
        title=_str(_field(d, "title", path), f"{path}.title"),
        detail=_str(d.get("detail", ""), f"{path}.detail"),
        evidence=_strings(d.get("evidence", []), f"{path}.evidence"),
        remediation=_strings(d.get("remediation", []), f"{path}.remediation"),
        references=_references(d.get("references", []), f"{path}.references"),
    )


def _field(d: dict[str, Any], key: str, path: str) -> Any:
    if key not in d:
        raise ReportFileError(f"{path + '.' if path else ''}{key}: missing")
    return d[key]


def _map(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReportFileError(f"{path}: expected a mapping")
    return value


def _str(value: Any, path: str) -> str:
    if not isinstance(value, str):
        raise ReportFileError(f"{path}: expected a string")
    return value


def _opt_str(value: Any, path: str) -> str | None:
    return None if value is None else _str(value, path)


def _int(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReportFileError(f"{path}: expected an integer")
    return value


def _bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ReportFileError(f"{path}: expected true or false")
    return value


def _strings(value: Any, path: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ReportFileError(f"{path}: expected a list of strings")
    return list(value)


def _references(value: Any, path: str) -> list[str]:
    refs = _strings(value, path)
    for i, ref in enumerate(refs):
        if not safe_url(ref):
            raise ReportFileError(f"{path}[{i}]: expected an http:// or https:// URL, got {ref!r}")
    return refs


def _enum(value: Any, enum: type[E], path: str) -> E:
    try:
        return enum(value)
    except ValueError:
        choices = ", ".join(e.value for e in enum)
        raise ReportFileError(f"{path}: expected one of {choices}, got {value!r}") from None
