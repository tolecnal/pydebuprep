"""JSON Schemas of the report and config formats: the contract with other tools, such as
pydebuprep-portal. Published in schema/ (`make generated`); print one with
`python3 -m pydebuprep.schema report|config`.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from pydebuprep import checks
from pydebuprep.config import LOGS_HELP, REPORT_HELP, SEVERITIES, UPLOAD_HELP
from pydebuprep.model import CATEGORY_ORDER, SCHEMA_VERSION, Severity, Status
from pydebuprep.render import FORMATS

DRAFT = "https://json-schema.org/draft/2020-12/schema"
BASE = "https://pydebuprep.app/schema"

STRING = {"type": "string"}
STRINGS = {"type": "array", "items": STRING}
NULLABLE_STRING = {"type": ["string", "null"]}


def _object(properties: dict[str, Any], *, closed: bool = True) -> dict[str, Any]:
    """An object with every property required (reports always write all of them)."""
    obj: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "required": sorted(properties),
    }
    if closed:
        obj["additionalProperties"] = False
    return obj


def report_schema() -> dict[str, Any]:
    finding = _object(
        {
            "severity": {"enum": [s.value for s in Severity]},
            "title": STRING,
            "detail": STRING,
            "evidence": STRINGS,
            "remediation": STRINGS,
            "references": {"type": "array", "items": {"type": "string", "pattern": "^https?://"}},
        }
    )
    findings = {"type": "array", "items": {"$ref": "#/$defs/finding"}}
    result = _object(
        {
            "id": STRING,
            "title": STRING,
            "category": {"type": "string", "examples": list(CATEGORY_ORDER)},
            "status": {"enum": [s.value for s in Status]},
            "skipped_reason": NULLABLE_STRING,
            "error": NULLABLE_STRING,
            "findings": findings,
            "baseline_diff": {"oneOf": [findings, {"type": "null"}]},
        }
    )
    count = {"type": "integer", "minimum": 0}
    todo_item = _object(
        {
            "severity": {"enum": ["critical", "warning", None]},
            "check": NULLABLE_STRING,
            "title": STRING,
            "steps": STRINGS,
        }
    )
    schema = _object(
        {
            "schema_version": {"const": SCHEMA_VERSION},
            "tool": {"type": "object", "additionalProperties": STRING},
            "generated_at": {"type": "string", "format": "date-time"},
            "host": {"$ref": "#/$defs/host"},
            "baseline": {"oneOf": [{"$ref": "#/$defs/baseline"}, {"type": "null"}]},
            "summary": {"$ref": "#/$defs/summary"},
            "results": {"type": "array", "items": {"$ref": "#/$defs/result"}},
            "config": {"$ref": "#/$defs/config"},
            "todo": {"type": "array", "items": {"$ref": "#/$defs/todo_item"}},
        },
        closed=False,  # later versions may add fields
    )
    schema["required"] = [
        "baseline", "generated_at", "host", "results", "schema_version", "summary", "tool",
    ]  # fmt: skip
    schema["$defs"] = {
        "host": _object(
            {
                "hostname": STRING,
                "os_id": STRING,
                "os_version": STRING,
                "codename": STRING,
                "kernel": STRING,
                "is_root": {"type": "boolean"},
            }
        ),
        "baseline": _object(
            {"path": STRING, "created_at": STRING, "os_version": STRING, "hostname": STRING}
        ),
        "summary": _object(
            {
                "critical": count,
                "warning": count,
                "info": count,
                "ok": count,
                "skipped": count,
                "error": count,
                "exit_code": {"enum": [0, 1, 2]},
            }
        ),
        "result": result,
        "finding": finding,
        "config": _object(
            {
                "source": {"type": "string", "format": "uri"},
                "fetched_at": {"type": "string", "format": "date-time"},
                "stale": {"type": "boolean"},
            }
        ),
        "todo_item": todo_item,
    }
    return {
        "$schema": DRAFT,
        "$id": f"{BASE}/report.schema.json",
        "title": "pydebuprep report",
        "description": "A report written with --format json or --format yaml. Present only "
        "when the config came from a URL: config. Present only with --todo: todo.",
        **schema,
    }


def _option_schema(default: Any, help_text: str) -> dict[str, Any]:
    if isinstance(default, bool):
        kind: dict[str, Any] = {"type": "boolean"}
    elif isinstance(default, int):
        kind = {"type": "integer"}
    elif isinstance(default, float):
        kind = {"type": "number"}
    elif isinstance(default, list):
        kind = {"type": "array", "items": STRING}
    else:
        kind = {"type": "string"}
    return {**kind, "default": default, "description": help_text}


def _settings(properties: dict[str, Any]) -> dict[str, Any]:
    return {"type": ["object", "null"], "properties": properties, "additionalProperties": False}


def config_schema() -> dict[str, Any]:
    report_types: dict[str, Any] = {
        "format": {"enum": list(FORMATS)},
        "output_dir": NULLABLE_STRING,
        "min_severity": {"enum": list(SEVERITIES)},
        "color": {"type": "boolean"},
        "todo": {"type": "boolean"},
        "baseline": STRING,
        "snapshot_dir": STRING,
    }
    upload_types: dict[str, Any] = {
        "url": {"type": ["string", "null"], "format": "uri", "pattern": "^https?://"},
        "token_file": STRING,
        "ca_file": NULLABLE_STRING,
        "pending_dir": NULLABLE_STRING,
    }
    check_props = {}
    for cls in checks.ALL_CHECKS:
        options = {"enabled": {"type": "boolean", "default": True}}
        options |= {o.name: _option_schema(o.default, o.help) for o in cls.options}
        check_props[cls.id] = {**_settings(options), "description": cls.title}
    return {
        "$schema": DRAFT,
        "$id": f"{BASE}/config.schema.json",
        "title": "pydebuprep configuration",
        "description": "The YAML configuration file (/etc/pydebuprep.conf, or --config).",
        "type": ["object", "null"],
        "additionalProperties": False,
        "properties": {
            "report": _settings(
                {k: {**report_types[k], "description": text} for k, text in REPORT_HELP.items()}
            ),
            "logs": _settings({"ignore": {**STRINGS, "description": LOGS_HELP}}),
            "upload": _settings(
                {k: {**upload_types[k], "description": text} for k, text in UPLOAD_HELP.items()}
            ),
            "checks": _settings(check_props),
        },
    }


def main(argv: list[str]) -> int:
    schemas = {"report": report_schema, "config": config_schema}
    if len(argv) != 1 or argv[0] not in schemas:
        print("usage: python3 -m pydebuprep.schema report|config", file=sys.stderr)
        return 2
    print(json.dumps(schemas[argv[0]](), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
