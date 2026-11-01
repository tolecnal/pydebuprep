"""Report data model: the single source of truth that every output format renders."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = "1"
CATEGORY_ORDER = (
    "release",
    "packages",
    "boot",
    "services",
    "applications",
    "network",
    "security",
    "storage",
)
EVIDENCE_LIMIT = 20


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 3, "warning": 2, "info": 1}[self.value]


class Status(str, Enum):
    OK = "ok"
    FINDINGS = "findings"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "evidence": list(self.evidence),
            "remediation": list(self.remediation),
            "references": list(self.references),
        }


@dataclass
class CheckResult:
    id: str
    title: str
    category: str
    status: Status
    findings: list[Finding] = field(default_factory=list)
    baseline_diff: list[Finding] | None = None
    skipped_reason: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "status": self.status.value,
            "skipped_reason": self.skipped_reason,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
            "baseline_diff": (
                None if self.baseline_diff is None else [f.to_dict() for f in self.baseline_diff]
            ),
        }


@dataclass
class Host:
    hostname: str
    os_id: str
    os_version: str
    codename: str
    kernel: str
    is_root: bool
    # pydebuprep's hash of /etc/machine-id (see identity.py); None when there is none.
    machine_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "hostname": self.hostname,
            "os_id": self.os_id,
            "os_version": self.os_version,
            "codename": self.codename,
            "kernel": self.kernel,
            "is_root": self.is_root,
        }
        if self.machine_id is not None:
            data["machine_id"] = self.machine_id
        return data


@dataclass
class BaselineInfo:
    path: str
    created_at: str
    os_version: str
    hostname: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "created_at": self.created_at,
            "os_version": self.os_version,
            "hostname": self.hostname,
        }


@dataclass
class ConfigInfo:
    """Where a config fetched from a URL came from; stale when a saved copy stood in."""

    source: str
    fetched_at: str
    stale: bool

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "fetched_at": self.fetched_at, "stale": self.stale}


@dataclass
class Summary:
    critical: int
    warning: int
    info: int
    ok: int
    skipped: int
    error: int
    exit_code: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "critical": self.critical,
            "warning": self.warning,
            "info": self.info,
            "ok": self.ok,
            "skipped": self.skipped,
            "error": self.error,
            "exit_code": self.exit_code,
        }


@dataclass
class Report:
    tool: dict[str, str]
    generated_at: str
    host: Host
    baseline: BaselineInfo | None
    summary: Summary
    results: list[CheckResult]
    schema_version: str = SCHEMA_VERSION
    config: ConfigInfo | None = None  # set only for a config fetched from a URL

    def to_dict(self) -> dict[str, Any]:
        data = {
            "schema_version": self.schema_version,
            "tool": dict(self.tool),
            "generated_at": self.generated_at,
            "host": self.host.to_dict(),
            "baseline": None if self.baseline is None else self.baseline.to_dict(),
            "summary": self.summary.to_dict(),
            "results": [r.to_dict() for r in self.results],
        }
        if self.config is not None:
            data["config"] = self.config.to_dict()
        return data


def truncate_evidence(lines: list[str], limit: int = EVIDENCE_LIMIT) -> list[str]:
    if len(lines) <= limit:
        return list(lines)
    return [*lines[:limit], f"... (+{len(lines) - limit} more)"]


def all_findings(result: CheckResult) -> list[Finding]:
    return [*result.findings, *(result.baseline_diff or [])]


def compute_summary(results: list[CheckResult]) -> Summary:
    counts = {s: 0 for s in Severity}
    for result in results:
        for finding in all_findings(result):
            counts[finding.severity] += 1
    by_status = {s: sum(1 for r in results if r.status is s) for s in Status}
    if counts[Severity.CRITICAL]:
        exit_code = 2
    elif counts[Severity.WARNING]:
        exit_code = 1
    elif by_status[Status.ERROR]:
        # A check that could not run may be hiding a problem; don't report "all clear".
        exit_code = 1
    else:
        exit_code = 0
    return Summary(
        critical=counts[Severity.CRITICAL],
        warning=counts[Severity.WARNING],
        info=counts[Severity.INFO],
        ok=by_status[Status.OK],
        skipped=by_status[Status.SKIPPED],
        error=by_status[Status.ERROR],
        exit_code=exit_code,
    )


def _category_index(category: str) -> int:
    try:
        return CATEGORY_ORDER.index(category)
    except ValueError:
        return len(CATEGORY_ORDER)


def sort_results(results: list[CheckResult]) -> list[CheckResult]:
    return sorted(results, key=lambda r: (_category_index(r.category), r.id))


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: -f.severity.rank)
