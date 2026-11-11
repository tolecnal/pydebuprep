"""Runs checks in isolation so one failing check never breaks the report."""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from typing import Any

from pydebuprep.checks.base import Check, CheckSkipped, Context
from pydebuprep.findings_history import classify
from pydebuprep.model import CheckResult, Finding, Status, sort_findings, sort_results
from pydebuprep.progress import Progress, tracked
from pydebuprep.redact import redact, redact_finding


def _describe(exc: BaseException) -> str:
    return redact(f"{type(exc).__name__}: {exc}")


def _labelled(findings: list[Finding], check: Check, ctx: Context) -> list[Finding]:
    """FINDINGS, each saying how it compares with what the snapshot's run of CHECK found."""
    recorded: Any = (ctx.baseline or {}).get("findings")
    before = recorded.get(check.id) if isinstance(recorded, dict) else None
    if not isinstance(before, list):
        return findings
    return [dataclasses.replace(f, since_snapshot=classify(f, before)) for f in findings]


def run_check(check: Check, ctx: Context) -> CheckResult:
    result = CheckResult(check.id, check.title, check.category, Status.OK)
    reason = check.unmet_requirement(ctx)
    if reason is not None:
        result.status = Status.SKIPPED
        result.skipped_reason = reason
        return result
    try:
        found = [redact_finding(f) for f in check.run(ctx)]
        result.findings = sort_findings(_labelled(found, check, ctx))
        diff: list[Finding] | None = None
        if ctx.baseline is not None and check.supports_baseline:
            before = ctx.baseline_for(check.id)
            if before is not None:
                diff = sort_findings([redact_finding(f) for f in check.compare(ctx, before)])
        result.baseline_diff = diff
    except CheckSkipped as exc:
        result.status = Status.SKIPPED
        result.skipped_reason = redact(str(exc))
        result.findings = []
        result.baseline_diff = None
        return result
    except Exception as exc:
        result.status = Status.ERROR
        result.error = _describe(exc)
        result.findings = []
        result.baseline_diff = None
        return result
    if result.findings or result.baseline_diff:
        result.status = Status.FINDINGS
    return result


def run_checks(
    checks: Sequence[Check], ctx: Context, progress: Progress | None = None
) -> list[CheckResult]:
    return sort_results([run_check(c, ctx) for c in tracked(checks, progress)])
