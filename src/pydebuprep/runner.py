"""Runs checks in isolation so one failing check never breaks the report."""

from __future__ import annotations

from collections.abc import Sequence

from pydebuprep.checks.base import Check, CheckSkipped, Context
from pydebuprep.model import CheckResult, Finding, Status, sort_findings, sort_results


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def run_check(check: Check, ctx: Context) -> CheckResult:
    result = CheckResult(check.id, check.title, check.category, Status.OK)
    reason = check.unmet_requirement(ctx)
    if reason is not None:
        result.status = Status.SKIPPED
        result.skipped_reason = reason
        return result
    try:
        result.findings = sort_findings(check.run(ctx))
        diff: list[Finding] | None = None
        if ctx.baseline is not None and check.supports_baseline:
            before = ctx.baseline_for(check.id)
            if before is not None:
                diff = sort_findings(check.compare(ctx, before))
        result.baseline_diff = diff
    except CheckSkipped as exc:
        result.status = Status.SKIPPED
        result.skipped_reason = str(exc)
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


def run_checks(checks: Sequence[Check], ctx: Context) -> list[CheckResult]:
    return sort_results([run_check(c, ctx) for c in checks])
