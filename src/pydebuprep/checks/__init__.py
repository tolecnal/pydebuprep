"""Registry of all checks, in no particular order (reports sort them)."""

from __future__ import annotations

from collections.abc import Sequence

from pydebuprep.checks.base import Check

ALL_CHECKS: list[type[Check]] = []


def get_checks(only: Sequence[str] | None = None, skip: Sequence[str] = ()) -> list[Check]:
    known = {cls.id: cls for cls in ALL_CHECKS}
    for check_id in [*(only or []), *skip]:
        if check_id not in known:
            raise ValueError(f"unknown check: {check_id}")
    selected = [known[i] for i in only] if only else list(ALL_CHECKS)
    return [cls() for cls in selected if cls.id not in skip]
