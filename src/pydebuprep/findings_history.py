"""Telling a report's findings from the ones a snapshot recorded: is this new, or was it
already there before the upgrade?

A finding's text changes without it being a different finding: "1 package is held back" and
"3 packages are held back" are the same condition, and so are "9x sshd: ..." and "5x sshd:
...". So numbers count for nothing, nor does the wording that follows them in a title, and
what's compared is what's left. New evidence under the same title makes a finding worse.
"""

from __future__ import annotations

import re
from typing import Any

from pydebuprep.model import ALREADY, NEW, WORSE, Finding, Severity

__all__ = ["ALREADY", "NEW", "WORSE", "classify", "fingerprint"]

# A number standing alone, or a count such as "9x": not the 1 in "foo1", part of a name.
NUMBER = re.compile(r"\b\d+(?:[.:]\d+)*(?:x\b|\b)")
COUNT_START = "# "
# A title starting with a count changes its wording with the number.
AGREEING_WORDS = frozenset(
    {"is", "are", "was", "were", "has", "have", "do", "does"}
    | {"isn't", "aren't", "wasn't", "weren't", "doesn't", "don't"}
)
STEM_LENGTH = 4


def _without_numbers(text: str) -> str:
    return NUMBER.sub("#", text)


def _title_key(title: str) -> str:
    text = _without_numbers(title)
    if not text.startswith(COUNT_START):
        return text
    words = text.split()[1:]
    return " ".join(["#", *(w[:STEM_LENGTH] for w in words if w not in AGREEING_WORDS)])


def fingerprint(finding: Finding) -> dict[str, Any]:
    """What a snapshot records of a finding."""
    return {
        "title": _title_key(finding.title),
        "evidence": sorted({_without_numbers(line) for line in finding.evidence}),
        "severity": finding.severity.value,
    }


def _rank(record: dict[str, Any]) -> int | None:
    try:
        return Severity(record.get("severity")).rank
    except ValueError:
        return None


def classify(finding: Finding, before: list[dict[str, Any]]) -> str:
    """How FINDING compares with what a check found at the snapshot. Snapshots may come from
    elsewhere, so a record that makes no sense counts for nothing."""
    now = fingerprint(finding)
    record = next(
        (r for r in before if isinstance(r, dict) and r.get("title") == now["title"]), None
    )
    if record is None:
        return NEW
    evidence = record.get("evidence")
    known = set(evidence) if isinstance(evidence, list) else set()
    rank = _rank(record)
    if set(now["evidence"]) - known or (rank is not None and finding.severity.rank > rank):
        return WORSE
    return ALREADY
