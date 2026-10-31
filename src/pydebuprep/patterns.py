"""Limits on the regular expressions a config may give.

They are matched, as root, against every journal and kernel message, and a config may
come from a portal, so a pattern must not be able to pin a CPU: at most MAX_PATTERNS of
them, each at most MAX_PATTERN_LENGTH long, and none with a repeated part that itself
repeats without bound ("(a+)+", "(\\w+\\s?)*"), the shape behind catastrophic backtracking.
"""

from __future__ import annotations

import importlib
import re
import sys
from collections.abc import Iterator
from typing import Any

MAX_PATTERNS = 100
MAX_PATTERN_LENGTH = 200

# The parser behind re.compile: re._parser since Python 3.11, sre_parse before.
_parser: Any = importlib.import_module("re._parser" if sys.version_info >= (3, 11) else "sre_parse")
_REPEATS = {_parser.MAX_REPEAT, _parser.MIN_REPEAT} | (
    {_parser.POSSESSIVE_REPEAT} if hasattr(_parser, "POSSESSIVE_REPEAT") else set()
)
_UNBOUNDED = _parser.MAXREPEAT


def _subpatterns(value: Any) -> Iterator[Any]:
    """The parsed subpatterns inside an opcode's argument, however it is nested."""
    if isinstance(value, _parser.SubPattern):
        yield value
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _subpatterns(item)


def _repeats(pattern: Any) -> Iterator[tuple[int, Any]]:
    """(maximum, body) of every repeat in a parsed pattern, outermost first."""
    for op, av in pattern:
        if op in _REPEATS:
            _, maximum, body = av
            yield maximum, body
        for sub in _subpatterns(av):
            yield from _repeats(sub)


def _nested(pattern: Any) -> bool:
    for outer, body in _repeats(pattern):
        for inner, _ in _repeats(body):
            if (outer > 1 and inner == _UNBOUNDED) or (outer == _UNBOUNDED and inner > 1):
                return True
    return False


def pattern_problem(pattern: str) -> str | None:
    """Why PATTERN may not be used, or None."""
    if len(pattern) > MAX_PATTERN_LENGTH:
        return f"pattern {pattern[:40]!r}… is longer than {MAX_PATTERN_LENGTH} characters"
    try:
        re.compile(pattern)
        parsed = _parser.parse(pattern)
    except re.error as exc:  # a pattern this short can't nest deep enough to recurse out
        return f"invalid pattern {pattern!r}: {exc}"
    if _nested(parsed):
        return (
            f"pattern {pattern!r} repeats a part that itself repeats (nested quantifiers "
            "can take exponential time); write it without the nesting"
        )
    return None


def patterns_problems(patterns: list[str]) -> list[str]:
    """Every reason PATTERNS may not be used."""
    if len(patterns) > MAX_PATTERNS:
        return [f"at most {MAX_PATTERNS} patterns, not {len(patterns)}"]
    return [p for p in map(pattern_problem, patterns) if p is not None]
