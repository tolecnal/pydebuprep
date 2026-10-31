"""Limits on the regular expressions a config may give: they run as root over every
journal and kernel message, so one pattern must not be able to pin a CPU."""

from __future__ import annotations

import pytest

from pydebuprep.checks.dmesg_errors import DmesgErrorsCheck
from pydebuprep.checks.journal_errors import JournalErrorsCheck
from pydebuprep.config import ConfigError, parse_config
from pydebuprep.patterns import MAX_PATTERN_LENGTH, MAX_PATTERNS, pattern_problem


@pytest.mark.parametrize(
    "pattern",
    [
        "^systemd-logind: ",
        r"ACPI Error: AE_NOT_FOUND",
        r"(foo|bar)+ baz",
        r"\d+ ms",
        r"(ab){2,5}",
        r"a*b*c*",
        r"(?:x\d)+",
    ],
)
def test_ordinary_patterns_pass(pattern: str) -> None:
    assert pattern_problem(pattern) is None


@pytest.mark.parametrize(
    "pattern",
    ["(a+)+$", "(a*)*", "(?:a+)*b", "(x+x+)+y", r"(\w+\s?)*$", "((ab)*c)+"],
)
def test_nested_unbounded_repeats_are_refused(pattern: str) -> None:
    problem = pattern_problem(pattern)
    assert problem is not None and "nested" in problem


def test_long_and_invalid_and_deep_patterns() -> None:
    assert "longer than" in (pattern_problem("a" * (MAX_PATTERN_LENGTH + 1)) or "")
    assert pattern_problem("(") is not None
    assert pattern_problem("(" * 150 + ")" * 150) is not None  # deep, not a crash


@pytest.mark.parametrize("check", [JournalErrorsCheck, DmesgErrorsCheck])
def test_check_options_use_the_limits(check: type) -> None:
    with pytest.raises(ValueError, match="nested"):
        check({"ignore": ["(a+)+$"]})
    with pytest.raises(ValueError, match="at most"):
        check({"ignore": ["x"] * (MAX_PATTERNS + 1)})
    assert check({"ignore": ["^ok"]})


def test_logs_ignore_uses_the_limits() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_config("logs:\n  ignore: ['(a+)+$']\n", "c")
    assert "nested" in str(exc.value)
    many = "logs:\n  ignore: [" + ", ".join(f"'x{i}'" for i in range(MAX_PATTERNS + 1)) + "]\n"
    with pytest.raises(ConfigError, match="at most"):
        parse_config(many, "c")


def test_an_optional_part_inside_a_repeat_is_fine() -> None:
    assert pattern_problem(r"(?:a?b)+") is None
