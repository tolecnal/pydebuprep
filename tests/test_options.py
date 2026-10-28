from __future__ import annotations

from typing import Any

import pytest

from pydebuprep import checks
from pydebuprep.checks.base import Check, Context, Option
from pydebuprep.model import Finding


class Tunable(Check):
    id = "tunable"
    title = "Tunable"
    category = "storage"
    options = (
        Option("include_remote", False, "Also check network filesystems"),
        Option("warning_pct", 25.0, "Warn below this free percentage"),
        Option("max_age_days", 7, "Maximum age in days"),
        Option("ignore", [], "Patterns to ignore"),
        Option("mode", "fast", "Mode"),
    )

    def run(self, ctx: Context) -> list[Finding]:
        return []

    def validate(self) -> None:
        if not 0 <= self.opt("warning_pct") <= 100:
            raise ValueError("warning_pct must be between 0 and 100")


def test_defaults() -> None:
    t = Tunable()
    assert t.opt("include_remote") is False
    assert t.opt("ignore") == []
    assert t.settings == {
        "include_remote": False,
        "warning_pct": 25.0,
        "max_age_days": 7,
        "ignore": [],
        "mode": "fast",
    }


def test_defaults_are_not_shared() -> None:
    a, b = Tunable(), Tunable()
    a.opt("ignore").append("x")
    assert b.opt("ignore") == []


@pytest.mark.parametrize(
    ("name", "value", "expected"),
    [
        ("include_remote", "yes", True),
        ("include_remote", "false", False),
        ("include_remote", True, True),
        ("warning_pct", "30", 30.0),
        ("warning_pct", 30, 30.0),
        ("max_age_days", "14", 14),
        ("ignore", "a, b,c", ["a", "b", "c"]),
        ("ignore", ["a", 1], ["a", "1"]),
        ("ignore", "", []),
        ("mode", "slow", "slow"),
    ],
)
def test_coercion(name: str, value: Any, expected: Any) -> None:
    assert Tunable({name: value}).opt(name) == expected


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        ({"nope": 1}, "tunable: unknown option 'nope'"),
        ({"include_remote": "maybe"}, "tunable.include_remote: expected true or false"),
        ({"max_age_days": "x"}, "tunable.max_age_days: expected an integer"),
        ({"max_age_days": True}, "tunable.max_age_days: expected an integer"),
        ({"warning_pct": "lots"}, "tunable.warning_pct: expected a number"),
        ({"ignore": {"a": 1}}, "tunable.ignore: expected a list"),
        ({"warning_pct": 150}, "tunable: warning_pct must be between 0 and 100"),
    ],
)
def test_invalid_settings(settings: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message.replace(".", r"\.")):
        Tunable(settings)


def test_enabled_is_not_an_option() -> None:
    with pytest.raises(ValueError, match="unknown option 'enabled'"):
        Tunable({"enabled": True})


def test_get_checks_passes_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checks, "ALL_CHECKS", [Tunable])
    (t,) = checks.get_checks(settings={"tunable": {"max_age_days": 3}})
    assert t.opt("max_age_days") == 3


def test_get_checks_rejects_settings_for_unknown_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checks, "ALL_CHECKS", [Tunable])
    with pytest.raises(ValueError, match="unknown check: other"):
        checks.get_checks(settings={"other": {}})


def test_parse_check_option() -> None:
    assert checks.parse_check_option("disk-space.include_remote=true") == (
        "disk-space",
        "include_remote",
        "true",
    )
    for bad in ("disk-space", "disk-space.x", "=1", "a.=1", ".b=1"):
        with pytest.raises(ValueError, match=r"expected CHECK\.OPTION=VALUE"):
            checks.parse_check_option(bad)


def test_every_registered_option_has_help_and_valid_default() -> None:
    for cls in checks.ALL_CHECKS:
        for option in cls.options:
            assert option.help, (cls.id, option.name)
        cls()  # defaults must validate


class Patterns(Check):
    id = "patterns"
    title = "Patterns"
    category = "services"
    options = (Option("ignore", [], "Regular expressions", split=False),)

    def run(self, ctx: Context) -> list[Finding]:
        return []


def test_unsplit_list_option_keeps_commas() -> None:
    assert Patterns({"ignore": "a{1,3}"}).opt("ignore") == ["a{1,3}"]
    assert Patterns({"ignore": "x, y"}).opt("ignore") == ["x, y"]
    assert Patterns({"ignore": ""}).opt("ignore") == []
    assert Patterns({"ignore": ["a,b", "c"]}).opt("ignore") == ["a,b", "c"]


@pytest.mark.parametrize("value", [[{"a": 1}], [["x"]], [None]])
def test_list_items_must_be_scalars(value: Any) -> None:
    with pytest.raises(ValueError, match=r"tunable\.ignore: expected a list of strings"):
        Tunable({"ignore": value})


def test_regex_options_do_not_split() -> None:
    from pydebuprep.checks.dmesg_errors import DmesgErrorsCheck
    from pydebuprep.checks.journal_errors import JournalErrorsCheck

    assert JournalErrorsCheck({"ignore": "Failed (a|b), retrying"}).opt("ignore") == [
        "Failed (a|b), retrying"
    ]
    assert DmesgErrorsCheck({"ignore": "x{1,2}"}).opt("ignore") == ["x{1,2}"]


@pytest.mark.parametrize("value", [0, -5])
def test_debsums_timeout_must_be_positive(value: int) -> None:
    from pydebuprep.checks.debsums import DebsumsCheck

    with pytest.raises(ValueError, match="debsums: timeout_seconds must be greater than 0"):
        DebsumsCheck({"timeout_seconds": value})


@pytest.mark.parametrize("value", [[True], [False, "x"]])
def test_list_items_reject_booleans(value: Any) -> None:
    """YAML turns yes/no/on/off into booleans; don't silently store "True"."""
    with pytest.raises(ValueError, match=r"tunable\.ignore: expected a list of strings"):
        Tunable({"ignore": value})
