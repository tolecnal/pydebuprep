"""Secrets in what a report quotes from logs and crontabs stay out of it."""

from __future__ import annotations

import pytest

from pydebuprep.checks.base import Check, Context
from pydebuprep.model import Finding, Severity
from pydebuprep.redact import REDACTED, redact
from pydebuprep.runner import run_check

from .helpers import make_ctx


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("backup: password=hunter2 failed", "hunter2"),
        ("DB_PASSWORD: hunter2", "hunter2"),
        ('{"api_key": "hunter2"}', "hunter2"),
        ("curl 'https://x/y?token=hunter2&a=1'", "hunter2"),
        ("tool --password hunter2 --verbose", "hunter2"),
        ("tool --auth-token=hunter2", "hunter2"),
        ("mysqldump -uroot -phunter2 db", "hunter2"),
        ("/usr/bin/mariadb -phunter2", "hunter2"),
        ("rsync postgres://app:hunter2@db/app", "hunter2"),
        ("Authorization: Bearer hunter2", "hunter2"),
        ("sent header bearer hunter2", "hunter2"),
        ("uploaded with pdp_0123abcd_" + "a" * 43, "pdp_0123abcd"),
    ],
)
def test_secrets_are_redacted(text: str, secret: str) -> None:
    out = redact(text)
    assert secret not in out
    assert REDACTED in out


@pytest.mark.parametrize(
    "text",
    [
        "password authentication failed for user bob",
        "sudo apt install php8.2-mysql",
        "tool -P 3306 -v",
        "ls -p /tmp",
        "https://deb.debian.org/debian",
        "ssh.service: Failed with result 'exit-code'.",
    ],
)
def test_ordinary_text_is_left_alone(text: str) -> None:
    assert redact(text) == text


class Quoting(Check):
    id = "quoting"
    title = "Quoting"
    category = "services"
    secret = "password=hunter2"

    def run(self, ctx: Context) -> list[Finding]:
        return [
            Finding(
                Severity.WARNING,
                f"Failed: {self.secret}",
                detail=self.secret,
                evidence=[self.secret],
                remediation=[self.secret],
                references=["https://example.com/token=abc"],
            )
        ]

    def collect_baseline(self, ctx: Context) -> str:
        return "x"

    def compare(self, ctx: Context, before: str) -> list[Finding]:
        return self.run(ctx)


def test_a_report_never_holds_what_was_redacted() -> None:
    ctx = make_ctx()
    ctx.baseline = {"checks": {"quoting": "before"}}
    result = run_check(Quoting(), ctx)
    for finding in [*result.findings, *(result.baseline_diff or [])]:
        assert "hunter2" not in " ".join(
            [finding.title, finding.detail, *finding.evidence, *finding.remediation]
        )
        assert finding.references == ["https://example.com/token=abc"]


def test_an_error_message_is_redacted_too() -> None:
    class Failing(Quoting):
        def run(self, ctx: Context) -> list[Finding]:
            raise RuntimeError("could not connect: password=hunter2")

    result = run_check(Failing(), make_ctx())
    assert "hunter2" not in (result.error or "")


def test_a_skip_reason_is_redacted_too() -> None:
    from pydebuprep.checks.base import CheckSkipped

    class Skipping(Quoting):
        def run(self, ctx: Context) -> list[Finding]:
            raise CheckSkipped("password=hunter2")

    assert "hunter2" not in (run_check(Skipping(), make_ctx()).skipped_reason or "")


# --- redaction can't be made slow -------------------------------------------------------

LONG = 1_000_000


@pytest.mark.parametrize(
    "text",
    [
        "a" * LONG,
        "-" * LONG,
        "--" + "a-" * (LONG // 2),
        "mysql " * (LONG // 6),
        "://" + "a" * LONG,
        "password " * (LONG // 9),
        "token" * (LONG // 5),
    ],
    ids=["word", "dashes", "dashed words", "mysql", "url", "password words", "token run"],
)
def test_a_long_line_is_redacted_quickly(text: str) -> None:
    """A user's crontab line reaches this as root: it must not take minutes."""
    import time

    started = time.monotonic()
    out = redact(text)
    assert time.monotonic() - started < 5
    assert len(out) < 5000 and out.endswith("characters left out)")


def test_a_long_line_keeps_its_start_and_loses_its_tail() -> None:
    from pydebuprep.redact import MAX_LINE

    out = redact("job: password=hunter2 " + "x" * MAX_LINE + " token=tail-secret")
    assert out.startswith(f"job: password={REDACTED} xxx")
    assert "tail-secret" not in out


def test_a_line_at_the_limit_is_left_whole() -> None:
    from pydebuprep.redact import MAX_LINE

    assert redact("x" * MAX_LINE) == "x" * MAX_LINE


def test_words_that_only_contain_a_secret_word_still_count() -> None:
    assert redact("MY_DB_PASSWORD=hunter2") == f"MY_DB_PASSWORD={REDACTED}"
    assert redact("x --db-password hunter2") == f"x --db-password {REDACTED}"
