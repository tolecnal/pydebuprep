"""The progress indicator: which check is running, on stderr, so the report stays clean."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from fakes import FakeSystem
from pydebuprep import checks
from pydebuprep.checks.base import Check, Context
from pydebuprep.cli import main
from pydebuprep.model import Finding
from pydebuprep.progress import Progress, choose, tracked

OS_RELEASE = 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n'


class First(Check):
    id = "first"
    title = "The first check"
    category = "packages"

    def run(self, ctx: Context) -> list[Finding]:
        return []


class Second(First):
    id = "second"
    title = "The second check"


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def lines_of(progress: Progress, stream: io.StringIO, n: int = 2) -> str:
    list(tracked([First(), Second()][:n], progress))
    return stream.getvalue()


def test_plain_progress_is_a_line_for_each_check() -> None:
    stream = io.StringIO()
    assert lines_of(Progress(stream, live=False), stream) == (
        "pydebuprep: [1/2] first: The first check\npydebuprep: [2/2] second: The second check\n"
    )


def test_live_progress_rewrites_one_line_and_clears_it() -> None:
    stream = io.StringIO()
    out = lines_of(Progress(stream, live=True, columns=80), stream)
    assert out == (
        "\r[1/2] [----------] first: The first check\x1b[K"
        "\r[2/2] [#####-----] second: The second check\x1b[K"
        "\r\x1b[K"
    )
    assert "\n" not in out


def test_live_progress_counts_are_aligned() -> None:
    stream = io.StringIO()
    progress = Progress(stream, live=True, columns=80)
    progress.start(4, 49, First())
    assert stream.getvalue().startswith("\r[ 4/49] [")


def test_live_progress_fits_the_terminal() -> None:
    stream = io.StringIO()
    Progress(stream, live=True, columns=30).start(1, 2, First())
    shown = stream.getvalue().removeprefix("\r").removesuffix("\x1b[K")
    assert len(shown) == 29 and shown.endswith("…")


def test_the_line_is_cleared_when_a_run_is_interrupted() -> None:
    stream = io.StringIO()
    steps = tracked([First(), Second()], Progress(stream, live=True, columns=80))
    next(steps)
    steps.close()
    assert stream.getvalue().endswith("\r\x1b[K")


def test_no_progress_means_nothing_is_written() -> None:
    assert [c.id for c in tracked([First(), Second()], None)] == ["first", "second"]


def test_a_stream_that_went_away_does_not_stop_the_run() -> None:
    class Gone(io.StringIO):
        def write(self, text: str) -> int:
            raise BrokenPipeError

    assert [c.id for c in tracked([First()], Progress(Gone(), live=False))] == ["first"]


def test_progress_is_chosen_by_flag_then_by_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM", "xterm")
    assert choose(None, io.StringIO()) is None
    assert choose(False, Terminal()) is None
    live = choose(None, Terminal())
    assert live is not None and live.live
    forced = choose(True, io.StringIO())
    assert forced is not None and not forced.live
    forced_live = choose(True, Terminal())
    assert forced_live is not None and forced_live.live


def test_a_dumb_terminal_gets_no_live_line(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM", "dumb")
    assert choose(None, Terminal()) is None
    plain = choose(True, Terminal())
    assert plain is not None and not plain.live


@pytest.fixture
def _two_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checks, "ALL_CHECKS", [First, Second])


def run(args: list[str]) -> int:
    system = FakeSystem(
        files={"/etc/os-release": OS_RELEASE}, commands={("uname", "-r"): "6.12.0\n"}
    )
    return main(args, system=system)


@pytest.mark.usefixtures("_two_checks")
def test_report_shows_progress_on_stderr_and_a_clean_report_on_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    run(["report", "--no-baseline", "--format", "json", "--progress"])
    captured = capsys.readouterr()
    assert json.loads(captured.out)["summary"]["ok"] == 2
    assert captured.err == (
        "pydebuprep: [1/2] first: The first check\npydebuprep: [2/2] second: The second check\n"
    )


@pytest.mark.usefixtures("_two_checks")
def test_report_is_quiet_in_scripts_and_with_no_progress(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    run(["report", "--no-baseline"])
    assert capsys.readouterr().err == ""
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    monkeypatch.setenv("TERM", "xterm")
    run(["report", "--no-baseline", "--no-progress"])
    assert capsys.readouterr().err == ""
    run(["report", "--no-baseline"])
    assert "[1/2]" in capsys.readouterr().err


@pytest.mark.usefixtures("_two_checks")
def test_progress_flags_exclude_each_other(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["report", "--progress", "--no-progress"]) == 3
    assert "not allowed with argument --progress" in capsys.readouterr().err


@pytest.mark.usefixtures("_two_checks")
def test_snapshot_shows_progress_while_it_records_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(["snapshot", "--snapshot-dir", str(tmp_path), "--progress"])
    assert "pydebuprep: [2/2] second: The second check\n" in capsys.readouterr().err
    run(["snapshot", "--snapshot-dir", str(tmp_path), "--progress", "--no-findings"])
    assert "[1/2]" not in capsys.readouterr().err


def test_the_width_is_that_of_the_terminal_progress_is_written_to(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Not stdout's: that is often a file or a pipe while stderr is the terminal."""
    import os

    class Stderr(Terminal):
        def fileno(self) -> int:
            return 7

    asked = []

    def size(fd: int) -> os.terminal_size:
        asked.append(fd)
        return os.terminal_size((30, 24))

    monkeypatch.setattr("pydebuprep.progress.os.get_terminal_size", size)
    stream = Stderr()
    Progress(stream, live=True).start(1, 2, First())
    assert asked == [7]
    assert len(stream.getvalue().removeprefix("\r").removesuffix("\x1b[K")) == 29


def test_an_unknown_width_is_taken_as_80() -> None:
    stream = io.StringIO()  # has no file descriptor
    Progress(stream, live=True).start(1, 1, First())
    long_title = type("Long", (First,), {"title": "x" * 200})()
    Progress(stream, live=True).start(1, 1, long_title)
    assert len(stream.getvalue().split("\r")[-1].removesuffix("\x1b[K")) == 79
