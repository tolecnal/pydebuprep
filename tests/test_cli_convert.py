"""`pydebuprep convert`: render a saved JSON or YAML report in another format."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from conftest import make_sample_report
from pydebuprep.cli import main
from pydebuprep.render import render


@pytest.fixture
def saved(tmp_path: Path) -> Path:
    path = tmp_path / "report.json"
    path.write_text(render(make_sample_report(), "json"), encoding="utf-8")
    return path


def test_convert_to_stdout_defaults_to_text(
    saved: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["convert", str(saved)]) == 0
    assert capsys.readouterr().out == render(make_sample_report(), "text")


@pytest.mark.parametrize("fmt", ["markdown", "jira", "html", "yaml"])
def test_convert_to_each_format(fmt: str, saved: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["convert", str(saved), "--format", fmt]) == 0
    assert capsys.readouterr().out == render(make_sample_report(), fmt)


def test_convert_exit_code_is_not_the_reports(saved: Path) -> None:
    # The sample report has a critical finding (report exit code 2); converting succeeded.
    assert make_sample_report().summary.exit_code == 2
    assert main(["convert", str(saved), "-f", "markdown"]) == 0


def test_convert_from_stdin(
    saved: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(saved.read_text(encoding="utf-8")))
    assert main(["convert", "-", "-f", "jira"]) == 0
    assert capsys.readouterr().out == render(make_sample_report(), "jira")


def test_convert_to_file(saved: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "report.md"
    assert main(["convert", str(saved), "-f", "markdown", "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == render(make_sample_report(), "markdown")
    assert f"Report written to {out}" in capsys.readouterr().err


def test_convert_to_output_dir_uses_the_reports_host_and_time(saved: Path, tmp_path: Path) -> None:
    outdir = tmp_path / "out"
    outdir.mkdir()
    assert main(["convert", str(saved), "-f", "html", "--output-dir", str(outdir)]) == 0
    # make_sample_report: host testhost, generated 2026-10-28T12:00:00+00:00
    assert [p.name for p in outdir.iterdir()] == ["pydebuprep-testhost-20261028T120000Z.html"]


def test_convert_never_overwrites(saved: Path, tmp_path: Path) -> None:
    out = tmp_path / "report.txt"
    out.write_text("keep me", encoding="utf-8")
    assert main(["convert", str(saved), "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == "keep me"
    assert (tmp_path / "report-20261028T120000Z.txt").exists()


def test_convert_text_report_is_refused(
    saved: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = tmp_path / "report.txt"
    text.write_text(render(make_sample_report(), "text"), encoding="utf-8")
    assert main(["convert", str(text), "-f", "markdown"]) == 3
    assert "JSON or YAML" in capsys.readouterr().err


def test_convert_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["convert", str(tmp_path / "nope.json")]) == 3
    assert "cannot read" in capsys.readouterr().err


def test_convert_malformed_report_names_the_field(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(
        render(make_sample_report(), "json").replace(
            '"severity": "critical"', '"severity": "urgent"', 1
        ),
        encoding="utf-8",
    )
    assert main(["convert", str(bad)]) == 3
    assert f"pydebuprep: error: {bad}: results[0].findings[0].severity" in capsys.readouterr().err


def test_convert_unreadable_bytes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"\xff\xfe\x00garbage")
    assert main(["convert", str(bad)]) == 3
    assert "pydebuprep: error:" in capsys.readouterr().err


def test_convert_no_color_and_color(
    saved: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("pydebuprep.cli.use_color", lambda no_color, configured=True: not no_color)
    assert main(["convert", str(saved)]) == 0
    assert "\x1b[" in capsys.readouterr().out
    assert main(["convert", str(saved), "--no-color"]) == 0
    assert "\x1b[" not in capsys.readouterr().out


def test_convert_hostname_cannot_escape_the_output_dir(tmp_path: Path) -> None:
    report = make_sample_report()
    report.host.hostname = "../../evil/name"
    saved = tmp_path / "r.json"
    saved.write_text(render(report, "json"), encoding="utf-8")
    outdir = tmp_path / "out"
    outdir.mkdir()
    assert main(["convert", str(saved), "--output-dir", str(outdir)]) == 0
    (written,) = outdir.iterdir()
    assert written.name == "pydebuprep-.._.._evil_name-20261028T120000Z.txt"
