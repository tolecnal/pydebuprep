from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fakes import FROZEN_NOW, FakeSystem
from pydebuprep import __version__, checks, cli
from pydebuprep.checks.base import Check, Context
from pydebuprep.cli import main, resolve_output_path
from pydebuprep.model import Finding, Severity

OS_RELEASE = 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\nPRETTY_NAME="Debian 13"\n'


class Warn(Check):
    id = "warn-check"
    title = "Warn check"
    category = "packages"

    def run(self, ctx: Context) -> list[Finding]:
        return [
            Finding(Severity.WARNING, "a warning", remediation=["fix it"]),
            Finding(Severity.INFO, "an info note"),
        ]

    def collect_baseline(self, ctx: Context) -> Any:
        return {"seen": True}

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        return [Finding(Severity.INFO, "compared with baseline")]


class RootCrit(Check):
    id = "root-crit"
    title = "Root critical"
    category = "boot"
    requires_root = True

    def run(self, ctx: Context) -> list[Finding]:
        return [Finding(Severity.CRITICAL, "critical thing")]


@pytest.fixture(autouse=True)
def _registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checks, "ALL_CHECKS", [Warn, RootCrit])


def fake(**kw: Any) -> FakeSystem:
    return FakeSystem(
        files={"/etc/os-release": OS_RELEASE},
        commands={("uname", "-r"): "6.12.0-1-amd64\n"},
        **kw,
    )


def run(args: list[str], **kw: Any) -> int:
    return main(args, system=fake(**kw))


def test_default_is_text_report_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    rc = run(["--no-baseline"])
    out = capsys.readouterr().out
    assert "pydebuprep report" in out
    assert "critical thing" in out
    assert rc == 2


def test_json_format_parses(capsys: pytest.CaptureFixture[str]) -> None:
    rc = run(["report", "--format", "json", "--no-baseline"])
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["exit_code"] == rc == 2
    assert data["host"]["kernel"] == "6.12.0-1-amd64"
    assert data["host"]["codename"] == "trixie"


def test_output_dir_writes_timestamped_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(["report", "--format", "markdown", "--output-dir", str(tmp_path), "--no-baseline"])
    f = tmp_path / "pydebuprep-testhost-20261028T120000Z.md"
    assert f.exists()
    assert f.read_text().startswith("# pydebuprep report")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(f) in captured.err


def test_resolve_output_path(tmp_path: Path) -> None:
    assert resolve_output_path(None, None, "h", "json", FROZEN_NOW) is None
    p = resolve_output_path(None, str(tmp_path), "h", "yaml", FROZEN_NOW)
    assert p == tmp_path / "pydebuprep-h-20261028T120000Z.yaml"
    new = tmp_path / "r.json"
    assert resolve_output_path(str(new), None, "h", "json", FROZEN_NOW) == new
    new.write_text("old")
    assert resolve_output_path(str(new), None, "h", "json", FROZEN_NOW) == (
        tmp_path / "r-20261028T120000Z.json"
    )


def test_output_file_existing_gets_timestamp(tmp_path: Path) -> None:
    existing = tmp_path / "report.txt"
    existing.write_text("old")
    run(["--output", str(existing), "--no-baseline"])
    assert existing.read_text() == "old"
    assert (tmp_path / "report-20261028T120000Z.txt").exists()


def test_unwritable_output_dir_exits_3(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["--output-dir", str(tmp_path / "missing"), "--no-baseline"]) == 3
    assert "pydebuprep: error:" in capsys.readouterr().err


def test_unknown_check_exits_3(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["--checks", "nope", "--no-baseline"]) == 3
    assert "unknown check: nope" in capsys.readouterr().err


def test_bad_baseline_exits_3(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{")
    assert run(["--baseline", str(bad)]) == 3
    assert "not valid JSON" in capsys.readouterr().err


def test_bad_argument_exits_3(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["--format", "pdf"]) == 3
    assert run(["--baseline", "x", "--no-baseline"]) == 3


def test_report_as_non_root_exits_cleanly(capsys: pytest.CaptureFixture[str]) -> None:
    rc = run(["--no-baseline"], root=False)
    out = capsys.readouterr().out
    assert "requires root" in out
    assert "Traceback" not in out
    assert rc == 1


def test_min_severity_filters_display_not_exit_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = run(["--min-severity", "warning", "--no-baseline"], root=False)
    out = capsys.readouterr().out
    assert "an info note" not in out
    assert "a warning" in out
    assert rc == 1


def test_auto_baseline_used(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["snapshot", "--snapshot-dir", str(tmp_path)]) == 0
    assert "20261028T120000Z.json" in capsys.readouterr().out
    run(["--format", "json", "--snapshot-dir", str(tmp_path)])
    data = json.loads(capsys.readouterr().out)
    assert data["baseline"]["path"].endswith("20261028T120000Z.json")
    warn = next(r for r in data["results"] if r["id"] == "warn-check")
    assert warn["baseline_diff"][0]["title"] == "compared with baseline"


def test_no_baseline_flag(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    run(["snapshot", "--snapshot-dir", str(tmp_path)])
    capsys.readouterr()
    run(["--format", "json", "--snapshot-dir", str(tmp_path), "--no-baseline"])
    assert json.loads(capsys.readouterr().out)["baseline"] is None


def test_snapshot_error_exits_3(tmp_path: Path) -> None:
    blocker = tmp_path / "f"
    blocker.write_text("")
    assert run(["snapshot", "--snapshot-dir", str(blocker / "x")]) == 3


def test_list_checks_prints_ids(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["list-checks"]) == 0
    out = capsys.readouterr().out
    assert "warn-check" in out
    assert "root-crit" in out


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["--version"]) == 0
    assert f"pydebuprep {__version__}" in capsys.readouterr().out


def test_color_only_on_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_stdout_is_tty", lambda: True)
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert cli.use_color(no_color_flag=False)
    assert not cli.use_color(no_color_flag=True)
    monkeypatch.setenv("NO_COLOR", "1")
    assert not cli.use_color(no_color_flag=False)
