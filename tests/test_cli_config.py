from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from fakes import FakeSystem
from pydebuprep import checks
from pydebuprep.checks.base import Check, Context, Option
from pydebuprep.cli import main
from pydebuprep.config import parse_config
from pydebuprep.model import Finding, Severity

OS_RELEASE = 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\nPRETTY_NAME="Debian 13"\n'


class Knob(Check):
    id = "knob"
    title = "Knob"
    category = "storage"
    options = (Option("level", "low", "How loud"), Option("limit", 5, "A limit"))
    runs = 0

    def run(self, ctx: Context) -> list[Finding]:
        Knob.runs += 1
        return [Finding(Severity.WARNING, f"level={self.opt('level')} limit={self.opt('limit')}")]


class Other(Check):
    id = "other"
    title = "Other"
    category = "packages"

    def run(self, ctx: Context) -> list[Finding]:
        return [Finding(Severity.INFO, "other ran")]

    def collect_baseline(self, ctx: Context) -> Any:
        return []


@pytest.fixture(autouse=True)
def _registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checks, "ALL_CHECKS", [Knob, Other])
    Knob.runs = 0


def run(args: list[str], **kw: Any) -> int:
    system = FakeSystem(
        files={"/etc/os-release": OS_RELEASE},
        commands={("uname", "-r"): "6.12.0-1-amd64\n"},
        **kw,
    )
    return main(args, system=system)


def conf(tmp_path: Path, text: str) -> str:
    path = tmp_path / "pydebuprep.conf"
    path.write_text(text)
    return str(path)


def test_config_sets_format(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    c = conf(tmp_path, "report:\n  format: json\n  baseline: none\n")
    run(["--config", c])
    assert json.loads(capsys.readouterr().out)["host"]["hostname"] == "testhost"


def test_default_config_path_from_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PYDEBUPREP_CONFIG", conf(tmp_path, "report:\n  format: yaml\n"))
    run(["--no-baseline"])
    assert yaml.safe_load(capsys.readouterr().out)["tool"]["name"] == "pydebuprep"


def test_no_config_ignores_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PYDEBUPREP_CONFIG", conf(tmp_path, "report:\n  format: [broken\n"))
    assert run(["--no-config", "--no-baseline"]) == 1
    assert "pydebuprep report" in capsys.readouterr().out


def test_cli_overrides_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    c = conf(tmp_path, "report:\n  format: json\n  min_severity: critical\n")
    run(["--config", c, "--format", "yaml", "--min-severity", "info", "--no-baseline"])
    data = yaml.safe_load(capsys.readouterr().out)
    assert any(r["findings"] for r in data["results"])


def test_config_disables_check(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    c = conf(tmp_path, "checks:\n  knob:\n    enabled: false\n")
    run(["--config", c, "--format", "json", "--no-baseline"])
    assert [r["id"] for r in json.loads(capsys.readouterr().out)["results"]] == ["other"]


def test_explicit_checks_override_disabled(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    c = conf(tmp_path, "checks:\n  knob:\n    enabled: false\n")
    run(["--config", c, "--checks", "knob", "--format", "json", "--no-baseline"])
    assert [r["id"] for r in json.loads(capsys.readouterr().out)["results"]] == ["knob"]


def test_check_options_config_then_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    c = conf(tmp_path, "checks:\n  knob:\n    level: high\n    limit: 9\n")
    run(["--config", c, "--check-option", "knob.limit=42", "--no-baseline"])
    assert "level=high limit=42" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("option", "message"),
    [
        ("knob.limit=lots", "knob.limit: expected an integer"),
        ("knob.nope=1", "knob: unknown option 'nope'"),
        ("ghost.x=1", "unknown check: ghost"),
        ("knob", "expected CHECK.OPTION=VALUE"),
    ],
)
def test_bad_check_option_exits_3(
    option: str, message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(["--check-option", option, "--no-baseline"]) == 3
    assert message in capsys.readouterr().err


def test_bad_config_exits_3_listing_all_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    c = conf(tmp_path, "report:\n  format: pdf\nchecks:\n  knob:\n    limit: x\n")
    assert run(["--config", c]) == 3
    err = capsys.readouterr().err
    assert "report.format: must be one of" in err
    assert "knob.limit: expected an integer" in err
    assert Knob.runs == 0


def test_config_output_dir_and_color(tmp_path: Path) -> None:
    out = tmp_path / "reports"
    out.mkdir()
    c = conf(tmp_path, f"report:\n  output_dir: {out}\n  format: markdown\n  baseline: none\n")
    run(["--config", c])
    (f,) = out.iterdir()
    assert f.name.endswith(".md")


def test_cli_output_overrides_config_output_dir(tmp_path: Path) -> None:
    c = conf(tmp_path, f"report:\n  output_dir: {tmp_path / 'missing'}\n")
    target = tmp_path / "r.txt"
    assert run(["--config", c, "--output", str(target), "--no-baseline"]) == 1
    assert target.exists()


def test_output_dir_checked_before_running_checks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(["--output-dir", str(tmp_path / "missing"), "--no-baseline"]) == 3
    assert "does not exist" in capsys.readouterr().err
    assert Knob.runs == 0


def test_output_file_dir_checked_before_running_checks(tmp_path: Path) -> None:
    assert run(["--output", str(tmp_path / "missing" / "r.txt"), "--no-baseline"]) == 3
    assert Knob.runs == 0


def test_config_baseline_path(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    snaps = tmp_path / "snaps"
    assert run(["snapshot", "--snapshot-dir", str(snaps)]) == 0
    snap = capsys.readouterr().out.strip()
    c = conf(tmp_path, f"report:\n  baseline: {snap}\n  format: json\n")
    run(["--config", c])
    assert json.loads(capsys.readouterr().out)["baseline"]["path"] == snap


def test_config_snapshot_dir_used_by_snapshot(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snaps = tmp_path / "from-config"
    c = conf(tmp_path, f"report:\n  snapshot_dir: {snaps}\n")
    assert run(["snapshot", "--config", c]) == 0
    assert capsys.readouterr().out.startswith(str(snaps))


def test_baseline_from_other_host_warns_even_when_os_release_skipped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snaps = tmp_path / "snaps"
    main(
        ["snapshot", "--snapshot-dir", str(snaps)],
        system=FakeSystem(
            files={"/etc/os-release": OS_RELEASE},
            commands={("uname", "-r"): "x\n"},
            hostname="elsewhere",
        ),
    )
    capsys.readouterr()
    run(["--snapshot-dir", str(snaps)])
    err = capsys.readouterr().err
    assert "pydebuprep: warning: baseline was taken on host elsewhere, not testhost" in err
    assert "pydebuprep: warning: baseline was taken on the current release" in err


def test_configtest_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    c = conf(tmp_path, "checks:\n  knob:\n    limit: 3\n")
    assert run(["configtest", "--config", c]) == 0
    out = capsys.readouterr().out
    assert f"Using {c}" in out
    assert "Syntax OK" in out


def test_configtest_without_default_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("PYDEBUPREP_CONFIG")
    monkeypatch.setattr("pydebuprep.cli.DEFAULT_CONFIG_PATH", "/nonexistent/pydebuprep.conf")
    assert run(["configtest"]) == 0
    out = capsys.readouterr().out
    assert "not found; built-in defaults apply" in out
    assert "Syntax OK" in out


def test_configtest_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    c = conf(tmp_path, "report:\n  colour: true\n")
    assert run(["configtest", "--config", c]) == 3
    captured = capsys.readouterr()
    assert "report: unknown key 'colour'" in captured.err
    assert "Syntax OK" not in captured.out


def test_configtest_explicit_missing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["configtest", "--config", str(tmp_path / "nope.conf")]) == 3
    assert "file not found" in capsys.readouterr().err


def test_example_config_round_trips(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["example-config"]) == 0
    text = capsys.readouterr().out
    cfg = parse_config(text, "example")
    assert cfg.check_settings == {"knob": {"level": "low", "limit": 5}}
    assert "# How loud" in text


def test_list_checks_verbose_shows_options(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["list-checks", "--verbose"]) == 0
    out = capsys.readouterr().out
    assert "level = low" in out
    assert "How loud" in out


class Lists(Check):
    id = "lists"
    title = "Lists"
    category = "services"
    options = (Option("ignore", [], "Regexes", split=False), Option("names", [], "Names"))

    def run(self, ctx: Context) -> list[Finding]:
        return [
            Finding(Severity.INFO, f"ignore={self.opt('ignore')!r} names={self.opt('names')!r}")
        ]


def test_repeated_check_option_appends_to_list_and_replaces_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(checks, "ALL_CHECKS", [Lists])
    c = conf(tmp_path, "checks:\n  lists:\n    ignore: [from-config]\n")
    run(
        [
            "--config",
            c,
            "--no-baseline",
            "--format",
            "json",
            "--check-option",
            "lists.ignore=a{1,3}",
            "--check-option",
            "lists.ignore=b, c",
            "--check-option",
            "lists.names=x,y",
        ]
    )
    data = json.loads(capsys.readouterr().out)
    assert data["results"][0]["findings"][0]["title"] == (
        "ignore=['a{1,3}', 'b, c'] names=['x', 'y']"
    )


def test_dash_output_means_stdout_even_with_config_output_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "reports"
    out.mkdir()
    c = conf(tmp_path, f"report:\n  output_dir: {out}\n")
    assert run(["--config", c, "-o", "-", "--no-baseline"]) == 1
    assert "pydebuprep report" in capsys.readouterr().out
    assert list(out.iterdir()) == []
    assert not (tmp_path / "-").exists()


def test_missing_env_config_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PYDEBUPREP_CONFIG", str(tmp_path / "typo.conf"))
    assert run(["--no-baseline"]) == 3
    assert "typo.conf: file not found" in capsys.readouterr().err
