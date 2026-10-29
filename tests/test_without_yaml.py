"""PyYAML is a package dependency, but the tool shouldn't crash without it: it runs
when YAML isn't needed and says how to install it when it is."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import pydebuprep
from fakes import FakeSystem
from pydebuprep.cli import main

OS_RELEASE = 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n'
HINT = "python3-yaml is not installed; install it with: sudo apt install python3-yaml"


@pytest.fixture(autouse=True)
def _no_yaml(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "yaml", None)  # makes "import yaml" raise ImportError


def run(args: list[str]) -> int:
    system = FakeSystem(
        files={"/etc/os-release": OS_RELEASE},
        commands={("uname", "-r"): "6.12.0-1-amd64\n"},
        strict=False,
    )
    return main(args, system=system)


@pytest.mark.parametrize("fmt", ["text", "json", "html", "markdown", "jira", "confluence"])
def test_report_works_without_yaml(
    fmt: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("PYDEBUPREP_CONFIG")
    monkeypatch.setattr("pydebuprep.cli.DEFAULT_CONFIG_PATH", "/nonexistent/pydebuprep.conf")
    assert run(["--no-baseline", "--format", fmt]) in (0, 1, 2)
    assert "pydebuprep" in capsys.readouterr().out


def test_example_config_works_without_yaml(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["example-config"]) == 0
    assert "checks:" in capsys.readouterr().out


@pytest.mark.parametrize(
    "args",
    [
        ["--no-baseline", "--format", "yaml", "--no-config"],
        ["--no-baseline"],  # the config file (from $PYDEBUPREP_CONFIG) needs YAML
        ["configtest"],
    ],
)
def test_clear_hint_when_yaml_is_needed(
    args: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(args) == 3
    err = capsys.readouterr().err
    assert HINT in err
    assert "Traceback" not in err


def test_modules_import_without_yaml(tmp_path: Path) -> None:
    src = Path(pydebuprep.__file__).parent.parent
    code = (
        "import sys; sys.modules['yaml'] = None; "
        "import pydebuprep.cli, pydebuprep.config, pydebuprep.render, pydebuprep.completion"
    )
    res: Any = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(src)},
        check=False,
    )
    assert res.returncode == 0, res.stderr
