"""pydebuprep-cleanup: dry run by default, and every guardrail on the way to acting."""

from __future__ import annotations

import json
import syslog
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from cleanup.test_plan import PACKAGES, owner_query, system
from fakes import FakeRunner
from pydebuprep.cleanup import cli
from pydebuprep.cleanup import runner as runner_module
from pydebuprep.cleanup.log import Log
from pydebuprep.cleanup.runner import APT_PURGE, APT_SIMULATE, DPKG_AUDIT
from pydebuprep.system import CONFFILES_HEAD

NOW = datetime(2026, 11, 3, 15, 4, 5, tzinfo=timezone.utc)
SIMULATED = "Purg hello [2.10-3]\nPurg cowsay [3.03]\n"


@pytest.fixture(autouse=True)
def quiet_syslog(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(syslog, "openlog", lambda *a, **k: None)
    monkeypatch.setattr(syslog, "closelog", lambda: None)
    monkeypatch.setattr(syslog, "syslog", lambda *a: None)
    monkeypatch.setattr(runner_module, "LOCK_PATH", str(tmp_path / "cleanup.lock"))
    monkeypatch.setattr(runner_module, "DPKG_LOCK", str(tmp_path / "lock-frontend"))
    monkeypatch.setattr(cli, "BACKUP_DIR", str(tmp_path))


def run(tmp_path: Path, argv: list[str], **kw: Any) -> tuple[int, FakeRunner]:
    fake = kw.pop("runner", FakeRunner({(*APT_SIMULATE, "cowsay", "hello"): SIMULATED}))
    sys_ = kw.pop("system", None) or system(commands={(*CONFFILES_HEAD, "cowsay", "hello"): ""})
    log = Log(str(tmp_path / "cleanup.log"), run_id="t")
    code = cli.main(["--no-config", *argv], system=sys_, runner=fake, log=log, now=NOW, **kw)
    return code, fake


def test_dry_run_is_the_default_and_changes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, fake = run(tmp_path, ["--all"])
    out = capsys.readouterr().out
    assert code == 0 and fake.calls == []
    assert "Dry run: nothing changed. Run again with --apply to do this." in out
    assert "linux-image-6.8.0-40-generic" in out and "hello" in out
    assert "Kernels kept: 6.8.0-45, 6.8.0-49" in out
    assert "linux-image-6.8.0-40-generic" in (tmp_path / "cleanup.log").read_text()


def test_apply_needs_yes_without_a_tty(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, fake = run(tmp_path, ["--residual", "--apply"], interactive=False)
    assert code == 1 and not [c for c in fake.calls if c[:3] == APT_PURGE]
    assert "--yes" in capsys.readouterr().err


def test_apply_asks_at_a_terminal(tmp_path: Path) -> None:
    code, fake = run(tmp_path, ["--residual", "--apply"], interactive=True, ask=lambda prompt: "n")
    assert code == 1 and not [c for c in fake.calls if c[:3] == APT_PURGE]
    asked: list[str] = []
    code, fake = run(tmp_path, ["--residual", "--apply"], interactive=True,
                     ask=lambda prompt: asked.append(prompt) or "y")  # fmt: skip
    assert code == 0 and (*APT_PURGE, "cowsay", "hello") in fake.calls
    assert asked == ["Purge 2 packages and remove 0 directories? [y/N] "]


def test_apply_flow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, fake = run(tmp_path, ["--residual", "--apply", "--yes"])
    assert code == 0
    simulated = (*APT_SIMULATE, "cowsay", "hello")
    assert fake.calls == [DPKG_AUDIT, simulated, simulated, (*APT_PURGE, "cowsay", "hello")]
    assert "Record the result: sudo pydebuprep report" in capsys.readouterr().out


def test_widened_simulation_refuses(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    widened = FakeRunner({(*APT_SIMULATE, "cowsay", "hello"): SIMULATED + "Remv cowsay-off [1]\n"})
    code, fake = run(tmp_path, ["--residual", "--apply", "--yes"], runner=widened)
    assert code == 1 and not [c for c in fake.calls if c[:3] == APT_PURGE]
    assert "apt would also change: cowsay-off" in capsys.readouterr().err


def test_json_plan(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _ = run(tmp_path, ["--residual", "--kernels", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0 and data["dry_run"] is True
    assert (
        data["residual"] == ["cowsay", "hello"]
        and "linux-image-6.8.0-40-generic" in data["kernels"]
    )
    assert data["kept"] == ["6.8.0-45", "6.8.0-49"] and data["dirs"] == [] and data["modules"] == []
    assert isinstance(data["size_kib"], int)


def test_usage_without_a_category(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(tmp_path, [])[0] == 3
    assert "choose what to clean" in capsys.readouterr().err
    assert run(tmp_path, ["--bogus"])[0] == 3
    assert run(tmp_path, ["--all", "--keep", "0"])[0] == 3
    assert run(tmp_path, ["--all", "--keep", "11"])[0] == 3


def test_refused_preflight_exits_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sys_ = system(root=False)
    code, fake = run(tmp_path, ["--all", "--apply", "--yes"], system=sys_)
    assert code == 1 and fake.calls == []
    assert "must be run as root" in capsys.readouterr().err


def test_refused_plan_exits_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sys_ = system(commands={("uname", "-r"): "custom\n"})
    assert run(tmp_path, ["--kernels"], system=sys_)[0] == 1
    assert "running kernel" in capsys.readouterr().err


def test_nothing_to_do(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sys_ = system(commands={cli.PACKAGES_ARGV: "ii \tbash\t5.2\t7000\n"})
    code, fake = run(tmp_path, ["--residual", "--apply", "--yes"], system=sys_)
    assert code == 0 and fake.calls == [DPKG_AUDIT]  # checked, locked, planned: nothing
    assert "Nothing to clean up." in capsys.readouterr().out


def test_failed_purge_exits_2(tmp_path: Path) -> None:
    from pydebuprep.system import CommandResult

    purge = (*APT_PURGE, "cowsay", "hello")
    failing = FakeRunner({(*APT_SIMULATE, "cowsay", "hello"): SIMULATED,
                          purge: CommandResult(purge, 100, "", "E: broken\n")})  # fmt: skip
    assert run(tmp_path, ["--residual", "--apply", "--yes"], runner=failing)[0] == 2


def test_keep_packages_from_config_and_option(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    conf = tmp_path / "pydebuprep.conf"
    conf.write_text("cleanup:\n  keep_packages: [hello]\n")
    log = Log(str(tmp_path / "cleanup.log"), run_id="t")
    code = cli.main(["--config", str(conf), "--residual", "--keep-package", "cowsay", "--json"],
                    system=system(), runner=FakeRunner(), log=log, now=NOW)  # fmt: skip
    data = json.loads(capsys.readouterr().out)
    assert code == 0 and data["residual"] == [] and data["skipped"] == ["cowsay", "hello"]


def test_bad_config_is_a_usage_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    conf = tmp_path / "pydebuprep.conf"
    conf.write_text("cleanup:\n  keep_packages: [-x]\n  other: 1\n")
    log = Log(str(tmp_path / "cleanup.log"), run_id="t")
    assert (
        cli.main(
            ["--config", str(conf), "--residual"],
            system=system(),
            runner=FakeRunner(),
            log=log,
            now=NOW,
        )
        == 3
    )
    err = capsys.readouterr().err
    assert "keep_packages" in err and "unknown key 'other'" in err


def test_remote_config_cannot_keep_packages() -> None:
    from pydebuprep.config import ConfigError
    from pydebuprep.remote_config import parse_remote

    with pytest.raises(ConfigError, match=r"cleanup\.keep_packages"):
        parse_remote("cleanup:\n  keep_packages: [hello]\n", "https://portal.example/c.yaml")


def test_packages_constant_matches(tmp_path: Path) -> None:
    assert PACKAGES and cli.PACKAGES_ARGV[0] == "dpkg-query"


def test_apply_directories_only(tmp_path: Path) -> None:

    removed: list[str] = []
    sys_ = system(commands={
        owner_query("/lib/modules/6.8.0-30-generic"): "",
        owner_query("/usr/src/linux-headers-6.8.0-30-generic"): "",
    })  # fmt: skip
    code, fake = run(
        tmp_path, ["--leftover-dirs", "--apply", "--yes"], system=sys_, remove=removed.append
    )
    assert code == 0 and fake.calls == [DPKG_AUDIT]  # no packages: nothing to simulate
    assert removed == ["/lib/modules/6.8.0-30-generic", "/usr/src/linux-headers-6.8.0-30-generic"]


def test_cleanup_section_must_be_a_mapping(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    conf = tmp_path / "pydebuprep.conf"
    conf.write_text("cleanup: 5\n")
    log = Log(str(tmp_path / "cleanup.log"), run_id="t")
    assert (
        cli.main(
            ["--config", str(conf), "--residual"],
            system=system(),
            runner=FakeRunner(),
            log=log,
            now=NOW,
        )
        == 3
    )
    assert "cleanup: expected a mapping" in capsys.readouterr().err
    conf.write_text("cleanup:\n  keep_packages: hello\n")
    log = Log(str(tmp_path / "cleanup.log"), run_id="t")
    assert (
        cli.main(
            ["--config", str(conf), "--residual"],
            system=system(),
            runner=FakeRunner(),
            log=log,
            now=NOW,
        )
        == 3
    )
    assert "expected a list of package names" in capsys.readouterr().err


def test_apply_plans_only_inside_the_lock(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from pydebuprep.cleanup.runner import Lock

    sys_ = system()
    with Lock(runner_module.LOCK_PATH):  # another cleanup is running
        code, _ = run(tmp_path, ["--residual", "--apply", "--yes"], system=sys_)
    assert code == 1 and "already running" in capsys.readouterr().err
    assert sys_.calls == []  # nothing planned outside the lock


def test_end_of_input_at_the_prompt_is_no(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def eof(prompt: str) -> str:
        raise EOFError

    code, fake = run(tmp_path, ["--residual", "--apply"], interactive=True, ask=eof)
    assert code == 1 and not [c for c in fake.calls if c[:3] == APT_PURGE]
    assert "not confirmed" in capsys.readouterr().err
