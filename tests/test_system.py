from __future__ import annotations

import pytest

from pydebuprep import system
from pydebuprep.system import APT_RO_OPTS, DisallowedCommandError, System, check_allowed


def _allow(monkeypatch: pytest.MonkeyPatch, *argvs: tuple[str, ...]) -> None:
    monkeypatch.setattr(system, "ALLOWED_COMMANDS", system.ALLOWED_COMMANDS | set(argvs))


def test_check_allowed_accepts_exact_commands() -> None:
    check_allowed(("apt", *APT_RO_OPTS, "list", "--upgradable"))
    check_allowed(("systemd-analyze",))
    check_allowed(("systemd-analyze", "blame", "--no-pager"))
    check_allowed(
        ("systemctl", "show", "-p", "UnitFileState", "-p", "ConditionResult", "cron.timer")
    )


@pytest.mark.parametrize(
    "argv",
    [
        ("apt", "update"),
        ("apt", *APT_RO_OPTS, "update"),
        ("apt-get", "install", "x"),
        ("update-grub",),
        ("systemctl", "restart", "ssh"),
        ("systemd-analyze", "set-log-level", "debug"),
        ("systemd-analyze", "blame", "--no-pager", "extra"),
        ("sh", "-c", "ls"),
        (),
        # Trailing arguments after a once-allowed prefix must not slip through.
        ("journalctl", "-p", "3", "--vacuum-size=1K"),
        ("journalctl", "-p", "err", "-b", "--no-pager", "-o", "json", "--rotate"),
        ("dmesg", "--level=err", "--clear"),
        ("dmesg", "--level=warn", "-c"),
        ("dmesg", "--level=err", "--notime", "-n", "1"),
        ("efibootmgr", "-v", "-B", "-b", "0000"),
        ("efibootmgr", "-v", "-o", "0001,0000"),
        ("apt-get", *APT_RO_OPTS, "-s", "autoremove", "--no-simulate", "-y"),
        ("apt-get", *APT_RO_OPTS, "-s", "autoremove", "-o", "APT::Get::Simulate=0"),
        ("apt-cache", *APT_RO_OPTS, "policy", "-o", "Dir::Cache::pkgcache=/etc/x"),
        ("apt-get", "check"),  # missing the read-only apt options
        ("apt-mark", "showhold"),  # apt-mark rebuilds pkgcache.bin as root without them
        ("apt", "list", "--upgradable"),
        ("debsums", "-c", "--generate=all"),
        ("dkms", "status", "install", "-m", "x", "-v", "1"),
        ("needrestart", "-b", "-r", "l", "-r", "a"),
        ("systemctl", "list-units", "--state=failed", "--no-legend", "--plain", "--no-pager", "x"),
        ("systemctl", "show", "-p", "UnitFileState", "-p", "ConditionResult", "--now", "x"),
        ("systemctl", "show", "-p", "UnitFileState", "-p", "ConditionResult", "a", "b"),
        ("systemctl", "show", "-p", "UnitFileState", "-p", "ConditionResult", "-H"),
    ],
)
def test_check_allowed_rejects_writes(argv: tuple[str, ...]) -> None:
    with pytest.raises(DisallowedCommandError):
        check_allowed(argv)


def test_run_rejects_disallowed() -> None:
    with pytest.raises(DisallowedCommandError):
        System().run(["apt", "update"])


def test_run_timeout_returns_result(monkeypatch: pytest.MonkeyPatch) -> None:
    _allow(monkeypatch, ("sleep", "5"))
    res = System().run(["sleep", "5"], timeout=0.1)
    assert res.timed_out
    assert not res.ok


def test_run_missing_binary_returns_127(monkeypatch: pytest.MonkeyPatch) -> None:
    _allow(monkeypatch, ("no-such-binary-pydebuprep",))
    res = System().run(["no-such-binary-pydebuprep"])
    assert res.returncode == 127
    assert not res.ok


def test_run_decodes_invalid_utf8(monkeypatch: pytest.MonkeyPatch) -> None:
    _allow(monkeypatch, ("printf", "\\377ok"))
    res = System().run(["printf", "\\377ok"])
    assert res.stdout.endswith("ok")
    assert "�" in res.stdout


def test_run_sets_c_locale(monkeypatch: pytest.MonkeyPatch) -> None:
    _allow(monkeypatch, ("env",))
    assert "LC_ALL=C" in System().run(["env"]).stdout


def test_read_text_missing_returns_none(tmp_path: pytest.TempPathFactory) -> None:
    assert System().read_text("/nonexistent/pydebuprep") is None


def test_walk_files_collects_errors(tmp_path) -> None:  # type: ignore[no-untyped-def]
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "f.dpkg-new").write_text("x")
    errors: list[str] = []
    files = list(System().walk_files(str(tmp_path), errors))
    assert files == [str(tmp_path / "a" / "f.dpkg-new")]
    assert errors == []


def test_apt_never_writes_its_solver_log() -> None:
    # Without it, `apt-get -s autoremove` as root replaces /var/log/apt/eipp.log.xz.
    opts = list(zip(APT_RO_OPTS[::2], APT_RO_OPTS[1::2], strict=True))
    assert ("-o", "Dir::Log::Planner=") in opts
