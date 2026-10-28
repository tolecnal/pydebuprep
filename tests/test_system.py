from __future__ import annotations

import pytest

from pydebuprep import system
from pydebuprep.system import APT_RO_OPTS, DisallowedCommandError, System, check_allowed


def _allow(monkeypatch: pytest.MonkeyPatch, *prefixes: tuple[str, ...]) -> None:
    monkeypatch.setattr(system, "ALLOWED_PREFIXES", system.ALLOWED_PREFIXES + prefixes)


def test_check_allowed_accepts_apt_with_ro_opts() -> None:
    check_allowed(("apt", *APT_RO_OPTS, "list", "--upgradable"))
    check_allowed(("systemd-analyze",))
    check_allowed(("systemd-analyze", "blame", "--no-pager"))


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
    ],
)
def test_check_allowed_rejects_writes(argv: tuple[str, ...]) -> None:
    with pytest.raises(DisallowedCommandError):
        check_allowed(argv)


def test_run_rejects_disallowed() -> None:
    with pytest.raises(DisallowedCommandError):
        System().run(["apt", "update"])


def test_run_timeout_returns_result(monkeypatch: pytest.MonkeyPatch) -> None:
    _allow(monkeypatch, ("sleep",))
    res = System().run(["sleep", "5"], timeout=0.1)
    assert res.timed_out
    assert not res.ok


def test_run_missing_binary_returns_127(monkeypatch: pytest.MonkeyPatch) -> None:
    _allow(monkeypatch, ("no-such-binary-pydebuprep",))
    res = System().run(["no-such-binary-pydebuprep"])
    assert res.returncode == 127
    assert not res.ok


def test_run_decodes_invalid_utf8(monkeypatch: pytest.MonkeyPatch) -> None:
    _allow(monkeypatch, ("printf",))
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
