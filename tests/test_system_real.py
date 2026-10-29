"""System against the real filesystem and process table (everything else uses FakeSystem)."""

from __future__ import annotations

import os
import socket
from datetime import timezone
from pathlib import Path

import pytest

from pydebuprep import system
from pydebuprep.system import System, _decode


def test_decode() -> None:
    assert _decode(None) == ""
    assert _decode("already text") == "already text"
    assert _decode(b"caf\xc3\xa9 \xff") == "café �"


def test_run_unexecutable_returns_126(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(system, "ALLOWED_COMMANDS", system.ALLOWED_COMMANDS | {(str(tmp_path),)})
    res = System().run([str(tmp_path)])  # a directory: exists, but can't be executed
    assert res.returncode == 126
    assert not res.ok


def test_file_queries(tmp_path: Path) -> None:
    f = tmp_path / "a.conf"
    f.write_text("x = 1\n")
    s = System()
    assert s.read_text(str(f)) == "x = 1\n"
    assert s.exists(str(f))
    assert not s.exists(str(tmp_path / "missing"))
    assert s.glob(str(tmp_path / "*.conf")) == [str(f)]
    assert s.mtime(str(f)) == pytest.approx(f.stat().st_mtime)
    assert s.mtime(str(tmp_path / "missing")) is None


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read every directory")
def test_walk_files_reports_unreadable_directories(tmp_path: Path) -> None:
    (tmp_path / "ok").mkdir()
    (tmp_path / "ok" / "f").write_text("")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "hidden").write_text("")
    locked.chmod(0)
    try:
        errors: list[str] = []
        files = list(System().walk_files(str(tmp_path), errors))
        assert files == [str(tmp_path / "ok" / "f")]
        assert errors == [f"{locked}: Permission denied"]
        assert list(System().walk_files(str(tmp_path))) == files  # errors ignored when no list
    finally:
        locked.chmod(0o700)


def test_disk_usage(tmp_path: Path) -> None:
    usage = System().disk_usage(str(tmp_path))
    assert usage is not None
    assert usage.total > 0
    assert 0 <= usage.free <= usage.total
    assert System().disk_usage(str(tmp_path / "missing")) is None


def test_which_identity_and_clock() -> None:
    s = System()
    assert s.which("sh")
    assert not s.which("no-such-command-pydebuprep")
    assert s.is_root() == (os.geteuid() == 0)
    assert s.hostname() == socket.gethostname()
    assert s.now().tzinfo is timezone.utc
