"""pydebuprep's own private files: pending uploads and cached configs."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from pydebuprep import state
from pydebuprep.state import (
    CachedConfig,
    StateError,
    load_cached_config,
    pending_reports,
    remove_pending,
    save_cached_config,
    save_pending,
    write_private,
)

URL = "https://portal.example/api/v1/configs/web/default"


def mode(path: str | Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def test_write_private_mode_and_replace(tmp_path: Path) -> None:
    path = write_private(str(tmp_path), "a.json", b"one")
    assert path == str(tmp_path / "a.json")
    assert mode(path) == 0o600
    write_private(str(tmp_path), "a.json", b"two")
    assert (tmp_path / "a.json").read_bytes() == b"two"
    assert os.listdir(tmp_path) == ["a.json"]  # no temp file left behind


def test_directory_missing_is_an_error(tmp_path: Path) -> None:
    missing = tmp_path / "pending"
    with pytest.raises(StateError, match=f"{missing}: no such directory"):
        write_private(str(missing), "a.json", b"x")
    assert not missing.exists()


def test_symlinked_directory_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(StateError, match="not a directory"):
        write_private(str(tmp_path / "link"), "a.json", b"x")
    assert os.listdir(real) == []


def test_file_where_the_directory_should_be(tmp_path: Path) -> None:
    (tmp_path / "f").write_text("")
    with pytest.raises(StateError, match="not a directory"):
        write_private(str(tmp_path / "f"), "a.json", b"x")


def test_target_symlink_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("keep")
    directory = tmp_path / "d"
    directory.mkdir()
    (directory / "a.json").symlink_to(outside)
    write_private(str(directory), "a.json", b"new")
    assert outside.read_text() == "keep"
    assert not (directory / "a.json").is_symlink()
    assert (directory / "a.json").read_bytes() == b"new"


@pytest.mark.parametrize("name", ["", ".", "..", "a/b"])
def test_plain_names_only(tmp_path: Path, name: str) -> None:
    with pytest.raises(ValueError, match="not a plain file name"):
        write_private(str(tmp_path), name, b"x")


def test_unwritable_directory(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root can write anywhere")
    tmp_path.chmod(0o500)
    try:
        with pytest.raises(StateError, match="cannot write"):
            write_private(str(tmp_path), "a.json", b"x")
    finally:
        tmp_path.chmod(0o700)


def test_failed_write_leaves_no_temp_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*_: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(state.os, "fsync", broken)
    with pytest.raises(StateError, match="No space left on device"):
        write_private(str(tmp_path), "a.json", b"x")
    assert os.listdir(tmp_path) == []


def test_save_pending_is_idempotent(tmp_path: Path) -> None:
    first = save_pending(str(tmp_path), b'{"r": 1}', "web/01 x", "2026-10-30T09:15:00+01:00")
    name = os.path.basename(first)
    assert name.startswith("pydebuprep-web_01_x-20261030T081500Z-")
    assert name.endswith(".json") and len(name) == len("pydebuprep-web_01_x-20261030T081500Z-") + 17
    assert (
        save_pending(str(tmp_path), b'{"r": 1}', "web/01 x", "2026-10-30T09:15:00+01:00") == first
    )
    other = save_pending(str(tmp_path), b'{"r": 2}', "web/01 x", "2026-10-30T09:15:00+01:00")
    assert other != first
    assert pending_reports(str(tmp_path)) == sorted([first, other])


def test_pending_reports_skips_symlinks_and_other_files(tmp_path: Path) -> None:
    kept = save_pending(str(tmp_path), b"{}", "h", "2026-10-30T09:15:00+00:00")
    (tmp_path / "notes.txt").write_text("")
    (tmp_path / "link.json").symlink_to(kept)
    (tmp_path / "dir.json").mkdir()
    assert pending_reports(str(tmp_path)) == [kept]
    assert pending_reports(str(tmp_path / "missing")) == []


def test_remove_pending(tmp_path: Path) -> None:
    kept = save_pending(str(tmp_path), b"{}", "h", "2026-10-30T09:15:00+00:00")
    remove_pending(kept)
    assert pending_reports(str(tmp_path)) == []
    remove_pending(kept)  # already gone: fine


def test_cache_round_trip(tmp_path: Path) -> None:
    cached = CachedConfig(URL, "2026-10-29T14:02:00+00:00", '"abc"', "report:\n  format: json\n")
    path = save_cached_config(str(tmp_path), cached)
    assert mode(path) == 0o600
    assert load_cached_config(str(tmp_path), URL) == cached
    assert load_cached_config(str(tmp_path), URL + "x") is None


def test_cache_ignores_corrupt_symlinked_and_other_url(tmp_path: Path) -> None:
    path = save_cached_config(str(tmp_path), CachedConfig(URL, "t", None, "x"))
    Path(path).write_text("not json")
    assert load_cached_config(str(tmp_path), URL) is None
    Path(path).write_text('{"url": "https://other", "fetched_at": "t", "etag": null, "text": "x"}')
    assert load_cached_config(str(tmp_path), URL) is None
    Path(path).write_text(json.dumps({"url": URL, "fetched_at": 1, "etag": None, "text": "x"}))
    assert load_cached_config(str(tmp_path), URL) is None
    Path(path).write_text('["a list"]')
    assert load_cached_config(str(tmp_path), URL) is None
    os.remove(path)
    real = tmp_path / "elsewhere.json"
    real.write_text(json.dumps({"url": URL, "fetched_at": "t", "etag": None, "text": "x"}))
    os.symlink(real, path)
    assert load_cached_config(str(tmp_path), URL) is None
    assert load_cached_config(str(tmp_path / "missing"), URL) is None


def test_state_dir_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(state.STATE_DIR_ENV, raising=False)
    assert state.state_dir() == "/var/lib/pydebuprep"
    monkeypatch.setenv(state.STATE_DIR_ENV, "/srv/pdp")
    assert state.state_dir() == "/srv/pdp"
    assert state.DEFAULT_PENDING_DIR == "/var/lib/pydebuprep/pending"


def test_directory_that_cannot_be_inspected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def denied(path: str) -> os.stat_result:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(state.os, "lstat", denied)
    with pytest.raises(StateError, match=f"{tmp_path}: Permission denied"):
        write_private(str(tmp_path), "a.json", b"x")


def test_temp_file_that_cannot_be_removed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*_: object) -> None:
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(state.os, "fsync", broken)
    monkeypatch.setattr(state.os, "unlink", broken)
    with pytest.raises(StateError, match="Input/output error"):
        write_private(str(tmp_path), "a.json", b"x")
