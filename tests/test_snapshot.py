from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from fakes import FakeSystem
from pydebuprep.checks.base import Check, Context
from pydebuprep.model import Finding
from pydebuprep.osinfo import OsInfo
from pydebuprep.snapshot import (
    SnapshotError,
    baseline_info,
    build_snapshot,
    create_snapshot,
    find_latest,
    load_snapshot,
)

OS = OsInfo("debian", "12", "bookworm", "Debian 12", None)


class Units(Check):
    id = "units"
    title = "Units"
    category = "services"

    def run(self, ctx: Context) -> list[Finding]:
        return []

    def collect_baseline(self, ctx: Context) -> Any:
        return ["ssh.service"]


class RootOnly(Units):
    id = "root-only"
    requires_root = True


class Broken(Units):
    id = "broken"

    def collect_baseline(self, ctx: Context) -> Any:
        raise RuntimeError("nope")


class NoBaseline(Check):
    id = "no-baseline"

    def run(self, ctx: Context) -> list[Finding]:
        return []


def ctx() -> Context:
    sys = FakeSystem(root=False, commands={("uname", "-r"): "6.1.0-26-amd64\n"})
    return Context(sys, OS)


CHECKS = [Units(), RootOnly(), Broken(), NoBaseline()]


def test_build_snapshot_contents() -> None:
    snap = build_snapshot(CHECKS, ctx())
    assert snap["schema_version"] == "1"
    assert snap["hostname"] == "testhost"
    assert snap["kernel"] == "6.1.0-26-amd64"
    assert snap["os"] == {"id": "debian", "version_id": "12", "codename": "bookworm"}
    assert snap["created_at"] == "2026-10-28T12:00:00+00:00"
    assert snap["checks"] == {"units": ["ssh.service"]}
    assert sorted(snap["skipped"]) == ["broken", "root-only"]


def test_create_and_load_roundtrip(tmp_path: Path) -> None:
    d = tmp_path / "snaps"
    path = create_snapshot(CHECKS, ctx(), str(d))
    assert path.name == "20261028T120000Z.json"
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    loaded = load_snapshot(str(path))
    assert loaded["checks"] == {"units": ["ssh.service"]}


def test_create_never_overwrites(tmp_path: Path) -> None:
    a = create_snapshot(CHECKS, ctx(), str(tmp_path))
    b = create_snapshot(CHECKS, ctx(), str(tmp_path))
    assert a != b
    assert b.name == "20261028T120000Z-1.json"


def test_load_invalid_json_raises(tmp_path: Path) -> None:
    p = tmp_path / "x.json"
    p.write_text("{not json")
    with pytest.raises(SnapshotError, match="not valid JSON"):
        load_snapshot(str(p))


def test_load_wrong_schema_raises(tmp_path: Path) -> None:
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"schema_version": "99", "checks": {}}))
    with pytest.raises(SnapshotError, match="schema"):
        load_snapshot(str(p))


def test_load_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(SnapshotError):
        load_snapshot(str(tmp_path / "missing.json"))


def test_find_latest_skips_corrupt(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = {"schema_version": "1", "checks": {}, "created_at": "x", "hostname": "h", "os": {}}
    (tmp_path / "20261001T000000Z.json").write_text(json.dumps(good))
    (tmp_path / "20261002T000000Z.json").write_text("garbage")
    found = find_latest(str(tmp_path))
    assert found is not None
    assert found[0].endswith("20261001T000000Z.json")
    assert "20261002T000000Z.json" in capsys.readouterr().err


def test_find_latest_orders_suffixed_names(tmp_path: Path) -> None:
    good = json.dumps({"schema_version": "1", "checks": {}})
    for name in ("20261001T000000Z.json", "20261001T000000Z-1.json", "20260901T000000Z.json"):
        (tmp_path / name).write_text(good)
    found = find_latest(str(tmp_path))
    assert found is not None
    assert found[0].endswith("20261001T000000Z-1.json")


def test_find_latest_empty_or_missing_dir_returns_none(tmp_path: Path) -> None:
    assert find_latest(str(tmp_path)) is None
    assert find_latest(str(tmp_path / "nope")) is None


def test_create_unwritable_dir_raises_snapshot_error(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("")
    with pytest.raises(SnapshotError):
        create_snapshot(CHECKS, ctx(), str(blocker / "sub"))


def test_baseline_info() -> None:
    snap = {"created_at": "c", "os": {"version_id": "12"}, "hostname": "h"}
    info = baseline_info("/p.json", snap)
    assert (info.path, info.created_at, info.os_version, info.hostname) == (
        "/p.json",
        "c",
        "12",
        "h",
    )


def test_snapshot_files_are_private_whatever_the_umask(tmp_path: Path) -> None:
    """Snapshots hold cron command lines, network details and package lists."""
    old = os.umask(0o002)
    try:
        path = create_snapshot(CHECKS, ctx(), str(tmp_path / "snaps"))
        second = create_snapshot(CHECKS, ctx(), str(tmp_path / "snaps"))
    finally:
        os.umask(old)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(second.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_existing_snapshot_directory_is_left_alone(tmp_path: Path) -> None:
    d = tmp_path / "mine"
    d.mkdir(mode=0o755)
    d.chmod(0o755)
    path = create_snapshot(CHECKS, ctx(), str(d))
    assert stat.S_IMODE(d.stat().st_mode) == 0o755  # the user's own directory
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
