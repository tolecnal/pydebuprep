"""Pre-upgrade snapshots: the union of each check's baseline data."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from pydebuprep.checks.base import Check, Context
from pydebuprep.model import BaselineInfo

DEFAULT_SNAPSHOT_DIR = "/var/lib/pydebuprep/snapshots"
SCHEMA_VERSION = "1"


class SnapshotError(Exception):
    pass


def format_timestamp(when: datetime) -> str:
    return when.strftime("%Y%m%dT%H%M%SZ")


def running_kernel(ctx: Context) -> str:
    res = ctx.system.run(["uname", "-r"])
    return res.stdout.strip() if res.ok else "unknown"


def build_snapshot(checks: Sequence[Check], ctx: Context) -> dict[str, Any]:
    data: dict[str, Any] = {}
    skipped: list[str] = []
    for check in checks:
        if not check.supports_baseline:
            continue
        if check.unmet_requirement(ctx) is not None:
            skipped.append(check.id)
            continue
        try:
            value = check.collect_baseline(ctx)
        except Exception:
            skipped.append(check.id)
            continue
        if value is None:
            skipped.append(check.id)
        else:
            data[check.id] = value
    os_info = ctx.osinfo
    return {
        "schema_version": SCHEMA_VERSION,
        "created_at": ctx.system.now().isoformat(timespec="seconds"),
        "hostname": ctx.system.hostname(),
        "os": {"id": os_info.id, "version_id": os_info.version_id, "codename": os_info.codename},
        "kernel": running_kernel(ctx),
        "checks": data,
        "skipped": skipped,
    }


def create_snapshot(
    checks: Sequence[Check], ctx: Context, directory: str = DEFAULT_SNAPSHOT_DIR
) -> Path:
    snap = build_snapshot(checks, ctx)
    stamp = format_timestamp(ctx.system.now())
    target_dir = Path(directory)
    try:
        if not target_dir.exists():
            target_dir.mkdir(parents=True, mode=0o750)
            os.chmod(target_dir, 0o750)
        payload = json.dumps(snap, indent=2, ensure_ascii=False) + "\n"
        n = 0
        while True:
            name = f"{stamp}.json" if n == 0 else f"{stamp}-{n}.json"
            path = target_dir / name
            try:
                with open(path, "x", encoding="utf-8") as fh:
                    fh.write(payload)
                return path
            except FileExistsError:
                n += 1
    except OSError as exc:
        raise SnapshotError(f"cannot write snapshot in {directory}: {exc.strerror or exc}") from exc


def load_snapshot(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise SnapshotError(f"cannot read snapshot {path}: {exc.strerror or exc}") from exc
    try:
        snap = json.loads(text)
    except ValueError as exc:
        raise SnapshotError(f"snapshot {path} is not valid JSON: {exc}") from exc
    if not isinstance(snap, dict) or snap.get("schema_version") != SCHEMA_VERSION:
        raise SnapshotError(f"snapshot {path} has an unsupported schema version")
    if not isinstance(snap.get("checks"), dict):
        raise SnapshotError(f"snapshot {path} has no checks section")
    return snap


def _sort_key(path: Path) -> tuple[str, int]:
    base, _, suffix = path.stem.partition("-")
    return (base, int(suffix) if suffix.isdigit() else 0)


def find_latest(directory: str = DEFAULT_SNAPSHOT_DIR) -> tuple[str, dict[str, Any]] | None:
    try:
        candidates = sorted(Path(directory).glob("*.json"), key=_sort_key, reverse=True)
    except OSError:
        return None
    for path in candidates:
        try:
            return str(path), load_snapshot(str(path))
        except SnapshotError as exc:
            print(f"pydebuprep: skipping unusable snapshot: {exc}", file=sys.stderr)
    return None


def baseline_info(path: str, snap: dict[str, Any]) -> BaselineInfo:
    os_info = snap.get("os") or {}
    return BaselineInfo(
        path=path,
        created_at=str(snap.get("created_at", "")),
        os_version=str(os_info.get("version_id", "")),
        hostname=str(snap.get("hostname", "")),
    )
