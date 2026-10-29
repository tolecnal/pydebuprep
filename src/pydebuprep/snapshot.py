"""Pre-upgrade snapshots: the union of each check's baseline data."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from pydebuprep.checks.base import Check, CommandFailed, Context, running_kernel
from pydebuprep.model import BaselineInfo

DEFAULT_SNAPSHOT_DIR = "/var/lib/pydebuprep/snapshots"
SCHEMA_VERSION = "1"
SNAPSHOT_DIR_MODE = 0o700
SNAPSHOT_FILE_MODE = 0o600
# Never overwrite an existing file, and never write through a symlink.
CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class SnapshotError(Exception):
    pass


def format_timestamp(when: datetime) -> str:
    return when.strftime("%Y%m%dT%H%M%SZ")


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
    try:
        kernel = running_kernel(ctx)
    except CommandFailed:
        kernel = "unknown"
    return {
        "schema_version": SCHEMA_VERSION,
        "created_at": ctx.system.now().isoformat(timespec="seconds"),
        "hostname": ctx.system.hostname(),
        "os": {"id": os_info.id, "version_id": os_info.version_id, "codename": os_info.codename},
        "kernel": kernel,
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
        # Snapshots hold cron command lines, network details and package lists, so
        # they are private to their owner: a new directory is 0700, each file 0600.
        if not target_dir.exists():
            target_dir.mkdir(parents=True, mode=SNAPSHOT_DIR_MODE)
            os.chmod(target_dir, SNAPSHOT_DIR_MODE)
        payload = json.dumps(snap, indent=2, ensure_ascii=False) + "\n"
        n = 0
        while True:
            name = f"{stamp}.json" if n == 0 else f"{stamp}-{n}.json"
            path = target_dir / name
            try:
                fd = os.open(path, CREATE_FLAGS, SNAPSHOT_FILE_MODE)
            except FileExistsError:
                n += 1
                continue
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            return path
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


def baseline_warnings(snap: dict[str, Any], hostname: str, codename: str) -> list[str]:
    """Reasons the baseline may not be a pre-upgrade snapshot of this host."""
    warnings = []
    other = snap.get("hostname")
    if other and other != hostname:
        warnings.append(f"baseline was taken on host {other}, not {hostname}")
    before = (snap.get("os") or {}).get("codename")
    if before and before == codename:
        warnings.append(
            f"baseline was taken on the current release ({codename}); "
            "it may be a post-upgrade snapshot"
        )
    return warnings
