"""pydebuprep's own private files: reports that failed to upload, and saved copies of
configs fetched from a URL.

These are the only files a report run writes besides its report, and only into
directories that already exist (the package creates them): pydebuprep creates no
directories. Files are mode 0600, written under a temporary name and renamed into
place, never through a symlink.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timezone

from pydebuprep.snapshot import format_timestamp

STATE_DIR_ENV = "PYDEBUPREP_STATE_DIR"
DEFAULT_STATE_DIR = "/var/lib/pydebuprep"
DEFAULT_PENDING_DIR = f"{DEFAULT_STATE_DIR}/pending"
UNSAFE_IN_FILE_NAME = re.compile(r"[^A-Za-z0-9._-]")


class StateError(Exception):
    pass


def state_dir() -> str:
    return os.environ.get(STATE_DIR_ENV) or DEFAULT_STATE_DIR


def write_private(directory: str, name: str, data: bytes) -> str:
    """Write DATA to DIRECTORY/NAME (mode 0600), replacing it; return the path."""
    if not name or "/" in name or name in (".", ".."):
        raise ValueError(f"{name!r} is not a plain file name")
    try:
        info = os.lstat(directory)
    except FileNotFoundError:
        raise StateError(f"{directory}: no such directory") from None
    except OSError as exc:
        raise StateError(f"{directory}: {exc.strerror}") from None
    if not stat.S_ISDIR(info.st_mode):
        raise StateError(f"{directory}: not a directory")
    path = os.path.join(directory, name)
    temp = os.path.join(directory, f".{name}.{secrets.token_hex(8)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(temp, flags, 0o600)
    except OSError as exc:
        raise StateError(f"cannot write {path}: {exc.strerror}") from None
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp, path)  # replaces a symlink at PATH itself, never its target
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.unlink(temp)
        raise StateError(f"cannot write {path}: {exc.strerror or exc}") from None
    return path


def save_pending(directory: str, body: bytes, hostname: str, generated_at: str) -> str:
    """Keep a report that failed to upload; the same report twice is kept once."""
    when = datetime.fromisoformat(generated_at).astimezone(timezone.utc)
    host = UNSAFE_IN_FILE_NAME.sub("_", hostname)
    digest = hashlib.sha256(body).hexdigest()[:12]
    return write_private(
        directory, f"pydebuprep-{host}-{format_timestamp(when)}-{digest}.json", body
    )


def pending_reports(directory: str) -> list[str]:
    """The kept reports, oldest name first; symlinks and other files are left alone."""
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    paths = [os.path.join(directory, n) for n in names if n.endswith(".json")]
    return sorted(p for p in paths if stat.S_ISREG(os.lstat(p).st_mode))


def remove_pending(path: str) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)


@dataclass
class CachedConfig:
    url: str
    fetched_at: str
    etag: str | None
    text: str


def _cache_name(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:32] + ".json"


def save_cached_config(directory: str, cached: CachedConfig) -> str:
    data = {"url": cached.url, "fetched_at": cached.fetched_at, "etag": cached.etag}
    data["text"] = cached.text
    return write_private(directory, _cache_name(cached.url), json.dumps(data).encode())


def load_cached_config(directory: str, url: str) -> CachedConfig | None:
    """The saved copy of URL's config, or None if there is no usable one."""
    path = os.path.join(directory, _cache_name(url))
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("url") != url:
        return None
    fetched_at, etag, text = data.get("fetched_at"), data.get("etag"), data.get("text")
    if not isinstance(fetched_at, str) or not isinstance(text, str):
        return None
    return CachedConfig(url, fetched_at, etag if isinstance(etag, str) else None, text)
