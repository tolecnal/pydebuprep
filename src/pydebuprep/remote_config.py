"""Configs fetched from a URL (`--config https://…`), with a saved copy to fall back on.

A config from a URL is written by someone other than the host's root, so it may only
steer the read-only checks: it can't name a path pydebuprep writes to or reads its
credentials from, and it can't send the token to another server.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from datetime import datetime

from pydebuprep.config import Config, ConfigError, parse_config
from pydebuprep.deps import require_yaml
from pydebuprep.model import ConfigInfo
from pydebuprep.portal import (
    Connection,
    PortalError,
    check_url,
    fetch_config,
    read_token,
    same_origin,
)
from pydebuprep.state import (
    CachedConfig,
    StateError,
    load_cached_config,
    save_cached_config,
    state_dir,
)

# Write paths and credentials: only the host's own config may set these.
REMOTE_FORBIDDEN = (
    ("report", "output_dir"),
    ("report", "snapshot_dir"),
    ("upload", "token_file"),
    ("upload", "ca_file"),
    ("upload", "pending_dir"),
)


def is_url(text: str) -> bool:
    return text.startswith(("https://", "http://"))


def _forbidden_keys(text: str, url: str) -> list[str]:
    yaml = require_yaml()
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return []  # parse_config reports it, with its location
    if not isinstance(data, dict):
        return []
    return [
        f"{url}: {section}.{key} can't be set by a config fetched from a URL"
        for section, key in REMOTE_FORBIDDEN
        if isinstance(data.get(section), dict) and key in data[section]
    ]


def parse_remote(text: str, url: str) -> Config:
    """Parse a config fetched from URL, enforcing what such a config may not do."""
    errors = _forbidden_keys(text, url)
    try:
        config = parse_config(text, url)
    except ConfigError as exc:
        raise ConfigError(errors + exc.errors) from None
    upload_url = config.upload.url
    if upload_url and not same_origin(upload_url, url):
        errors.append(f"{url}: upload.url must be on the same server as the config ({upload_url})")
    baseline = config.report.baseline
    if baseline not in ("auto", "none") and not os.path.isabs(baseline):
        errors.append(f"{url}: report.baseline must be auto, none or an absolute path")
    if errors:
        raise ConfigError(errors)
    config.upload.pending_dir = os.path.join(state_dir(), "pending")
    return config


def load_remote_config(
    url: str,
    *,
    token_file: str,
    conn: Connection,
    cache_dir: str,
    now: datetime,
    warn: Callable[[str], None],
    env: Mapping[str, str] = os.environ,
) -> tuple[Config, ConfigInfo]:
    """Fetch URL's config; if the portal can't be reached, use the saved copy (stale)."""
    try:
        check_url(url, conn.allow_http)
    except PortalError as exc:
        raise ConfigError([str(exc)]) from None
    cached = load_cached_config(cache_dir, url)
    try:
        token = read_token(token_file, env)
        fetched = fetch_config(url, token, conn, cached.etag if cached else None)
    except PortalError as exc:
        if cached is None:
            raise ConfigError(
                [f"cannot fetch config {url}: {exc}; there is no saved copy to fall back on"]
            ) from None
        warn(f"cannot fetch config {url}: {exc}; using the copy fetched on {cached.fetched_at}")
        return parse_remote(cached.text, url), ConfigInfo(url, cached.fetched_at, True)
    if fetched.text is not None:
        text = fetched.text
    elif cached is not None:
        text = cached.text
    else:
        raise ConfigError([f"{url}: the portal answered 'not modified' but there is no saved copy"])
    config = parse_remote(text, url)  # an invalid config is an error, and isn't saved
    fetched_at = now.isoformat(timespec="seconds")
    try:
        save_cached_config(cache_dir, CachedConfig(url, fetched_at, fetched.etag, text))
    except StateError as exc:
        warn(f"could not save a copy of the config: {exc}")
    return config, ConfigInfo(url, fetched_at, False)
