"""Talking to a pydebuprep portal: the only code that does.

Two requests, both opt-in: fetching a config (`--config https://…`) and uploading a
report (`upload: url:`). HTTPS with verified certificates (the system's CAs plus an
optional bundle), http:// only with --allow-http, and redirects are never followed, so
the token only ever goes to the server it was configured for.
"""

from __future__ import annotations

import gzip
import http.client
import json
import os
import re
import socket
import ssl
import stat
import threading
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from email.message import Message
from typing import Any
from urllib.parse import urlsplit

from pydebuprep import __version__
from pydebuprep.config import url_problem
from pydebuprep.render._common import clean

TOKEN_ENV = "PYDEBUPREP_TOKEN"  # nosec B105 - a variable name, not a token
CA_FILE_ENV = "PYDEBUPREP_CA_FILE"
TIMEOUT = 30.0
MAX_CONFIG_BYTES = 1 << 20
MAX_REPLY_BYTES = 1 << 16
REPORTS_PATH = "/api/v1/reports"
TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]+")
DEFAULT_PORTS = {"https": 443, "http": 80}
TOKEN_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class PortalError(Exception):
    pass


@dataclass(frozen=True)
class Connection:
    allow_http: bool = False
    ca_file: str | None = None
    timeout: float = TIMEOUT


@dataclass
class Fetched:
    text: str | None  # None: not modified since the ETag given
    etag: str | None


def _valid_token(text: str, source: str) -> str:
    token = text.strip()
    if not token:
        raise PortalError(f"{source} is empty")
    if not TOKEN.fullmatch(token):
        # Never echo the text: it may be a real token with a stray character.
        raise PortalError(f"{source} is not a valid token (letters, digits and ._~+/=- only)")
    return token


def read_token(token_file: str, env: Mapping[str, str]) -> str:
    """The upload token: PYDEBUPREP_TOKEN if set, else TOKEN_FILE (root-only)."""
    if TOKEN_ENV in env:
        return _valid_token(env[TOKEN_ENV], TOKEN_ENV)
    try:
        with os.fdopen(os.open(token_file, TOKEN_OPEN_FLAGS), "rb") as fh:
            mode = os.fstat(fh.fileno()).st_mode
            if not stat.S_ISREG(mode):
                raise PortalError(f"cannot read {token_file}: not a regular file")
            if stat.S_IMODE(mode) & 0o077:
                raise PortalError(
                    f"{token_file} is readable by other users; run: chmod 600 {token_file}"
                )
            data = fh.read(4096)
    except FileNotFoundError:
        raise PortalError(
            f"no upload token: set {TOKEN_ENV} or create {token_file} (mode 0600)"
        ) from None
    except OSError as exc:
        raise PortalError(f"cannot read {token_file}: {exc.strerror or exc}") from None
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        text = "\x00"  # fails the token rule below
    return _valid_token(text, token_file)


def check_url(url: str, allow_http: bool) -> None:
    problem = url_problem(url)
    if problem:
        raise PortalError(f"{url}: {problem}")
    if urlsplit(url).scheme == "http" and not allow_http:
        raise PortalError(
            f"{url}: http:// is allowed only with --allow-http "
            "(the token would cross the network unencrypted)"
        )


def same_origin(a: str, b: str) -> bool:
    def origin(url: str) -> tuple[str, str, int | None]:
        parts = urlsplit(url)
        return parts.scheme, (parts.hostname or ""), parts.port or DEFAULT_PORTS.get(parts.scheme)

    return origin(a) == origin(b)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(  # noqa: PLR0917 - urllib's signature
        self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> urllib.request.Request | None:
        raise PortalError(f"{req.full_url}: redirect to {newurl} not followed")


def _opener(conn: Connection) -> urllib.request.OpenerDirector:
    context = ssl.create_default_context()
    if conn.ca_file:
        try:
            context.load_verify_locations(conn.ca_file)
        except (OSError, ssl.SSLError) as exc:
            reason = getattr(exc, "strerror", None) or str(exc)
            raise PortalError(f"cannot load CA file {conn.ca_file}: {reason}") from None
    return urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=context))


def _excerpt(data: bytes) -> str:
    return " ".join(clean(data.decode("utf-8", "replace")).split())[:200]


def _request(
    method: str,
    url: str,
    token: str,
    conn: Connection,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    limit: int,
) -> tuple[int, Message, bytes]:
    """_send, within conn.timeout for the whole request: a socket timeout covers one
    read, so a server trickling a byte at a time would otherwise hold the run for ever.
    On a timeout the request is abandoned in a daemon thread."""
    outcome: list[Any] = []

    def send() -> None:
        try:
            outcome.append(_send(method, url, token, conn, data=data, headers=headers, limit=limit))
        except BaseException as exc:  # handed to the caller below
            outcome.append(exc)

    worker = threading.Thread(target=send, daemon=True)
    worker.start()
    worker.join(conn.timeout)
    if not outcome:
        raise PortalError(f"{url}: timed out after {conn.timeout:g} s")
    if isinstance(outcome[0], BaseException):
        raise outcome[0]
    result: tuple[int, Message, bytes] = outcome[0]
    return result


def _send(
    method: str,
    url: str,
    token: str,
    conn: Connection,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    limit: int,
) -> tuple[int, Message, bytes]:
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("User-Agent", f"pydebuprep/{__version__}")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    opener = _opener(conn)
    try:
        # The scheme was checked by check_url: https, or http with --allow-http.
        with opener.open(request, timeout=conn.timeout) as response:  # nosec B310
            # With a known length, read all of it, so a reply cut short is an error
            # (IncompleteRead) rather than a truncated config.
            length = response.headers.get("Content-Length", "")
            whole = length.isdigit() and int(length) <= limit
            body = response.read() if whole else response.read(limit + 1)
            return response.status, response.headers, body
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return 304, exc.headers, b""
        excerpt = _excerpt(exc.read(200))
        raise PortalError(f"{url}: HTTP {exc.code}" + (f": {excerpt}" if excerpt else "")) from None
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, (TimeoutError, socket.timeout)):
            raise PortalError(f"{url}: timed out after {conn.timeout:g} s") from None
        text = getattr(reason, "strerror", None) or str(reason)
        raise PortalError(f"{url}: {text}") from None
    except TimeoutError:
        raise PortalError(f"{url}: timed out after {conn.timeout:g} s") from None
    except http.client.HTTPException as exc:  # not HTTP, or a reply cut short
        raise PortalError(f"{url}: {type(exc).__name__}: {exc}") from None
    except (OSError, ValueError) as exc:
        raise PortalError(f"{url}: {exc}") from None


def fetch_config(url: str, token: str, conn: Connection, etag: str | None = None) -> Fetched:
    """GET a config; Fetched(None, …) when unchanged since ETAG."""
    check_url(url, conn.allow_http)
    headers = {"If-None-Match": etag} if etag else {}
    status, reply_headers, body = _request(
        "GET", url, token, conn, headers=headers, limit=MAX_CONFIG_BYTES
    )
    new_etag = reply_headers.get("ETag") or etag
    if status == 304:
        return Fetched(None, new_etag)
    if len(body) > MAX_CONFIG_BYTES:
        raise PortalError(f"{url}: the config is larger than 1 MiB")
    try:
        return Fetched(body.decode("utf-8"), reply_headers.get("ETag"))
    except UnicodeDecodeError:
        raise PortalError(f"{url}: the config is not UTF-8 text") from None


def upload_report(base_url: str, token: str, conn: Connection, body: bytes) -> str:
    """POST a JSON report; returns the portal's URL for it (or BASE_URL)."""
    check_url(base_url, conn.allow_http)
    url = base_url.rstrip("/") + REPORTS_PATH
    status, _, reply = _request(
        "POST",
        url,
        token,
        conn,
        data=gzip.compress(body),
        headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
        limit=MAX_REPLY_BYTES,
    )
    if not 200 <= status < 300:  # a 304 isn't "stored"; the kept report must stay
        raise PortalError(f"{url}: HTTP {status}")
    try:
        # A short JSON object at most: a reply nested thousands deep would raise
        # RecursionError, after the report was already printed.
        location = json.loads(reply).get("url") if len(reply) <= 4096 else None
    except (ValueError, AttributeError, RecursionError):
        location = None
    return clean(location) if isinstance(location, str) and location else base_url
