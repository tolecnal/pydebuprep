"""Talking to a pydebuprep portal: tokens, URL rules, fetching configs, uploading reports."""

from __future__ import annotations

import gzip
import json
import shutil
import socket
import ssl
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from portal_stub import Portal, Reply, running_portal
from pydebuprep import __version__
from pydebuprep.portal import (
    MAX_CONFIG_BYTES,
    REPORTS_PATH,
    Connection,
    Fetched,
    PortalError,
    check_url,
    fetch_config,
    read_token,
    same_origin,
    upload_report,
)

CONFIG_PATH = "/api/v1/configs/web/default"
HTTP = Connection(allow_http=True, timeout=5.0)
TOKEN = "pdp_abc.DEF-123~x+y/z="


@pytest.fixture
def portal() -> Iterator[Portal]:
    with running_portal() as p:
        yield p


# --- the token -------------------------------------------------------------


def token_file(tmp_path: Path, text: str, mode: int = 0o600) -> str:
    path = tmp_path / "token"
    path.write_text(text)
    path.chmod(mode)
    return str(path)


def test_token_from_env_wins(tmp_path: Path) -> None:
    path = token_file(tmp_path, "from-file\n")
    assert read_token(path, {"PYDEBUPREP_TOKEN": "from-env"}) == "from-env"


def test_token_from_file(tmp_path: Path) -> None:
    assert read_token(token_file(tmp_path, f"{TOKEN}\n"), {}) == TOKEN


def test_missing_token(tmp_path: Path) -> None:
    missing = str(tmp_path / "token")
    with pytest.raises(PortalError) as exc:
        read_token(missing, {})
    assert str(exc.value) == (
        f"no upload token: set PYDEBUPREP_TOKEN or create {missing} (mode 0600)"
    )


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660])
def test_token_readable_by_others_refused(tmp_path: Path, mode: int) -> None:
    path = token_file(tmp_path, TOKEN, mode)
    with pytest.raises(PortalError) as exc:
        read_token(path, {})
    assert str(exc.value) == (f"{path} is readable by other users; run: chmod 600 {path}")


@pytest.mark.parametrize("text", ["", "\n", "two words", "tab\there", 'bad"quote', "é"])
def test_malformed_token_never_shown(tmp_path: Path, text: str) -> None:
    path = token_file(tmp_path, text)
    with pytest.raises(PortalError) as exc:
        read_token(path, {})
    assert "not a valid token" in str(exc.value) or "is empty" in str(exc.value)
    if text.strip():
        assert text.strip() not in str(exc.value)
    with pytest.raises(PortalError) as exc:
        read_token(path, {"PYDEBUPREP_TOKEN": text})
    assert "PYDEBUPREP_TOKEN" in str(exc.value)


def test_unreadable_token_file(tmp_path: Path) -> None:
    (tmp_path / "token").mkdir()
    with pytest.raises(PortalError, match="cannot read"):
        read_token(str(tmp_path / "token"), {})
    fifo = tmp_path / "fifo"
    import os

    os.mkfifo(fifo, 0o600)
    with pytest.raises(PortalError, match="not a regular file"):
        read_token(str(fifo), {})
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "token")
    with pytest.raises(PortalError, match="cannot read"):
        read_token(str(link), {})


# --- URLs ------------------------------------------------------------------


def test_http_needs_opt_in() -> None:
    with pytest.raises(PortalError, match=r"http:// is allowed only with --allow-http"):
        check_url("http://portal.example", False)
    check_url("http://portal.example", True)
    check_url("https://portal.example", False)


@pytest.mark.parametrize("url", ["ftp://p", "https://", "https://u:pw@p", "p.example"])
def test_bad_urls(url: str) -> None:
    with pytest.raises(PortalError, match=url.replace("+", r"\+")):
        check_url(url, True)


@pytest.mark.parametrize(
    ("a", "b", "same"),
    [
        ("https://P.example", "https://p.example:443/x", True),
        ("http://p.example/a", "http://p.example:80/b", True),
        ("https://p.example", "https://p.example:8443", False),
        ("https://p.example", "https://q.example", False),
        ("https://p.example", "http://p.example", False),
    ],
)
def test_same_origin(a: str, b: str, same: bool) -> None:
    assert same_origin(a, b) is same


# --- fetching a config ------------------------------------------------------


def test_fetch_sends_token_and_returns_text(portal: Portal) -> None:
    portal.route("GET", CONFIG_PATH, Reply(200, b"report: {}\n", {"ETag": '"v1"'}))
    assert fetch_config(portal.url + CONFIG_PATH, TOKEN, HTTP) == Fetched("report: {}\n", '"v1"')
    headers = portal.requests[0].headers
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    assert headers["User-Agent"] == f"pydebuprep/{__version__}"
    assert "If-None-Match" not in headers


def test_fetch_not_modified(portal: Portal) -> None:
    portal.route("GET", CONFIG_PATH, Reply(304, headers={"ETag": '"v1"'}))
    assert fetch_config(portal.url + CONFIG_PATH, TOKEN, HTTP, '"v1"') == Fetched(None, '"v1"')
    assert portal.requests[0].headers["If-None-Match"] == '"v1"'


def test_fetch_never_follows_redirects(portal: Portal) -> None:
    portal.route("GET", CONFIG_PATH, Reply(302, headers={"Location": "https://evil.example/"}))
    with pytest.raises(PortalError, match=r"redirect to https://evil\.example/ not followed"):
        fetch_config(portal.url + CONFIG_PATH, TOKEN, HTTP)
    assert len(portal.requests) == 1


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_fetch_http_error_shows_status_and_short_body(portal: Portal, status: int) -> None:
    portal.route("GET", CONFIG_PATH, Reply(status, b"<html>" + b"x" * 1000))
    with pytest.raises(PortalError) as exc:
        fetch_config(portal.url + CONFIG_PATH, TOKEN, HTTP)
    message = str(exc.value)
    assert f"HTTP {status}" in message
    assert len(message) < 400
    assert TOKEN not in message


def test_fetch_too_large(portal: Portal) -> None:
    portal.route("GET", CONFIG_PATH, Reply(200, b"x" * (MAX_CONFIG_BYTES + 1)))
    with pytest.raises(PortalError, match="larger than 1 MiB"):
        fetch_config(portal.url + CONFIG_PATH, TOKEN, HTTP)


def test_fetch_not_utf8(portal: Portal) -> None:
    portal.route("GET", CONFIG_PATH, Reply(200, b"\xff\xfe"))
    with pytest.raises(PortalError, match="not UTF-8"):
        fetch_config(portal.url + CONFIG_PATH, TOKEN, HTTP)


def test_fetch_times_out(portal: Portal) -> None:
    portal.route("GET", CONFIG_PATH, Reply(200, b"late", delay=3.0))
    start = time.monotonic()
    with pytest.raises(PortalError, match="timed out"):
        fetch_config(portal.url + CONFIG_PATH, TOKEN, Connection(allow_http=True, timeout=0.5))
    assert time.monotonic() - start < 2.5


def test_fetch_connection_refused() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with pytest.raises(PortalError, match=f"127.0.0.1:{port}"):
        fetch_config(f"http://127.0.0.1:{port}{CONFIG_PATH}", TOKEN, HTTP)


def test_fetch_checks_the_url_first() -> None:
    with pytest.raises(PortalError, match="--allow-http"):
        fetch_config("http://portal.example/x", TOKEN, Connection())


# --- uploading a report -----------------------------------------------------


@pytest.mark.parametrize("status", [200, 201])
def test_upload(portal: Portal, status: int) -> None:
    reply = json.dumps({"id": 7, "url": "https://p/reports/7"}).encode()
    portal.route("POST", REPORTS_PATH, Reply(status, reply))
    body = b'{"schema_version": "1"}'
    assert upload_report(portal.url + "/", TOKEN, HTTP, body) == "https://p/reports/7"
    sent = portal.requests[0]
    assert sent.path == "/api/v1/reports"
    assert sent.body == body
    assert sent.headers["Content-Type"] == "application/json"
    assert sent.headers["Content-Encoding"] == "gzip"
    assert sent.headers["Authorization"] == f"Bearer {TOKEN}"


def test_upload_under_a_base_path(portal: Portal) -> None:
    portal.route("POST", "/portal" + REPORTS_PATH, Reply(201, b"not json"))
    assert upload_report(portal.url + "/portal", TOKEN, HTTP, b"{}") == portal.url + "/portal"


def test_upload_is_compressed(portal: Portal) -> None:
    portal.route("POST", REPORTS_PATH, Reply(201, b"{}"))
    upload_report(portal.url, TOKEN, HTTP, b"a" * 10000)
    assert int(portal.requests[0].headers["Content-Length"]) < 1000
    assert gzip.decompress(gzip.compress(b"x")) == b"x"


@pytest.mark.parametrize("status", [413, 422, 503])
def test_upload_refused(portal: Portal, status: int) -> None:
    portal.route("POST", REPORTS_PATH, Reply(status, b'{"detail": "no"}'))
    with pytest.raises(PortalError, match=f"HTTP {status}"):
        upload_report(portal.url, TOKEN, HTTP, b"{}")


# --- TLS --------------------------------------------------------------------


@pytest.fixture
def tls_portal(tmp_path: Path) -> Iterator[tuple[Portal, str]]:
    if not shutil.which("openssl"):
        pytest.skip("openssl not installed")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-keyout", str(key), "-out", str(cert), "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True,
    )  # fmt: skip
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    with running_portal(tls=context) as portal:
        portal.route("GET", CONFIG_PATH, Reply(200, b"report: {}\n"))
        yield portal, str(cert)


def test_untrusted_certificate_fails(tls_portal: tuple[Portal, str]) -> None:
    portal, _ = tls_portal
    with pytest.raises(PortalError, match="certificate verify failed"):
        fetch_config(portal.url + CONFIG_PATH, TOKEN, Connection(timeout=5.0))
    assert portal.requests == []  # nothing, not even the token, was sent


def test_extra_ca_file_is_trusted(tls_portal: tuple[Portal, str]) -> None:
    portal, cert = tls_portal
    conn = Connection(ca_file=cert, timeout=5.0)
    assert fetch_config(portal.url + CONFIG_PATH, TOKEN, conn).text == "report: {}\n"


def test_unreadable_ca_file(tmp_path: Path) -> None:
    conn = Connection(ca_file=str(tmp_path / "missing.pem"))
    with pytest.raises(PortalError, match="cannot load CA file"):
        fetch_config("https://portal.example/x", TOKEN, conn)


# --- servers that misbehave --------------------------------------------------


def raw_server(reply: bytes) -> tuple[str, socket.socket]:
    """A one-shot server that sends REPLY and hangs up, whatever it was asked."""
    import threading

    listener = socket.create_server(("127.0.0.1", 0))

    def serve() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.recv(65536)
            conn.sendall(reply)

    threading.Thread(target=serve, daemon=True).start()
    return f"http://127.0.0.1:{listener.getsockname()[1]}", listener


def test_reply_cut_short() -> None:
    url, listener = raw_server(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nreport:")
    with listener, pytest.raises(PortalError, match=r"IncompleteRead|incomplete"):
        fetch_config(url + CONFIG_PATH, TOKEN, HTTP)


def test_not_http_at_all() -> None:
    url, listener = raw_server(b"SSH-2.0-OpenSSH_9.6\r\n")
    with listener, pytest.raises(PortalError, match=url.split("//")[1]):
        fetch_config(url + CONFIG_PATH, TOKEN, HTTP)


def test_connect_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    # A host that drops packets can't be simulated on 127.0.0.1; urllib reports a
    # connect timeout as URLError(reason=TimeoutError).
    import urllib.error

    from pydebuprep import portal as portal_module

    class Dropping:
        def open(self, *_: object, **__: object) -> None:
            raise urllib.error.URLError(TimeoutError("timed out"))

    monkeypatch.setattr(portal_module, "_opener", lambda conn: Dropping())
    with pytest.raises(PortalError, match="timed out after 30 s"):
        fetch_config("https://portal.example/x", TOKEN, Connection())


def test_connection_reset_while_reading(monkeypatch: pytest.MonkeyPatch) -> None:
    from pydebuprep import portal as portal_module

    class Resetting:
        def open(self, *_: object, **__: object) -> None:
            raise ConnectionResetError(104, "Connection reset by peer")

    monkeypatch.setattr(portal_module, "_opener", lambda conn: Resetting())
    with pytest.raises(PortalError, match="Connection reset by peer"):
        upload_report("https://portal.example", TOKEN, Connection(), b"{}")


def test_slow_trickle_hits_the_overall_timeout() -> None:
    import threading

    listener = socket.create_server(("127.0.0.1", 0))

    def trickle() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.recv(65536)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n")
            for _ in range(40):
                time.sleep(0.3)
                try:
                    conn.sendall(b"x")
                except OSError:
                    return

    threading.Thread(target=trickle, daemon=True).start()
    url = f"http://127.0.0.1:{listener.getsockname()[1]}{CONFIG_PATH}"
    start = time.monotonic()
    with listener, pytest.raises(PortalError, match="timed out after 1 s"):
        fetch_config(url, TOKEN, Connection(allow_http=True, timeout=1.0))
    assert time.monotonic() - start < 2.0


def test_deeply_nested_upload_reply_is_not_a_crash(portal: Portal) -> None:
    portal.route("POST", REPORTS_PATH, Reply(201, b"[" * 60000))
    assert upload_report(portal.url, TOKEN, HTTP, b"{}") == portal.url


def test_upload_needs_a_2xx_answer(portal: Portal) -> None:
    portal.route("POST", REPORTS_PATH, Reply(304))
    with pytest.raises(PortalError, match="HTTP 304"):
        upload_report(portal.url, TOKEN, HTTP, b"{}")
