"""A stand-in pydebuprep portal for tests: a real HTTP server on 127.0.0.1."""

from __future__ import annotations

import gzip
import http.server
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field


@dataclass
class Request:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes  # decompressed when sent with Content-Encoding: gzip


@dataclass
class Reply:
    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    delay: float = 0.0


Route = Callable[[Request], Reply]


@dataclass
class Portal:
    url: str
    routes: dict[tuple[str, str], Route | Reply] = field(default_factory=dict)
    requests: list[Request] = field(default_factory=list)

    def route(self, method: str, path: str, reply: Route | Reply) -> None:
        self.routes[(method, path)] = reply


def _handler(portal: Portal) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def _serve(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            if self.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
            request = Request(method, self.path, dict(self.headers.items()), body)
            portal.requests.append(request)
            route = portal.routes.get((method, self.path), Reply(404, b"not found"))
            reply = route if isinstance(route, Reply) else route(request)
            time.sleep(reply.delay)
            try:
                self.send_response(reply.status)
                for name, value in reply.headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(reply.body)))
                self.end_headers()
                self.wfile.write(reply.body)
            except OSError:
                pass  # the client gave up (a timeout test)

        def do_GET(self) -> None:
            self._serve("GET")

        def do_POST(self) -> None:
            self._serve("POST")

        def log_message(self, *args: object) -> None:
            pass

    return Handler


@contextmanager
def running_portal(*, tls: ssl.SSLContext | None = None) -> Iterator[Portal]:
    """A portal on a free port; with TLS, on https:// using that server context."""
    portal = Portal("")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(portal))
    server.daemon_threads = True
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    scheme = "https" if tls is not None else "http"
    portal.url = f"{scheme}://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        yield portal
    finally:
        server.shutdown()
        server.server_close()
