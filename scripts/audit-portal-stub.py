#!/usr/bin/env python3
"""A stand-in pydebuprep portal for the read-only audit (CI only).

Serves one config at /api/v1/configs/audit/default and refuses every upload with 503,
so an audited report run both saves a copy of its config and keeps a pending report.
Usage: audit-portal-stub.py URL_FILE   (writes the config URL to URL_FILE, then serves)
"""

from __future__ import annotations

import http.server
import json
import sys

CONFIG_PATH = "/api/v1/configs/audit/default"


def main(url_file: str) -> None:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    # debsums reads every packaged file; the plain report run already covers it.
    Handler.config = f"upload:\n  url: {base}\nchecks:\n  debsums:\n    enabled: false\n"
    with open(url_file, "w", encoding="utf-8") as fh:
        fh.write(base + CONFIG_PATH + "\n")
    server.serve_forever()


class Handler(http.server.BaseHTTPRequestHandler):
    config = ""

    def _reply(self, status: int, body: bytes, kind: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == CONFIG_PATH:
            self._reply(200, self.config.encode(), "application/yaml")
        else:
            self._reply(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        body = json.dumps({"detail": "uploads are refused, so the report is kept"}).encode()
        self._reply(503, body, "application/json")

    def log_message(self, *args: object) -> None:
        pass


if __name__ == "__main__":
    main(sys.argv[1])
