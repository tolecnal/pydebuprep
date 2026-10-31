"""System against the real filesystem and process table (everything else uses FakeSystem)."""

from __future__ import annotations

import os
import socket
from datetime import timezone
from pathlib import Path

import pytest

from pydebuprep import system
from pydebuprep.system import System, _decode


def test_decode() -> None:
    assert _decode(None) == ""
    assert _decode("already text") == "already text"
    assert _decode(b"caf\xc3\xa9 \xff") == "café �"


def test_run_unexecutable_returns_126(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(system, "ALLOWED_COMMANDS", system.ALLOWED_COMMANDS | {(str(tmp_path),)})
    res = System().run([str(tmp_path)])  # a directory: exists, but can't be executed
    assert res.returncode == 126
    assert not res.ok


def test_file_queries(tmp_path: Path) -> None:
    f = tmp_path / "a.conf"
    f.write_text("x = 1\n")
    s = System()
    assert s.read_text(str(f)) == "x = 1\n"
    assert s.exists(str(f))
    assert not s.exists(str(tmp_path / "missing"))
    assert s.glob(str(tmp_path / "*.conf")) == [str(f)]
    assert s.mtime(str(f)) == pytest.approx(f.stat().st_mtime)
    assert s.mtime(str(tmp_path / "missing")) is None


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read every directory")
def test_walk_files_reports_unreadable_directories(tmp_path: Path) -> None:
    (tmp_path / "ok").mkdir()
    (tmp_path / "ok" / "f").write_text("")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "hidden").write_text("")
    locked.chmod(0)
    try:
        errors: list[str] = []
        files = list(System().walk_files(str(tmp_path), errors))
        assert files == [str(tmp_path / "ok" / "f")]
        assert errors == [f"{locked}: Permission denied"]
        assert list(System().walk_files(str(tmp_path))) == files  # errors ignored when no list
    finally:
        locked.chmod(0o700)


def test_disk_usage(tmp_path: Path) -> None:
    usage = System().disk_usage(str(tmp_path))
    assert usage is not None
    assert usage.total > 0
    assert 0 <= usage.free <= usage.total
    assert System().disk_usage(str(tmp_path / "missing")) is None


def test_which_identity_and_clock() -> None:
    s = System()
    assert s.which("sh")
    assert not s.which("no-such-command-pydebuprep")
    assert s.is_root() == (os.geteuid() == 0)
    assert s.hostname() == socket.gethostname()
    assert s.now().tzinfo is timezone.utc


def test_clock_synchronized_reads_kernel_state() -> None:
    assert System().clock_synchronized() in (True, False)


def test_clock_synchronized_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_libc(*a: object, **k: object) -> object:
        raise OSError("no libc")

    monkeypatch.setattr(system.ctypes, "CDLL", no_libc)
    assert System().clock_synchronized() is None


def test_clock_synchronized_error_state(monkeypatch: pytest.MonkeyPatch) -> None:
    class Libc:
        @staticmethod
        def adjtimex(buf: object) -> int:
            return -1

    monkeypatch.setattr(system.ctypes, "CDLL", lambda *a, **k: Libc())
    assert System().clock_synchronized() is None


def test_clock_unsynchronized(monkeypatch: pytest.MonkeyPatch) -> None:
    class Libc:
        @staticmethod
        def adjtimex(buf: object) -> int:
            return 5  # TIME_ERROR

    monkeypatch.setattr(system.ctypes, "CDLL", lambda *a, **k: Libc())
    assert System().clock_synchronized() is False


def test_loaded_modules() -> None:
    mods = System().loaded_modules()
    assert isinstance(mods, set)


def test_find_files_limits_depth_and_skips_symlinked_dirs(tmp_path: Path) -> None:
    (tmp_path / "a" / "b" / "c").mkdir(parents=True)
    (tmp_path / "a" / "pyvenv.cfg").write_text("")
    (tmp_path / "a" / "b" / "c" / "pyvenv.cfg").write_text("")
    (tmp_path / "link").symlink_to(tmp_path / "a")
    s = System()
    assert s.find_files([str(tmp_path)], "pyvenv.cfg", max_depth=1) == [
        str(tmp_path / "a" / "pyvenv.cfg")
    ]
    assert s.find_files([str(tmp_path), str(tmp_path / "missing")], "pyvenv.cfg", max_depth=5) == [
        str(tmp_path / "a" / "b" / "c" / "pyvenv.cfg"),
        str(tmp_path / "a" / "pyvenv.cfg"),
    ]


def test_python_version() -> None:
    import sys

    assert System().python_version() == f"{sys.version_info.major}.{sys.version_info.minor}"


def test_real_readlink(tmp_path: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to("target")
    assert System().readlink(str(link)) == "target"
    assert System().readlink(str(tmp_path / "missing")) is None


def test_scratch_dir_is_private_and_removed() -> None:
    system = System()
    with system.scratch_dir() as scratch:
        assert scratch.startswith("/tmp/pydebuprep-")
        assert os.stat(scratch).st_mode & 0o777 == 0o700
        path = system.write_scratch(scratch, "key.gpg", b"data")
        assert path == f"{scratch}/key.gpg"
        assert os.stat(path).st_mode & 0o777 == 0o600
        with open(path, "rb") as fh:
            assert fh.read() == b"data"
    assert not os.path.exists(scratch)


def test_write_scratch_refuses_other_directories(tmp_path: Path) -> None:
    system = System()
    with pytest.raises(ValueError, match="not a pydebuprep scratch directory"):
        system.write_scratch(str(tmp_path), "x", b"")
    with system.scratch_dir() as scratch:
        for name in ("../escape", "a/b", "", ".."):
            with pytest.raises(ValueError, match="plain file name"):
                system.write_scratch(scratch, name, b"")
        system.write_scratch(scratch, "once", b"")
        with pytest.raises(FileExistsError):
            system.write_scratch(scratch, "once", b"")
    with pytest.raises(ValueError, match="not a pydebuprep scratch directory"):
        system.write_scratch(scratch, "late", b"")  # removed already


def test_read_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "k.gpg").write_bytes(b"\x99\x00")
    assert System().read_bytes(str(tmp_path / "k.gpg")) == b"\x99\x00"
    assert System().read_bytes(str(tmp_path / "missing")) is None
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    assert System().read_bytes(str(fifo)) is None
    assert System().read_text(str(fifo)) is None
    monkeypatch.setattr(system, "MAX_READ_BYTES", 4)
    (tmp_path / "big").write_bytes(b"12345")
    assert System().read_bytes(str(tmp_path / "big")) is None


def test_read_range(tmp_path: Path) -> None:
    (tmp_path / "f").write_bytes(b"0123456789")
    assert System().read_range(str(tmp_path / "f"), 2, 3) == b"234"
    assert System().read_range(str(tmp_path / "f"), 8, 10) == b"89"
    assert System().read_range(str(tmp_path / "f"), -1, 3) is None
    assert System().read_range(str(tmp_path / "f"), 0, -1) is None
    assert System().read_range(str(tmp_path / "f"), 0, system.MAX_READ_BYTES + 1) is None
    assert System().read_range(str(tmp_path / "missing"), 0, 3) is None


def test_lines_streams_plain_and_gzip_files(tmp_path: Path) -> None:
    import gzip

    (tmp_path / "plain").write_text("a\nb\n")
    (tmp_path / "packed.gz").write_bytes(gzip.compress(b"c\nd\n"))
    (tmp_path / "broken.gz").write_bytes(b"not gzip at all")
    system = System()
    assert list(system.lines(str(tmp_path / "plain"))) == ["a\n", "b\n"]
    assert list(system.lines(str(tmp_path / "packed.gz"))) == ["c\n", "d\n"]
    assert list(system.lines(str(tmp_path / "broken.gz"))) == []
    assert list(system.lines(str(tmp_path / "missing"))) == []


def test_tcp_connect_and_http_get() -> None:
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(204 if self.path == "/ok" else 500)
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        system = System()
        assert system.tcp_connect("127.0.0.1", port, 3.0) is None
        assert system.http_get(f"http://127.0.0.1:{port}/ok", 3.0) == (204, None)
        assert system.http_get(f"http://127.0.0.1:{port}/bad", 3.0) == (500, None)
    finally:
        server.shutdown()
        server.server_close()
    assert system.tcp_connect("127.0.0.1", port, 3.0) is not None  # closed now
    status, error = system.http_get(f"http://127.0.0.1:{port}/ok", 3.0)
    assert status is None and error
    status, error = system.http_get("https://127.0.0.1:1/", 1.0)
    assert status is None and error


def test_tcp_connect_fails_when_the_peer_hangs_up_at_once() -> None:
    # Docker's userland proxy accepts every connection on a published port and closes it
    # at once when nothing listens behind it; a working service waits or greets.
    import threading

    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def hang_up() -> None:
        conn, _ = listener.accept()
        conn.close()

    threading.Thread(target=hang_up, daemon=True).start()
    try:
        error = System().tcp_connect("127.0.0.1", port, 3.0)
    finally:
        listener.close()
    assert error is not None and "closed" in error


def test_tcp_connect_accepts_a_greeting() -> None:
    import threading

    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def greet() -> None:
        conn, _ = listener.accept()
        conn.sendall(b"220 ready\r\n")
        conn.close()

    threading.Thread(target=greet, daemon=True).start()
    try:
        assert System().tcp_connect("127.0.0.1", port, 3.0) is None
    finally:
        listener.close()


def test_client_environment_is_not_passed_to_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(system, "ALLOWED_COMMANDS", system.ALLOWED_COMMANDS | {("env",)})
    monkeypatch.setenv("PGSSLKEYLOGFILE", "/tmp/keys")
    monkeypatch.setenv("MYSQL_PWD", "secret")
    monkeypatch.setenv("MARIADB_HOST", "evil.example")
    monkeypatch.setenv("APT_CONFIG", "/tmp/apt.conf")
    monkeypatch.setenv("DOCKER_HOST", "tcp://evil.example:2375")
    monkeypatch.setenv("KEEP_ME", "1")
    out = System().run(["env"]).stdout
    assert "KEEP_ME=1" in out
    for var in ("PGSSLKEYLOGFILE", "MYSQL_PWD", "MARIADB_HOST", "APT_CONFIG", "DOCKER_HOST"):
        assert var not in out


def test_http_get_with_a_bad_port_is_an_error() -> None:
    status, error = System().http_get("http://localhost:99999/", 1.0)
    assert status is None and error


def test_a_file_swapped_for_a_fifo_after_the_check_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    regular = os.lstat(__file__)
    real_lstat = os.lstat
    # The type check sees a regular file; by the time it is opened it is a FIFO.
    monkeypatch.setattr(
        system.os, "lstat", lambda p: regular if str(p) == str(fifo) else real_lstat(p)
    )
    assert System().read_bytes(str(fifo)) is None
