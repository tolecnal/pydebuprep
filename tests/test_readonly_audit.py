"""The strace analyser behind scripts/readonly-audit.sh must catch real changes."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "readonly-audit.py"
EXEC = '100 execve("/usr/bin/apt-mark", ["apt-mark", "showhold"], 0x7ffd /* 3 vars */) = 0\n'


def audit(tmp_path: Path, trace: str, *allow: str) -> tuple[int, str]:
    log = tmp_path / "t.strace"
    log.write_text(EXEC + trace)
    args = [a for p in allow for a in ("--allow", p)]
    res = subprocess.run(
        [sys.executable, str(SCRIPT), str(log), *args], capture_output=True, text=True, check=False
    )
    return res.returncode, res.stdout


@pytest.mark.parametrize(
    "trace",
    [
        '100 openat(AT_FDCWD, "/var/cache/apt/pkgcache.bin", O_RDWR|O_CREAT|O_TRUNC, 0644) = 3\n',
        '100 openat(AT_FDCWD, "/etc/passwd", O_WRONLY|O_APPEND) = 3\n',
        '100 unlink("/var/lib/dpkg/lock") = 0\n',
        '100 rename("/etc/a", "/etc/b") = 0\n',
        '100 chmod("/etc/shadow", 0644) = 0\n',
        "100 kill(1234, SIGTERM) = 0\n",
        '100 mkdir("/var/lib/x", 0755) = 0\n',
        '100 openat(AT_FDCWD, "/tmp/leftover", O_RDWR|O_CREAT|O_EXCL, 0600) = 3\n',
        '100 mount("/dev/sda1", "/mnt", "ext4", 0, NULL) = 0\n',
        '100 openat(AT_FDCWD, "/var/lib/pydebuprep/snapshots/x.json", O_WRONLY|O_CREAT, 0666) = 3\n',
    ],
)
def test_changes_are_violations(tmp_path: Path, trace: str) -> None:
    rc, out = audit(tmp_path, trace)
    assert rc == 1, out
    assert "VIOLATION" in out
    assert "apt-mark" in out  # attributed to the program that did it


@pytest.mark.parametrize(
    "trace",
    [
        '100 openat(AT_FDCWD, "/tmp/x", O_RDWR|O_CREAT|O_EXCL, 0600) = 3\n100 unlink("/tmp/x") = 0\n',
        '100 openat(AT_FDCWD, "/tmp", O_RDWR|O_EXCL|O_TMPFILE, 0600) = 4\n',
        '100 openat(AT_FDCWD, "/dev/null", O_RDWR) = 3\n',
        "100 kill(1234, 0) = 0\n",
        '100 openat(AT_FDCWD, "/etc/shadow", O_RDONLY|O_CLOEXEC) = 3\n',
        '100 openat(AT_FDCWD, "/var/cache/apt/pkgcache.bin", O_RDWR|O_CREAT, 0644) = -1 EACCES (Permission denied)\n',
    ],
)
def test_harmless_activity_passes(tmp_path: Path, trace: str) -> None:
    rc, out = audit(tmp_path, trace)
    assert rc == 0, out


def test_allowed_prefix(tmp_path: Path) -> None:
    trace = (
        '100 openat(AT_FDCWD, "/var/lib/pydebuprep/snapshots/x.json", O_WRONLY|O_CREAT, 0666) = 3\n'
    )
    assert audit(tmp_path, trace, "/var/lib/pydebuprep/snapshots")[0] == 0


def test_unfinished_and_resumed_calls(tmp_path: Path) -> None:
    trace = (
        '100 openat(AT_FDCWD, "/etc/motd", O_WRONLY|O_TRUNC <unfinished ...>\n'
        "100 <... openat resumed>) = 3\n"
    )
    assert audit(tmp_path, trace)[0] == 1
