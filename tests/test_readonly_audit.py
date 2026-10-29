"""The strace analyser behind scripts/readonly-audit.sh must catch real changes."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "readonly-audit.py"
EXEC = '100 execve("/usr/bin/apt-mark", ["apt-mark", "showhold"], 0x7ffd /* 3 vars */) = 0\n'


def audit(tmp_path: Path, trace: str, *allow: str, strict: str = "") -> tuple[int, str]:
    log = tmp_path / "t.strace"
    log.write_text(EXEC + trace)
    args = [a for p in allow for a in ("--allow", p)]
    args += ["--strict", strict] if strict else []
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
        '100 mkdir("/tmp/leftover.d", 0700) = 0\n',
        '100 rmdir("/tmp/not-ours") = 0\n',
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
        '100 mkdir("/tmp/YENoEJqPuA", 0700) = 0\n100 rmdir("/tmp/YENoEJqPuA") = 0\n',
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


def test_adjtimex_read_allowed_but_changes_flagged(tmp_path: Path) -> None:
    read = "100 adjtimex({modes=0, offset=0, freq=0, status=STA_PLL}) = 0 (TIME_OK)\n"
    assert audit(tmp_path, read)[0] == 0
    change = "100 adjtimex({modes=ADJ_OFFSET|ADJ_FREQUENCY, offset=5}) = 0 (TIME_OK)\n"
    assert audit(tmp_path, change)[0] == 1
    glibc_read = (
        "100 clock_adjtime(CLOCK_REALTIME, {modes=0, offset=-3, status=STA_PLL}) = 0 (TIME_OK)\n"
    )
    assert audit(tmp_path, glibc_read)[0] == 0
    glibc_change = "100 clock_adjtime(CLOCK_REALTIME, {modes=ADJ_SETOFFSET, time={tv_sec=1}}) = 0\n"
    assert audit(tmp_path, glibc_change)[0] == 1


def test_signals_within_the_traced_run_are_allowed(tmp_path: Path) -> None:
    # Go programs (docker) preempt their own threads with SIGURG.
    trace = (
        "201 tgkill(200, 202, SIGURG) = 0\n200 kill(201, SIGTERM) = 0\n202 kill(200, SIGCHLD) = 0\n"
    )
    assert audit(tmp_path, trace)[0] == 0


def test_signals_to_other_processes_are_flagged(tmp_path: Path) -> None:
    rc, out = audit(tmp_path, "100 tgkill(4242, 4242, SIGURG) = 0\n")
    assert rc == 1
    assert "tgkill(4242" in out


def test_failed_write_attempts_count_under_strict_prefixes(tmp_path: Path) -> None:
    efivar = "/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    write = f'100 openat(AT_FDCWD, "{efivar}", O_WRONLY) = -1 EPERM (Operation not permitted)\n'
    unlink = f'100 unlink("{efivar}") = -1 EPERM (Operation not permitted)\n'
    read = f'100 openat(AT_FDCWD, "{efivar}", O_RDONLY) = -1 ENOENT (No such file or directory)\n'
    strict = "/sys/firmware/efi/efivars"
    assert audit(tmp_path, write)[0] == 0
    rc, out = audit(tmp_path, write, strict=strict)
    assert rc == 1
    assert "(failed attempt)" in out
    assert audit(tmp_path, unlink, strict=strict)[0] == 1
    assert audit(tmp_path, read, strict=strict)[0] == 0
    elsewhere = '100 openat(AT_FDCWD, "/etc/x", O_WRONLY) = -1 EACCES (Permission denied)\n'
    assert audit(tmp_path, elsewhere, strict=strict)[0] == 0


def test_scratch_files_removed_through_a_directory_fd_are_cleaned_up(tmp_path: Path) -> None:
    # shutil.rmtree opens the directory and unlinks entries relative to its descriptor.
    trace = (
        '100 mkdir("/tmp/pydebuprep-x1", 0700) = 0\n'
        '100 openat(AT_FDCWD, "/tmp/pydebuprep-x1/key-0.gpg", O_WRONLY|O_CREAT|O_EXCL, 0600) = 4\n'
        '100 openat(AT_FDCWD, "/tmp/pydebuprep-x1", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3\n'
        '100 unlinkat(3, "key-0.gpg", 0) = 0\n'
        '100 rmdir("/tmp/pydebuprep-x1") = 0\n'
    )
    rc, out = audit(tmp_path, trace)
    assert rc == 0, out


def test_relative_unlink_outside_tmp_is_still_a_violation(tmp_path: Path) -> None:
    trace = (
        '100 openat(AT_FDCWD, "/etc", O_RDONLY|O_DIRECTORY) = 3\n'
        '100 unlinkat(3, "passwd", 0) = 0\n'
        '100 unlinkat(9, "unknown-fd", 0) = 0\n'
    )
    rc, out = audit(tmp_path, trace)
    assert rc == 1
    assert out.count("VIOLATION") == 2
