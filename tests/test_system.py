from __future__ import annotations

import pytest

from fakes import FakeSystem
from pydebuprep import system
from pydebuprep.system import (
    APT_RO_OPTS,
    SHOW_UNITS,
    DisallowedCommandError,
    System,
    check_allowed,
)


def _allow(monkeypatch: pytest.MonkeyPatch, *argvs: tuple[str, ...]) -> None:
    monkeypatch.setattr(system, "ALLOWED_COMMANDS", system.ALLOWED_COMMANDS | set(argvs))


def test_check_allowed_accepts_exact_commands() -> None:
    check_allowed(("apt", *APT_RO_OPTS, "list", "--upgradable"))
    check_allowed(("systemd-analyze",))
    check_allowed(("systemd-analyze", "blame", "--no-pager"))
    check_allowed(
        ("systemctl", "show", "-p", "UnitFileState", "-p", "ConditionResult", "cron.timer")
    )


@pytest.mark.parametrize(
    "argv",
    [
        ("apt", "update"),
        ("apt", *APT_RO_OPTS, "update"),
        ("apt-get", "install", "x"),
        ("update-grub",),
        ("systemctl", "restart", "ssh"),
        ("systemd-analyze", "set-log-level", "debug"),
        ("systemd-analyze", "blame", "--no-pager", "extra"),
        ("sh", "-c", "ls"),
        (),
        # Trailing arguments after a once-allowed prefix must not slip through.
        ("journalctl", "-p", "3", "--vacuum-size=1K"),
        ("journalctl", "-p", "err", "-b", "--no-pager", "-o", "json", "--rotate"),
        ("dmesg", "--level=err", "--clear"),
        ("dmesg", "--level=warn", "-c"),
        ("dmesg", "--level=err", "--notime", "-n", "1"),
        ("efibootmgr", "-v", "-B", "-b", "0000"),
        ("efibootmgr", "-v", "-o", "0001,0000"),
        ("apt-get", *APT_RO_OPTS, "-s", "autoremove", "--no-simulate", "-y"),
        ("apt-get", *APT_RO_OPTS, "-s", "autoremove", "-o", "APT::Get::Simulate=0"),
        ("apt-cache", *APT_RO_OPTS, "policy", "-o", "Dir::Cache::pkgcache=/etc/x"),
        ("apt-get", "check"),  # missing the read-only apt options
        ("apt-mark", "showhold"),  # apt-mark rebuilds pkgcache.bin as root without them
        ("apt", "list", "--upgradable"),
        ("debsums", "-c", "--generate=all"),
        ("dkms", "status", "install", "-m", "x", "-v", "1"),
        ("needrestart", "-b", "-r", "l", "-r", "a"),
        ("systemctl", "list-units", "--state=failed", "--no-legend", "--plain", "--no-pager", "x"),
        ("systemctl", "show", "-p", "UnitFileState", "-p", "ConditionResult", "--now", "x"),
        ("systemctl", "show", "-p", "UnitFileState", "-p", "ConditionResult", "a", "b"),
        ("systemctl", "show", "-p", "UnitFileState", "-p", "ConditionResult", "-H"),
    ],
)
def test_check_allowed_rejects_writes(argv: tuple[str, ...]) -> None:
    with pytest.raises(DisallowedCommandError):
        check_allowed(argv)


def test_run_rejects_disallowed() -> None:
    with pytest.raises(DisallowedCommandError):
        System().run(["apt", "update"])


def test_run_timeout_returns_result(monkeypatch: pytest.MonkeyPatch) -> None:
    _allow(monkeypatch, ("sleep", "5"))
    res = System().run(["sleep", "5"], timeout=0.1)
    assert res.timed_out
    assert not res.ok


def test_run_missing_binary_returns_127(monkeypatch: pytest.MonkeyPatch) -> None:
    _allow(monkeypatch, ("no-such-binary-pydebuprep",))
    res = System().run(["no-such-binary-pydebuprep"])
    assert res.returncode == 127
    assert not res.ok


def test_run_decodes_invalid_utf8(monkeypatch: pytest.MonkeyPatch) -> None:
    _allow(monkeypatch, ("printf", "\\377ok"))
    res = System().run(["printf", "\\377ok"])
    assert res.stdout.endswith("ok")
    assert "�" in res.stdout


def test_run_sets_c_locale(monkeypatch: pytest.MonkeyPatch) -> None:
    _allow(monkeypatch, ("env",))
    assert "LC_ALL=C" in System().run(["env"]).stdout


def test_read_text_missing_returns_none(tmp_path: pytest.TempPathFactory) -> None:
    assert System().read_text("/nonexistent/pydebuprep") is None


def test_walk_files_collects_errors(tmp_path) -> None:  # type: ignore[no-untyped-def]
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "f.dpkg-new").write_text("x")
    errors: list[str] = []
    files = list(System().walk_files(str(tmp_path), errors))
    assert files == [str(tmp_path / "a" / "f.dpkg-new")]
    assert errors == []


def test_apt_never_writes_its_solver_log() -> None:
    # Without it, `apt-get -s autoremove` as root replaces /var/log/apt/eipp.log.xz.
    opts = list(zip(APT_RO_OPTS[::2], APT_RO_OPTS[1::2], strict=True))
    assert ("-o", "Dir::Log::Planner=") in opts


def test_show_units_allows_unit_names() -> None:
    check_allowed((*SHOW_UNITS, "ssh.service", "cron.service"))
    check_allowed((*SHOW_UNITS, "getty@tty1.service"))


@pytest.mark.parametrize(
    "operands",
    [(), ("-H",), ("a;b",), tuple(f"u{i}.service" for i in range(257))],
)
def test_show_units_rejects_bad_operands(operands: tuple[str, ...]) -> None:
    with pytest.raises(DisallowedCommandError):
        check_allowed((*SHOW_UNITS, *operands))


def test_show_units_requires_the_separator() -> None:
    with pytest.raises(DisallowedCommandError):
        check_allowed((*SHOW_UNITS[:-1], "ssh.service"))


def test_fake_readlink_and_glob() -> None:
    fake = FakeSystem(links={"/proc/1/fd/3": "socket:[42]"})
    assert fake.readlink("/proc/1/fd/3") == "socket:[42]"
    assert fake.readlink("/proc/1/fd/4") is None
    assert fake.glob("/proc/1/fd/*") == ["/proc/1/fd/3"]


INRELEASE = "/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease"
KEY = "/usr/share/keyrings/debian-archive-keyring.gpg"
SCRATCH = "/tmp/pydebuprep-abc123"


@pytest.mark.parametrize(
    "argv",
    [
        ("sqv", "--keyring", KEY, "--cleartext", "--output", f"{SCRATCH}/out-1", INRELEASE),
        (
            "sqv", "--keyring", KEY, "--keyring", "/etc/apt/trusted.gpg.d/x.asc",
            "--keyring", f"{SCRATCH}/inline-1.asc", "--cleartext", "--output",
            f"{SCRATCH}/out-2", INRELEASE,
        ),
        ("gpgv", "--keyring", KEY, INRELEASE),
        ("gpgv", "--keyring", "/etc/apt/keyrings/v.gpg", "--keyring", f"{SCRATCH}/k-1.gpg", INRELEASE),
    ],
)  # fmt: skip
def test_signature_checks_allowed(argv: tuple[str, ...]) -> None:
    check_allowed(argv)


@pytest.mark.parametrize(
    "argv",
    [
        ("gpgv", INRELEASE),  # no keyring
        ("gpgv", "--keyring", KEY),  # no file to verify
        ("gpgv", "--keyring", "/home/u/k.gpg", INRELEASE),  # keyring elsewhere
        ("gpgv", "--keyring", "/etc/apt/../shadow", INRELEASE),
        ("gpgv", "--keyring", KEY, "/etc/passwd"),
        ("gpgv", "--keyring", KEY, "/var/lib/apt/lists/x_Release"),
        ("gpgv", "--keyring", KEY, "/var/lib/apt/lists/sub/x_InRelease"),
        ("gpgv", "--keyring", KEY, "--homedir", "/tmp", INRELEASE),
        ("gpgv", "--keyring", "/tmp/pydebuprep-x/../../etc/k", INRELEASE),
        ("gpgv", "--keyring", "/tmp/elsewhere/k.gpg", INRELEASE),
        ("sqv", "--keyring", KEY, "--cleartext", "--output", "/etc/apt/out", INRELEASE),
        ("sqv", "--keyring", KEY, "--cleartext", "--output", "-", INRELEASE),
        ("sqv", "--keyring", KEY, "--cleartext", "--output", f"{SCRATCH}/a/b", INRELEASE),
        ("sqv", "--keyring", KEY, "--output", f"{SCRATCH}/out", INRELEASE),  # no --cleartext
        ("sqv", "--keyring", KEY, "--cleartext", INRELEASE),
    ],
)
def test_signature_checks_rejected(argv: tuple[str, ...]) -> None:
    with pytest.raises(DisallowedCommandError):
        check_allowed(argv)


def test_fake_scratch_dir() -> None:
    fake = FakeSystem()
    with fake.scratch_dir() as scratch:
        path = fake.write_scratch(scratch, "k.gpg", b"\x99")
        assert fake.scratch_files == {path: b"\x99"}
    assert scratch == "/tmp/pydebuprep-test"


SOCK = "/var/run/postgresql"
PSQL_AS_POSTGRES = (
    "setpriv", "--reuid=postgres", "--regid=postgres", "--init-groups", "--",
    "psql", "-X", "-A", "-t", "-w", "-h", SOCK, "-p", "5432", "-d", "postgres", "-c", "SELECT 1",
)  # fmt: skip
CONNINFO = f"host={SOCK} port=5433 dbname=postgres user=monitor passfile=/etc/pydebuprep/pgpass"


@pytest.mark.parametrize(
    "argv",
    [
        ("pg_isready", "-h", SOCK, "-p", "5432"),
        PSQL_AS_POSTGRES,
        ("psql", "-X", "-A", "-t", "-w", "-d", CONNINFO, "-c", "SELECT 1"),
        ("mariadb-admin", "ping"),
        ("mysqladmin", "--defaults-extra-file=/etc/mysql/debian.cnf", "ping"),
        ("mariadb", "-N", "-B", "-e", "SELECT 1", "information_schema"),
        ("mysql", "--defaults-extra-file=/root/.my.cnf", "-N", "-B", "-e", "SELECT 1", "information_schema"),
    ],
)  # fmt: skip
def test_probe_commands_allowed(argv: tuple[str, ...]) -> None:
    check_allowed(argv)


@pytest.mark.parametrize(
    "argv",
    [
        ("pg_isready", "-h", SOCK, "-p", "5432; rm"),
        ("pg_isready", "-h", "/tmp", "-p", "5432"),
        (*PSQL_AS_POSTGRES[:-1], "DROP TABLE x"),
        tuple("--reuid=root" if a == "--reuid=postgres" else a for a in PSQL_AS_POSTGRES),
        tuple("99x" if a == "5432" else a for a in PSQL_AS_POSTGRES),
        ("psql", "-X", "-A", "-t", "-w", "-d", CONNINFO + " sslmode=disable", "-c", "SELECT 1"),
        ("psql", "-X", "-A", "-t", "-w", "-d", CONNINFO.replace("monitor", "a b"), "-c", "SELECT 1"),
        ("psql", "-X", "-A", "-t", "-w", "-d", CONNINFO.replace("/etc/pydebuprep/pgpass", "../x"), "-c", "SELECT 1"),
        ("mariadb-admin", "shutdown"),
        ("mariadb-admin", "ping", "--force"),
        ("mysqladmin", "--defaults-extra-file=relative.cnf", "ping"),
        ("mysqladmin", "--defaults-file=/etc/x.cnf", "ping"),
        ("mariadb", "-N", "-B", "-e", "DROP DATABASE x", "information_schema"),
        ("mariadb", "-N", "-B", "-e", "SELECT 1", "mysql"),
    ],
)  # fmt: skip
def test_probe_commands_rejected(argv: tuple[str, ...]) -> None:
    with pytest.raises(DisallowedCommandError):
        check_allowed(argv)


def test_fake_network() -> None:
    fake = FakeSystem(ports={("127.0.0.1", 8080)}, http={"http://127.0.0.1:8080/h": 503})
    assert fake.tcp_connect("127.0.0.1", 8080, 3.0) is None
    assert fake.tcp_connect("127.0.0.1", 9090, 3.0) == "Connection refused"
    assert fake.http_get("http://127.0.0.1:8080/h", 3.0) == (503, None)
    assert fake.http_get("http://127.0.0.1:9/x", 3.0) == (None, "Connection refused")
