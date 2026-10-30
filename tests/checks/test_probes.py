"""Opt-in readiness probes: postgresql, mariadb (and MySQL), docker."""

from __future__ import annotations

import json
from typing import Any

import pytest

from pydebuprep.checks._systemd import ACTIVE_SERVICES
from pydebuprep.checks.docker import DOCKER_PS, DockerCheck
from pydebuprep.checks.postgresql import PG_LSCLUSTERS, PostgresqlCheck
from pydebuprep.model import Severity
from pydebuprep.system import CommandResult

from .helpers import make_ctx, titles

# --- postgresql ----------------------------------------------------------------------

SOCK = "/var/run/postgresql"
SERVER = {"/usr/lib/postgresql/17/bin/postgres": "", "/var/run/postgresql/.s.PGSQL.5432": ""}


def cluster(name: str, port: str, status: str = "online") -> str:
    return f"17 {name} {port} {status} postgres /var/lib/postgresql/17/{name} /var/log/x.log\n"


def isready(port: str) -> tuple[str, ...]:
    return ("pg_isready", "-h", SOCK, "-p", port)


def query(port: str) -> tuple[str, ...]:
    return (
        "setpriv", "--reuid=postgres", "--regid=postgres", "--init-groups", "--",
        "psql", "-X", "-A", "-t", "-w", "-h", SOCK, "-p", port, "-d", "postgres",
        "-c", "SELECT 1",
    )  # fmt: skip


def pg(commands: dict[tuple[str, ...], Any], clusters: str = "", **kw: Any) -> list[Any]:
    opts = kw.pop("opts", {"probe": True})
    ctx = make_ctx(
        commands={PG_LSCLUSTERS: clusters or cluster("main", "5432"), **commands},
        files={**SERVER, **kw.pop("files", {})},
        **kw,
    )
    return PostgresqlCheck(opts).run(ctx)


def test_pg_probe_off_by_default_runs_nothing() -> None:
    assert pg({}, opts={}) == []  # strict FakeSystem: no probe command was run


def test_pg_cluster_answering_has_no_findings() -> None:
    assert pg({isready("5432"): "accepting connections\n", query("5432"): "1\n"}) == []


def test_pg_cluster_not_accepting_connections() -> None:
    res = CommandResult(isready("5432"), 2, "/var/run/postgresql:5432 - no response\n", "")
    (f,) = pg({isready("5432"): res})
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "PostgreSQL cluster 17/main doesn't accept connections",
    )
    assert f.evidence == ["/var/run/postgresql:5432 - no response"]


def test_pg_cluster_accepting_but_not_answering() -> None:
    bad = CommandResult(
        query("5432"), 2, "", "psql: error: FATAL:  the database system is in recovery mode\n"
    )
    (f,) = pg({isready("5432"): "accepting\n", query("5432"): bad})
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "PostgreSQL cluster 17/main accepts connections but doesn't answer queries",
    )
    assert f.evidence == ["psql: error: FATAL:  the database system is in recovery mode"]


def test_pg_login_failure_is_info() -> None:
    denied = CommandResult(
        query("5432"),
        2,
        "",
        'psql: error: FATAL:  Peer authentication failed for user "postgres"\n',
    )
    (f,) = pg({isready("5432"): "accepting\n", query("5432"): denied})
    assert (f.severity, f.title) == (
        Severity.INFO,
        "Couldn't log in to PostgreSQL cluster 17/main to probe it",
    )


def test_pg_timeout_counts_as_not_answering() -> None:
    slow = CommandResult(query("5432"), -1, "", "", True)
    assert titles(pg({isready("5432"): "accepting\n", query("5432"): slow})) == [
        "PostgreSQL cluster 17/main accepts connections but doesn't answer queries"
    ]


def test_pg_down_clusters_are_not_probed() -> None:
    clusters = cluster("main", "5432") + cluster("old", "5433", "down")
    files = {"/etc/postgresql/17/old/start.conf": "manual\n"}
    assert pg({isready("5432"): "ok\n", query("5432"): "1\n"}, clusters, files=files) == []


def test_pg_credentials_file() -> None:
    pgpass = "# monitoring\n*:*:*:monitor:secret\n"
    conninfo = f"host={SOCK} port=5432 dbname=postgres user=monitor passfile=/etc/pydebuprep/pgpass"
    psql = ("psql", "-X", "-A", "-t", "-w", "-d", conninfo, "-c", "SELECT 1")
    opts = {"probe": True, "credentials_file": "/etc/pydebuprep/pgpass"}
    assert (
        pg(
            {isready("5432"): "ok\n", psql: "1\n"},
            opts=opts,
            files={"/etc/pydebuprep/pgpass": pgpass},
        )
        == []
    )
    (f,) = pg({isready("5432"): "ok\n"}, opts=opts, files={"/etc/pydebuprep/pgpass": "# empty\n"})
    assert (f.severity, f.title) == (
        Severity.INFO,
        "Can't use the PostgreSQL credentials file /etc/pydebuprep/pgpass",
    )
    (f,) = pg({isready("5432"): "ok\n"}, opts=opts)  # unreadable or missing
    assert f.title == "Can't use the PostgreSQL credentials file /etc/pydebuprep/pgpass"


def test_pg_credentials_file_must_be_absolute() -> None:
    with pytest.raises(ValueError, match="credentials_file"):
        PostgresqlCheck({"credentials_file": "pgpass"})


def test_pg_probe_needs_root() -> None:
    (f,) = pg({}, root=False)
    assert (f.severity, f.title) == (Severity.INFO, "Readiness probes need root; not run")


# --- mariadb / mysql -----------------------------------------------------------------

from pydebuprep.checks.mariadb import MARIADBD_VERSION, MariaDbCheck  # noqa: E402
from pydebuprep.model import Status  # noqa: E402
from pydebuprep.runner import run_check  # noqa: E402

MARIADB_VERSION = (
    "mariadbd  Ver 11.8.6-MariaDB-0+deb13u1 from Debian for debian-linux-gnu on x86_64\n"
)
PING = ("mariadb-admin", "ping")
SELECT = ("mariadb", "-N", "-B", "-e", "SELECT 1", "information_schema")
MARIADB = {"mariadbd", "mariadb-admin", "mariadb"}
MYSQL_UP = "mysql.service loaded active running x\n"


def db(commands: dict[tuple[str, ...], Any], available: set[str] = MARIADB, **kw: Any) -> list[Any]:
    opts = kw.pop("opts", {"probe": True})
    running = {ACTIVE_SERVICES: "mariadb.service loaded active running x\n"}
    ctx = make_ctx(
        commands={MARIADBD_VERSION: MARIADB_VERSION, **running, **commands},
        available=available,
        **kw,
    )
    return MariaDbCheck(opts).run(ctx)


def test_db_probe_off_by_default() -> None:
    assert db({}, opts={}) == []


def test_db_answering_has_no_findings() -> None:
    assert db({PING: "mysqld is alive\n", SELECT: "1\n"}) == []


def test_db_not_answering_ping() -> None:
    down = CommandResult(
        PING,
        1,
        "",
        "mariadb-admin: connect to server at 'localhost' failed\nerror: 'Can't connect to local server through socket '/run/mysqld/mysqld.sock' (2)'\n",
    )
    (f,) = db({PING: down})
    assert (f.severity, f.title) == (Severity.WARNING, "The MariaDB server doesn't answer")
    assert "Can't connect to local server" in f.evidence[1]


def test_db_ping_but_no_query() -> None:
    bad = CommandResult(SELECT, 1, "", "ERROR 1030 (HY000): Got error 1 from storage engine\n")
    (f,) = db({PING: "mysqld is alive\n", SELECT: bad})
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "The MariaDB server answers but doesn't run queries",
    )


@pytest.mark.parametrize("failing", ["ping", "query"])
def test_db_access_denied_is_info(failing: str) -> None:
    denied = "ERROR 1045 (28000): Access denied for user 'root'@'localhost'\n"
    commands: dict[tuple[str, ...], Any] = {PING: "mysqld is alive\n", SELECT: "1\n"}
    key = PING if failing == "ping" else SELECT
    commands[key] = CommandResult(key, 1, "", denied)
    (f,) = db(commands)
    assert (f.severity, f.title) == (
        Severity.INFO,
        "Couldn't log in to the MariaDB server to probe it",
    )


def test_db_credentials_file_comes_first() -> None:
    opt = "--defaults-extra-file=/etc/mysql/debian.cnf"
    opts = {"probe": True, "credentials_file": "/etc/mysql/debian.cnf"}
    commands = {("mariadb-admin", opt, "ping"): "alive\n", ("mariadb", opt, *SELECT[1:]): "1\n"}
    assert db(commands, opts=opts) == []
    with pytest.raises(ValueError, match="credentials_file"):
        MariaDbCheck({"credentials_file": "debian.cnf"})


def test_mysql_is_probed_with_its_own_tools() -> None:
    ping = ("mysqladmin", "ping")
    select = ("mysql", *SELECT[1:])
    ctx = make_ctx(
        commands={ping: "mysqld is alive\n", select: "1\n", ACTIVE_SERVICES: MYSQL_UP},
        available={"mysqld", "mysqladmin", "mysql"},
    )
    assert MariaDbCheck({"probe": True}).run(ctx) == []  # no MariaDB upgrade check for MySQL
    down = CommandResult(ping, 1, "", "error: 'Can't connect to local MySQL server'\n")
    ctx = make_ctx(
        commands={ping: down, ACTIVE_SERVICES: MYSQL_UP},
        available={"mysqld", "mysqladmin", "mysql"},
    )
    assert titles(MariaDbCheck({"probe": True}).run(ctx)) == ["The MySQL server doesn't answer"]


def test_neither_server_installed_is_skipped() -> None:
    result = run_check(MariaDbCheck(), make_ctx(available={"uname"}))
    assert result.status is Status.SKIPPED
    assert "neither MariaDB nor MySQL" in (result.skipped_reason or "")


def test_db_server_without_client_tools_is_not_probed() -> None:
    assert db({}, available={"mariadbd"}) == []


# --- docker --------------------------------------------------------------------------

RUNNING = "docker.service loaded active running x\n"


def container(
    name: str, status: str = "Up 2 hours", state: str = "running", ports: str = ""
) -> str:
    return json.dumps({"Names": name, "State": state, "Status": status, "Ports": ports}) + "\n"


def dk(ps: str, opts: dict[str, Any] | None = None, **kw: Any) -> list[Any]:
    ctx = make_ctx(commands={ACTIVE_SERVICES: RUNNING, DOCKER_PS: ps}, **kw)
    return DockerCheck(opts or {}).run(ctx)


def test_docker_health_states_are_reported_separately() -> None:
    ps = (
        container("web", "Up 2 hours (unhealthy)")
        + container("db", "Restarting (1) 5 seconds ago", "restarting")
        + container("cache", "Up 10 seconds (health: starting)")
        + container("plain", "Up 3 hours")
        + container("ok", "Up 3 hours (healthy)")
        + container("job", "Exited (1) 2 days ago", "exited")
    )
    fs = dk(ps)
    assert [(f.severity, f.title, f.evidence) for f in fs] == [
        (
            Severity.WARNING,
            "1 Docker container fails its health check",
            ["web: Up 2 hours (unhealthy)"],
        ),
        (
            Severity.WARNING,
            "1 Docker container keeps restarting",
            ["db: Restarting (1) 5 seconds ago"],
        ),
        (
            Severity.INFO,
            "1 Docker container is still starting its health check",
            ["cache: Up 10 seconds (health: starting)"],
        ),
    ]


def test_docker_port_probe() -> None:
    ps = container(
        "web",
        ports="0.0.0.0:8080->80/tcp, [::]:8080->80/tcp, 127.0.0.1:9000->9000/tcp, 53/udp, 0.0.0.0:5353->53/udp, 3000/tcp",
    )
    assert dk(ps) == []  # probe off by default: no connections
    ok = dk(ps, {"probe": True}, ports={("127.0.0.1", 8080), ("::1", 8080), ("127.0.0.1", 9000)})
    assert ok == []
    (f,) = dk(ps, {"probe": True}, ports={("127.0.0.1", 8080)})
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "2 published container ports don't answer",
    )
    assert f.evidence == [
        "web: ::1 port 8080 (Connection refused)",
        "web: 127.0.0.1 port 9000 (Connection refused)",
    ]


def test_docker_port_ranges_are_expanded() -> None:
    ps = container("web", ports="0.0.0.0:8000-8002->8000-8002/tcp")
    (f,) = dk(ps, {"probe": True}, ports={("127.0.0.1", 8000), ("127.0.0.1", 8002)})
    assert f.evidence == ["web: 127.0.0.1 port 8001 (Connection refused)"]


def test_docker_stopped_containers_are_not_port_probed() -> None:
    assert dk(container("job", "Exited (0)", "exited", "0.0.0.0:1->1/tcp"), {"probe": True}) == []


def test_docker_http_probes() -> None:
    ps = container("web") + container("api") + container("old", "Exited (0)", "exited")
    probes = [
        "web=http://127.0.0.1:8080/health",
        "api=https://localhost:8443/",
        "old=http://[::1]:9/",
        "gone=http://localhost:1/",
    ]
    http = {"http://127.0.0.1:8080/health": 204, "https://localhost:8443/": 503}
    (f,) = dk(ps, {"probe": True, "http_probes": probes}, http=http)
    assert (f.severity, f.title) == (Severity.WARNING, "3 HTTP probes failed")
    assert f.evidence == [
        "api: https://localhost:8443/ answered 503",
        "gone: not running",
        "old: not running",
    ]
    assert dk(ps, {"http_probes": probes}, http=http) == []  # only with probe: true


def test_docker_http_probe_errors() -> None:
    (f,) = dk(container("web"), {"probe": True, "http_probes": ["web=http://127.0.0.1:1/"]})
    assert f.evidence == ["web: http://127.0.0.1:1/ failed: Connection refused"]


@pytest.mark.parametrize(
    "probe",
    [
        "web",
        "web=ftp://127.0.0.1/",
        "web=http://example.com/",
        "=http://localhost/",
        "web=http://10.0.0.1:80/",
    ],
)
def test_docker_http_probes_are_validated(probe: str) -> None:
    with pytest.raises(ValueError, match="http_probes"):
        DockerCheck({"http_probes": [probe]})


def test_docker_ignore_containers() -> None:
    ps = container("ci-runner-1", "Up (unhealthy)") + container("web", "Up (unhealthy)")
    (f,) = dk(ps, {"ignore_containers": ["ci-runner-*"]})
    assert f.evidence == ["web: Up (unhealthy)"]
    ctx = make_ctx(commands={ACTIVE_SERVICES: RUNNING, DOCKER_PS: container("web")})
    check = DockerCheck({"ignore_containers": ["ci-*"]})
    assert titles(check.compare(ctx, ["web", "ci-runner-1", "db"])) == [
        "1 Docker container was running before the upgrade but isn't now"
    ]


def test_pg_probe_without_online_clusters_does_nothing() -> None:
    files = {"/etc/postgresql/17/main/start.conf": "manual\n"}
    assert pg({}, cluster("main", "5432", "down"), files=files) == []


# --- final review fixes --------------------------------------------------------------


@pytest.mark.parametrize(
    "probe", ["web=http://localhost:99999/", "web=http://localhost:abc/", "web=http://localhost/é"]
)
def test_http_probe_urls_that_cannot_be_requested_are_config_errors(probe: str) -> None:
    with pytest.raises(ValueError, match="http_probes"):
        DockerCheck({"http_probes": [probe]})


def test_pgpass_user_outside_the_safe_set_is_not_used() -> None:
    opts = {"probe": True, "credentials_file": "/etc/pydebuprep/pgpass"}
    for entry in ("*:*:*:john@corp:pw\n", "*:*:*:a\\:b:pw\n"):
        (f,) = pg({isready("5432"): "ok\n"}, opts=opts, files={"/etc/pydebuprep/pgpass": entry})
        assert f.title == "Can't use the PostgreSQL credentials file /etc/pydebuprep/pgpass"


@pytest.mark.parametrize(
    "error",
    [
        'FATAL:  no pg_hba.conf entry for host "[local]", user "postgres", database "postgres"',
        'FATAL:  role "postgres" does not exist',
        'FATAL:  database "postgres" does not exist',
    ],
)
def test_pg_login_and_setup_refusals_are_info(error: str) -> None:
    denied = CommandResult(query("5432"), 2, "", f"psql: error: {error}\n")
    (f,) = pg({isready("5432"): "ok\n", query("5432"): denied})
    assert f.severity is Severity.INFO


def test_pg_cluster_without_the_standard_socket_is_not_probed() -> None:
    files = {"/var/run/postgresql/.s.PGSQL.5432": ""}
    clusters = cluster("main", "5432") + cluster("other", "5433")
    commands = {isready("5432"): "ok\n", query("5432"): "1\n"}
    assert pg(commands, clusters, files=files) == []  # 5433 has no socket there: not asked


def test_pg_standby_is_probed() -> None:
    commands = {isready("5432"): "ok\n", query("5432"): "1\n"}
    assert pg(commands, cluster("main", "5432", "online,recovery")) == []


def test_db_not_running_is_not_probed() -> None:
    ctx = make_ctx(
        commands={
            MARIADBD_VERSION: MARIADB_VERSION,
            ACTIVE_SERVICES: "ssh.service loaded active running x\n",
        },
        available=MARIADB,
    )
    assert MariaDbCheck({"probe": True}).run(ctx) == []


def test_mysql_without_probe_is_skipped() -> None:
    result = run_check(MariaDbCheck(), make_ctx(available={"mysqld"}))
    assert result.status is Status.SKIPPED
    assert "probe" in (result.skipped_reason or "")


def test_ignored_container_with_an_http_probe_is_skipped() -> None:
    opts = {"probe": True, "http_probes": ["ci=http://127.0.0.1:1/"], "ignore_containers": ["ci"]}
    assert dk(container("ci"), opts) == []
