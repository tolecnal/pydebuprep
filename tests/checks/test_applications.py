from __future__ import annotations

import json
from typing import Any

from pydebuprep.checks._systemd import ACTIVE_SERVICES
from pydebuprep.checks.bind import NAMED_CHECKCONF, BindCheck
from pydebuprep.checks.docker import DOCKER_PS, DockerCheck
from pydebuprep.checks.mariadb import MARIADBD_VERSION, MariaDbCheck
from pydebuprep.checks.postfix import POSTCONF, PostfixCheck
from pydebuprep.checks.postgresql import PG_LSCLUSTERS, PostgresqlCheck
from pydebuprep.checks.python_venvs import PythonVenvsCheck
from pydebuprep.model import Severity, Status
from pydebuprep.runner import run_check
from pydebuprep.system import CommandResult

from .helpers import make_ctx, titles

# --- postgresql ----------------------------------------------------------------------

SERVERS = {"/usr/lib/postgresql/15/bin/postgres": "", "/usr/lib/postgresql/17/bin/postgres": ""}


def pg_ctx(clusters: str, **kw: Any) -> Any:
    files = {**SERVERS, **kw.pop("files", {})}
    return make_ctx(commands={PG_LSCLUSTERS: clusters}, files=files, **kw)


def cluster(ver: str, name: str, status: str) -> str:
    return f"{ver} {name} 5432 {status} postgres /var/lib/postgresql/{ver}/{name} /var/log/postgresql/postgresql-{ver}-{name}.log\n"


def test_postgresql_current_cluster_ok() -> None:
    assert PostgresqlCheck().run(pg_ctx(cluster("17", "main", "online"))) == []


def test_postgresql_old_cluster_not_migrated() -> None:
    (f,) = PostgresqlCheck().run(pg_ctx(cluster("15", "main", "online")))
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "PostgreSQL cluster 15/main still uses version 15; 17 is installed",
    )
    assert f.remediation[0] == "sudo pg_upgradecluster 15 main"


def test_postgresql_old_cluster_left_after_migration() -> None:
    clusters = cluster("15", "main", "down") + cluster("17", "main", "online")
    (f,) = PostgresqlCheck().run(
        pg_ctx(clusters, files={"/etc/postgresql/15/main/start.conf": "manual\n"})
    )
    assert f.title == "PostgreSQL cluster 15/main still uses version 15; 17 is installed"
    assert f.remediation[0] == "Check 17/main has your data, then: sudo pg_dropcluster 15 main"


def test_postgresql_cluster_down_that_should_start() -> None:
    files = {"/etc/postgresql/17/main/start.conf": "# auto, manual or disabled\nauto\n"}
    fs = PostgresqlCheck().run(pg_ctx(cluster("17", "main", "down"), files=files))
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.WARNING, "PostgreSQL cluster 17/main is down")
    ]


def test_postgresql_baseline_compare() -> None:
    ctx = pg_ctx(cluster("17", "main", "online") + cluster("17", "reports", "down"))
    assert PostgresqlCheck().collect_baseline(ctx) == ["17/main"]
    assert titles(PostgresqlCheck().compare(ctx, ["17/main", "17/reports", "15/old"])) == [
        "PostgreSQL clusters online before the upgrade aren't now"
    ]
    assert PostgresqlCheck().compare(ctx, ["17/main"]) == []


def test_postgresql_ignores_malformed_lines_and_no_servers() -> None:
    ctx = make_ctx(commands={PG_LSCLUSTERS: "garbage\n" + cluster("17", "main", "online")})
    assert PostgresqlCheck().run(ctx) == []


# --- mariadb -------------------------------------------------------------------------

VERSION = "mariadbd  Ver 11.8.6-MariaDB-0+deb13u1 from Debian for debian-linux-gnu on x86_64\n"


def test_mariadb_upgraded_ok() -> None:
    files = {"/var/lib/mysql/mariadb_upgrade_info": "11.8.6-MariaDB"}
    assert MariaDbCheck().run(make_ctx(commands={MARIADBD_VERSION: VERSION}, files=files)) == []


def test_mariadb_needs_upgrade() -> None:
    files = {"/var/lib/mysql/mysql_upgrade_info": "10.11.11-MariaDB\n"}
    (f,) = MariaDbCheck().run(make_ctx(commands={MARIADBD_VERSION: VERSION}, files=files))
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "MariaDB data was last upgraded for 10.11; the server is 11.8",
    )
    assert f.remediation == ["sudo mariadb-upgrade"]


def test_mariadb_unknown_state_is_no_finding() -> None:
    assert MariaDbCheck().run(make_ctx(commands={MARIADBD_VERSION: VERSION})) == []
    files = {"/var/lib/mysql/mariadb_upgrade_info": "garbage"}
    assert (
        MariaDbCheck().run(make_ctx(commands={MARIADBD_VERSION: "odd output\n"}, files=files)) == []
    )


# --- postfix -------------------------------------------------------------------------


def test_postfix_ok() -> None:
    assert PostfixCheck().run(make_ctx(commands={POSTCONF: "myhostname = x\n"})) == []


def test_postfix_warnings() -> None:
    res = CommandResult(
        POSTCONF,
        0,
        "myhostname = x\n",
        "postconf: warning: /etc/postfix/main.cf: unused parameter: smtpd_tls_cert_fil=x\n",
    )
    (f,) = PostfixCheck().run(make_ctx(commands={POSTCONF: res}))
    assert (f.severity, f.title) == (Severity.WARNING, "postfix warns about its configuration")


def test_postfix_unreadable_config_is_critical() -> None:
    res = CommandResult(
        POSTCONF, 1, "", "postconf: fatal: open /etc/postfix/main.cf: Permission denied\n"
    )
    (f,) = PostfixCheck().run(make_ctx(commands={POSTCONF: res}))
    assert (f.severity, f.title) == (Severity.CRITICAL, "postfix can't read its configuration")


# --- bind ----------------------------------------------------------------------------


def test_bind_ok_and_invalid() -> None:
    assert BindCheck().run(make_ctx(commands={NAMED_CHECKCONF: ""})) == []
    res = CommandResult(
        NAMED_CHECKCONF, 1, "/etc/bind/named.conf.options:4: missing ';' before '}'\n", ""
    )
    (f,) = BindCheck().run(make_ctx(commands={NAMED_CHECKCONF: res}))
    assert (f.severity, f.title) == (Severity.CRITICAL, "The BIND configuration is invalid")
    assert f.evidence == ["/etc/bind/named.conf.options:4: missing ';' before '}'"]


# --- docker --------------------------------------------------------------------------


def container(name: str, state: str, status: str) -> str:
    return json.dumps({"Names": name, "State": state, "Status": status, "Image": "img"}) + "\n"


def docker_ctx(ps: str, active: str = "docker.service loaded active running x\n") -> Any:
    return make_ctx(commands={ACTIVE_SERVICES: active, DOCKER_PS: ps})


def test_docker_ok() -> None:
    ps = container("web", "running", "Up 2 hours (healthy)") + container(
        "job", "exited", "Exited (0) 1 day ago"
    )
    assert DockerCheck().run(docker_ctx(ps)) == []


def test_docker_unhealthy_and_restarting() -> None:
    ps = (
        container("web", "running", "Up 2 hours (unhealthy)")
        + container("db", "restarting", "Restarting (1) 5 seconds ago")
        + "not json\n"
    )
    fs = DockerCheck().run(docker_ctx(ps))  # "not json" is skipped
    assert [(f.title, f.evidence) for f in fs] == [
        ("1 Docker container fails its health check", ["web: Up 2 hours (unhealthy)"]),
        ("1 Docker container keeps restarting", ["db: Restarting (1) 5 seconds ago"]),
    ]


def test_docker_not_running_is_skipped_without_starting_it() -> None:
    ctx = make_ctx(commands={ACTIVE_SERVICES: "docker.socket loaded active listening x\n"})
    r = run_check(DockerCheck(), ctx)
    assert r.status is Status.SKIPPED
    assert DOCKER_PS not in ctx.system.calls


def test_docker_without_systemd_is_skipped() -> None:
    no_systemd = CommandResult(ACTIVE_SERVICES, 1, "", "System has not been booted with systemd\n")
    assert (
        run_check(DockerCheck(), make_ctx(commands={ACTIVE_SERVICES: no_systemd})).status
        is Status.SKIPPED
    )


def test_docker_baseline_compare() -> None:
    ps = container("web", "running", "Up 1 minute") + container("job", "exited", "Exited (0)")
    ctx = docker_ctx(ps)
    assert DockerCheck().collect_baseline(ctx) == ["web"]
    (f,) = DockerCheck().compare(ctx, ["web", "db", "cache"])
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "2 Docker containers were running before the upgrade but aren't now",
    )
    assert f.evidence == ["cache", "db"]
    assert DockerCheck().compare(ctx, ["web"]) == []


# --- python-venvs --------------------------------------------------------------------


def venv(path: str, version: str, works: bool, key: str = "version") -> dict[str, str]:
    files = {
        f"{path}/pyvenv.cfg": f"home = /usr/bin\ninclude-system-site-packages = false\n{key} = {version}\n"
    }
    if works:
        files[f"{path}/bin/python"] = ""
    return files


def test_venvs_ok() -> None:
    files = venv("/opt/app/.venv", "3.13.5", works=True)
    assert PythonVenvsCheck().run(make_ctx(files=files, python="3.13")) == []


def test_venvs_broken_and_outdated() -> None:
    files = {
        **venv("/opt/app/.venv", "3.11.2", works=False),
        **venv("/srv/tool/venv", "3.12.3.final.0", works=True, key="version_info"),
        **venv("/home/alice/proj/env", "3.13.1", works=True),
        "/opt/odd/pyvenv.cfg": "no version here\n",
    }
    fs = PythonVenvsCheck().run(make_ctx(files=files, python="3.13"))
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.WARNING, "1 virtualenv points to a Python that no longer exists"),
        (Severity.INFO, "1 virtualenv was built for an older Python than the system's 3.13"),
    ]
    assert fs[0].evidence == ["/opt/app/.venv (Python 3.11)"]
    assert fs[1].evidence == ["/srv/tool/venv (Python 3.12)"]


def test_venvs_search_paths_and_depth_options() -> None:
    files = venv("/data/deep/a/b/c/.venv", "3.11.2", works=False)
    assert PythonVenvsCheck().run(make_ctx(files=files)) == []
    check = PythonVenvsCheck({"search_paths": ["/data"], "max_depth": 6})
    assert titles(check.run(make_ctx(files=files))) == [
        "1 virtualenv points to a Python that no longer exists"
    ]


def test_venvs_max_depth_bounds() -> None:
    import pytest

    for bad in (0, 21):
        with pytest.raises(ValueError, match="max_depth must be between 1 and 20"):
            PythonVenvsCheck({"max_depth": bad})


def test_venvs_in_caches_are_skipped() -> None:
    files = {
        **venv("/home/alice/.cache/uv/archive-v0/abc", "3.10.4", works=True),
        **venv("/home/alice/proj/venv", "3.10.4", works=True),
    }
    fs = PythonVenvsCheck().run(make_ctx(files=files, python="3.13"))
    assert fs[0].evidence == ["/home/alice/proj/venv (Python 3.10)"]
    everything = PythonVenvsCheck({"exclude_paths": []}).run(make_ctx(files=files, python="3.13"))
    assert len(everything[0].evidence) == 2
