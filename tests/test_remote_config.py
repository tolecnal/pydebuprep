"""Configs fetched from a URL: safety rules, the saved copy, and the CLI."""

from __future__ import annotations

import json
import os
import re
import socket
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

import pytest

from portal_stub import Portal, Reply, running_portal
from pydebuprep import checks
from pydebuprep.cli import main
from pydebuprep.config import ConfigError
from pydebuprep.model import ConfigInfo
from pydebuprep.portal import Connection
from pydebuprep.remote_config import REMOTE_FORBIDDEN, is_url, load_remote_config, parse_remote
from pydebuprep.state import CachedConfig, load_cached_config, save_cached_config
from test_cli import RootCrit, Warn, fake

REAL_CHECKS = list(checks.ALL_CHECKS)  # before the registry fixture replaces it
URL = "https://portal.example/api/v1/configs/web/default"
PATH = "/api/v1/configs/web/default"
TOKEN = "pdp_test_token"
NOW = datetime(2026, 10, 30, 9, 15, tzinfo=timezone.utc)
HTTP = Connection(allow_http=True, timeout=5.0)


@pytest.fixture(autouse=True)
def _registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checks, "ALL_CHECKS", [Warn, RootCrit])
    monkeypatch.setenv("PYDEBUPREP_TOKEN", TOKEN)
    # The package creates this; the conftest's state directory starts empty.
    (Path(os.environ["PYDEBUPREP_STATE_DIR"]) / "configs").mkdir()


@pytest.fixture
def portal() -> Iterator[Portal]:
    with running_portal() as p:
        yield p


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "configs"
    directory.mkdir()
    return directory


# --- parse_remote: what a remote config may not do ---------------------------


def test_is_url() -> None:
    assert is_url("https://p/x") and is_url("http://p/x")
    assert not is_url("/etc/pydebuprep.conf") and not is_url("httpsfile.conf")


@pytest.mark.parametrize(("section", "key"), REMOTE_FORBIDDEN)
def test_write_paths_and_credentials_refused(section: str, key: str) -> None:
    with pytest.raises(ConfigError) as exc:
        parse_remote(f"{section}:\n  {key}: /etc\n", URL)
    assert exc.value.errors == [
        f"{URL}: {section}.{key} can't be set by a config fetched from a URL"
    ]


def test_refused_even_when_equal_to_the_default() -> None:
    with pytest.raises(ConfigError, match=r"report\.snapshot_dir can't be set"):
        parse_remote("report:\n  snapshot_dir: /var/lib/pydebuprep/snapshots\n", URL)


def test_all_errors_listed_together() -> None:
    text = "report:\n  output_dir: /etc\n  format: nope\nupload:\n  token_file: /etc/shadow\n"
    with pytest.raises(ConfigError) as exc:
        parse_remote(text, URL)
    assert len(exc.value.errors) == 3


def test_upload_url_must_be_the_same_server() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_remote("upload:\n  url: https://evil.example\n", URL)
    assert exc.value.errors == [
        f"{URL}: upload.url must be on the same server as the config (https://evil.example)"
    ]
    config = parse_remote("upload:\n  url: https://portal.example:443/\n", URL)
    assert config.upload.url == "https://portal.example:443/"


def test_no_upload_url_means_no_upload() -> None:
    assert parse_remote("report:\n  format: json\n", URL).upload.url is None


@pytest.mark.parametrize("path", ["/dev/zero", "/dev/watchdog", "snaps/x.json",
                                  "/var/lib/pydebuprep/snapshots/x.json"])  # fmt: skip
def test_baseline_may_not_name_a_file(path: str) -> None:
    # Opening a file is not harmless as root: /dev/zero exhausts memory, opening
    # /dev/watchdog arms a reboot, a FIFO hangs the run.
    with pytest.raises(ConfigError) as exc:
        parse_remote(f"report:\n  baseline: {path}\n", URL)
    assert exc.value.errors == [
        f"{URL}: report.baseline must be auto or none in a config fetched from a URL"
    ]
    for ok in ("auto", "none"):
        assert parse_remote(f"report:\n  baseline: {ok}\n", URL).report.baseline == ok


@pytest.mark.parametrize(
    ("check", "option", "value"),
    [
        ("postgresql", "credentials_file", "/dev/watchdog"),
        ("mariadb", "credentials_file", "/dev/watchdog"),
        ("python-venvs", "search_paths", "[/proc]"),
        ("docker", "http_probes", "[web=http://127.0.0.1:8080/admin]"),
    ],
)
def test_forbidden_check_options_refused(
    monkeypatch: pytest.MonkeyPatch, check: str, option: str, value: str
) -> None:
    monkeypatch.setattr(checks, "ALL_CHECKS", REAL_CHECKS)
    with pytest.raises(ConfigError) as exc:
        parse_remote(f"checks:\n  {check}:\n    {option}: {value}\n", URL)
    assert exc.value.errors == [
        f"{URL}: checks.{check}.{option} can't be set by a config fetched from a URL"
    ]
    config = parse_remote("checks:\n  postgresql:\n    probe: true\n", URL)
    assert config.check_settings["postgresql"] == {"probe": True}


def test_deeply_nested_config_is_an_error_not_a_crash() -> None:
    with pytest.raises(ConfigError, match="nested too deeply"):
        parse_remote("a: " + "[" * 5000, URL)


def test_check_options_and_pending_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYDEBUPREP_STATE_DIR", "/srv/state")
    config = parse_remote("checks:\n  warn-check:\n    enabled: false\n", URL)
    assert config.disabled == {"warn-check"}
    assert config.upload.pending_dir == "/srv/state/pending"
    assert config.path == URL


def test_yaml_errors_still_reported() -> None:
    with pytest.raises(ConfigError, match="line 2, column 1"):
        parse_remote("report: [\n", URL)


# --- load_remote_config: fetching, the saved copy -------------------------------


def load(portal: Portal, cache_dir: Path, token_file: str = "/nonexistent") -> tuple:
    warnings: list[str] = []
    result = load_remote_config(
        portal.url + PATH, token_file=token_file, conn=HTTP, cache_dir=str(cache_dir),
        now=NOW, warn=warnings.append,
    )  # fmt: skip
    return (*result, warnings)


def test_fetched_and_saved(portal: Portal, cache_dir: Path) -> None:
    portal.route("GET", PATH, Reply(200, b"report:\n  format: json\n", {"ETag": '"v1"'}))
    config, info, warnings = load(portal, cache_dir)
    assert config.report.format == "json"
    assert info == ConfigInfo(portal.url + PATH, "2026-10-30T09:15:00+00:00", False)
    assert warnings == []
    saved = load_cached_config(str(cache_dir), portal.url + PATH)
    assert saved == CachedConfig(
        portal.url + PATH, "2026-10-30T09:15:00+00:00", '"v1"', "report:\n  format: json\n"
    )
    assert portal.requests[0].headers["Authorization"] == f"Bearer {TOKEN}"


def test_not_modified_uses_the_saved_copy(portal: Portal, cache_dir: Path) -> None:
    url = portal.url + PATH
    save_cached_config(str(cache_dir), CachedConfig(url, "2026-10-01T00:00:00+00:00", '"v1"',
                                                    "report:\n  format: yaml\n"))  # fmt: skip
    portal.route("GET", PATH, Reply(304, headers={"ETag": '"v1"'}))
    config, info, warnings = load(portal, cache_dir)
    assert portal.requests[0].headers["If-None-Match"] == '"v1"'
    assert config.report.format == "yaml"
    assert warnings == []
    assert info == ConfigInfo(url, "2026-10-30T09:15:00+00:00", False)
    assert load_cached_config(str(cache_dir), url).fetched_at == "2026-10-30T09:15:00+00:00"


def test_not_modified_without_a_copy(portal: Portal, cache_dir: Path) -> None:
    portal.route("GET", PATH, Reply(304))
    with pytest.raises(ConfigError, match="not modified"):
        load(portal, cache_dir)


@pytest.mark.parametrize("failure", ["status", "token"])
def test_unreachable_falls_back_to_the_saved_copy(
    portal: Portal, cache_dir: Path, failure: str
) -> None:
    url = portal.url + PATH
    save_cached_config(str(cache_dir), CachedConfig(url, "2026-10-01T00:00:00+00:00", None,
                                                    "report:\n  format: yaml\n"))  # fmt: skip
    portal.route("GET", PATH, Reply(503, b"maintenance"))
    if failure == "token":
        os.environ.pop("PYDEBUPREP_TOKEN")
    config, info, warnings = load(portal, cache_dir)
    assert config.report.format == "yaml"
    assert info == ConfigInfo(url, "2026-10-01T00:00:00+00:00", True)
    reason = "HTTP 503" if failure == "status" else "no upload token"
    assert len(warnings) == 1 and reason in warnings[0]
    assert "using the copy fetched on 2026-10-01T00:00:00+00:00" in warnings[0]


def test_unreachable_without_a_copy(cache_dir: Path) -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        url = f"http://127.0.0.1:{s.getsockname()[1]}{PATH}"
    with pytest.raises(ConfigError) as exc:
        load_remote_config(url, token_file="/x", conn=HTTP, cache_dir=str(cache_dir), now=NOW,
                           warn=lambda m: None)  # fmt: skip
    (error,) = exc.value.errors
    assert error.startswith(f"cannot fetch config {url}: ")
    assert error.endswith("; there is no saved copy to fall back on")


def test_invalid_fetched_config_is_an_error_and_not_saved(portal: Portal, cache_dir: Path) -> None:
    url = portal.url + PATH
    good = CachedConfig(url, "2026-10-01T00:00:00+00:00", None, "report:\n  format: yaml\n")
    save_cached_config(str(cache_dir), good)
    portal.route("GET", PATH, Reply(200, b"report:\n  output_dir: /etc\n"))
    with pytest.raises(ConfigError, match="output_dir can't be set"):
        load(portal, cache_dir)
    assert load_cached_config(str(cache_dir), url) == good


def test_cache_directory_missing(portal: Portal, tmp_path: Path) -> None:
    portal.route("GET", PATH, Reply(200, b"report: {}\n"))
    _, info, warnings = load(portal, tmp_path / "missing")
    assert not info.stale
    assert len(warnings) == 1 and warnings[0].startswith("could not save a copy of the config: ")


def test_http_url_without_opt_in(cache_dir: Path) -> None:
    with pytest.raises(ConfigError, match="--allow-http"):
        load_remote_config("http://portal.example/c", token_file="/x", conn=Connection(),
                           cache_dir=str(cache_dir), now=NOW, warn=lambda m: None)  # fmt: skip


# --- the CLI ------------------------------------------------------------------


def serve_config(portal: Portal, text: str) -> str:
    portal.route("GET", PATH, Reply(200, text.encode(), {"ETag": '"v1"'}))
    return portal.url + PATH


def run_json(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict, str]:
    rc = main(["report", "--no-baseline", "--allow-http", "--format", "json", *args],
              system=fake())  # fmt: skip
    out, err = capsys.readouterr()
    return rc, json.loads(out), err


def test_report_with_a_remote_config(portal: Portal, capsys: pytest.CaptureFixture[str]) -> None:
    url = serve_config(portal, "checks:\n  root-crit:\n    enabled: false\n")
    rc, data, _ = run_json(["--config", url], capsys)
    assert [r["id"] for r in data["results"]] == ["warn-check"]
    assert data["config"]["source"] == url and data["config"]["stale"] is False
    assert rc == 1


def test_report_falls_back_and_says_so(portal: Portal, capsys: pytest.CaptureFixture[str]) -> None:
    url = serve_config(portal, "checks:\n  root-crit:\n    enabled: false\n")
    run_json(["--config", url], capsys)
    portal.route("GET", PATH, Reply(500, b"oops"))
    _, data, err = run_json(["--config", url], capsys)
    assert data["config"]["stale"] is True
    assert [r["id"] for r in data["results"]] == ["warn-check"]
    assert "pydebuprep: warning: cannot fetch config" in err
    main(["report", "--no-baseline", "--allow-http", "--config", url], system=fake())
    assert "could not be fetched; used the copy fetched on" in capsys.readouterr().out


def test_config_from_the_environment(
    portal: Portal, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PYDEBUPREP_CONFIG", serve_config(portal, "report: {}\n"))
    _, data, _ = run_json([], capsys)
    assert data["config"]["stale"] is False


def test_token_sources(
    portal: Portal, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    url = serve_config(portal, "report: {}\n")
    flag = tmp_path / "flag-token"
    flag.write_text("from-flag\n")
    flag.chmod(0o600)
    run_json(["--config", url, "--token-file", str(flag)], capsys)
    assert portal.requests[-1].headers["Authorization"] == f"Bearer {TOKEN}"  # env wins
    monkeypatch.delenv("PYDEBUPREP_TOKEN")
    run_json(["--config", url, "--token-file", str(flag)], capsys)
    assert portal.requests[-1].headers["Authorization"] == "Bearer from-flag"


def test_upload_after_a_remote_config_goes_back_to_the_portal(
    portal: Portal, capsys: pytest.CaptureFixture[str]
) -> None:
    portal.route("POST", "/api/v1/reports", Reply(201, b"{}"))
    url = serve_config(portal, f"upload:\n  url: {portal.url}\n")
    run_json(["--config", url], capsys)
    assert [r.method for r in portal.requests] == ["GET", "POST"]
    assert portal.requests[1].headers["Authorization"] == f"Bearer {TOKEN}"


def test_failed_upload_after_a_remote_config_is_kept_in_the_state_dir(
    portal: Portal, capsys: pytest.CaptureFixture[str]
) -> None:
    portal.route("POST", "/api/v1/reports", Reply(503, b""))
    pending = Path(os.environ["PYDEBUPREP_STATE_DIR"]) / "pending"
    pending.mkdir()
    url = serve_config(portal, f"upload:\n  url: {portal.url}\n")
    _, _, err = run_json(["--config", url], capsys)
    assert f"kept for `pydebuprep upload`: {pending}/" in err


def test_remote_config_errors_exit_3(portal: Portal, capsys: pytest.CaptureFixture[str]) -> None:
    url = serve_config(portal, "report:\n  output_dir: /etc\n")
    rc = main(["report", "--allow-http", "--config", url], system=fake())
    assert rc == 3
    err = capsys.readouterr().err
    assert re.search(r"config error: .*report\.output_dir can't be set", err)


@pytest.mark.parametrize("command", [["configtest"], ["snapshot", "--snapshot-dir", "SNAPS"]])
def test_other_commands_accept_a_url(
    portal: Portal, tmp_path: Path, capsys: pytest.CaptureFixture[str], command: list[str]
) -> None:
    (tmp_path / "snaps").mkdir()
    argv = [a.replace("SNAPS", str(tmp_path / "snaps")) for a in command]
    url = serve_config(portal, "report: {}\n")
    assert main([*argv, "--allow-http", "--config", url], system=fake()) == 0
    if command == ["configtest"]:
        assert capsys.readouterr().out == f"Using {url} (fetched now)\nSyntax OK\n"


def test_configtest_with_the_saved_copy(portal: Portal, capsys: pytest.CaptureFixture[str]) -> None:
    url = serve_config(portal, "report: {}\n")
    main(["configtest", "--allow-http", "--config", url])
    capsys.readouterr()
    portal.route("GET", PATH, Reply(502, b""))
    assert main(["configtest", "--allow-http", "--config", url]) == 0
    out = capsys.readouterr().out
    assert re.match(
        rf"Using the copy of {re.escape(url)} fetched on \S+ \(the portal could not be "
        r"reached\)\nSyntax OK\n",
        out,
    )


def test_a_list_is_not_a_config() -> None:
    with pytest.raises(ConfigError, match="expected a mapping"):
        parse_remote("- report\n- checks\n", URL)
