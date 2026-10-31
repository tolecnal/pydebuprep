"""Uploading reports from the CLI: after a report run, and `pydebuprep upload`."""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from portal_stub import Portal, Reply, running_portal
from pydebuprep import checks
from pydebuprep.cli import main
from pydebuprep.render import render
from pydebuprep.reportfile import load_report
from test_cli import RootCrit, Warn, fake

TOKEN = "pdp_test_token"
REPORTS = "/api/v1/reports"


@pytest.fixture(autouse=True)
def _registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checks, "ALL_CHECKS", [Warn, RootCrit])


@pytest.fixture
def portal() -> Iterator[Portal]:
    with running_portal() as p:
        p.route("POST", REPORTS, Reply(201, json.dumps({"url": f"{p.url}/r/1"}).encode()))
        yield p


@pytest.fixture
def pending(tmp_path: Path) -> Path:
    directory = tmp_path / "pending"
    directory.mkdir(mode=0o700)
    return directory


def configure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, url: str | None, **upload: Any
) -> None:
    lines = ["upload:"]
    if url is not None:
        lines.append(f"  url: {url}")
    for key, value in upload.items():
        lines.append(f"  {key}: {'null' if value is None else value}")
    conf = tmp_path / "pydebuprep.conf"
    conf.write_text("\n".join(lines) + "\n")
    monkeypatch.setenv("PYDEBUPREP_CONFIG", str(conf))
    monkeypatch.setenv("PYDEBUPREP_TOKEN", TOKEN)


def report(args: list[str]) -> int:
    return main(["report", "--no-baseline", "--allow-http", *args], system=fake())


def dead_url() -> str:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{s.getsockname()[1]}"


# --- after a report run ------------------------------------------------------


def test_report_is_uploaded_in_full(
    portal: Portal, pending: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    configure(monkeypatch, tmp_path, portal.url, pending_dir=pending)
    rc = report(["--min-severity", "critical"])
    out, err = capsys.readouterr()
    assert rc == 2
    assert "a warning" not in out  # hidden locally...
    uploaded = load_report(portal.requests[0].body.decode())
    titles = [f.title for r in uploaded.results for f in r.findings]
    assert "a warning" in titles and "an info note" in titles  # ...but uploaded
    assert portal.requests[0].headers["Authorization"] == f"Bearer {TOKEN}"
    assert f"Report uploaded to {portal.url}/r/1" in err
    assert os.listdir(pending) == []


def test_output_and_exit_code_same_as_without_upload(
    portal: Portal, pending: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    configure(monkeypatch, tmp_path, None)
    rc_plain = report([])
    plain = capsys.readouterr().out
    configure(monkeypatch, tmp_path, dead_url(), pending_dir=pending)
    assert report([]) == rc_plain
    assert capsys.readouterr().out == plain


@pytest.mark.parametrize("failure", ["refused", "dead"])
def test_failed_upload_is_kept(  # noqa: PLR0917 - pytest fixtures
    portal: Portal, pending: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], failure: str,
) -> None:  # fmt: skip
    portal.route("POST", REPORTS, Reply(503, b"down for maintenance"))
    url = portal.url if failure == "refused" else dead_url()
    configure(monkeypatch, tmp_path, url, pending_dir=pending)
    rc = report([])
    err = capsys.readouterr().err
    assert rc == 2
    assert "pydebuprep: warning: upload failed: " in err
    (kept,) = pending.iterdir()
    assert f"kept for `pydebuprep upload`: {kept}" in err
    assert oct(kept.stat().st_mode & 0o777) == "0o600"
    if failure == "refused":
        assert kept.read_bytes() == portal.requests[0].body
    assert load_report(kept.read_text()).host.hostname == "testhost"


def test_not_kept_when_pending_is_off(
    portal: Portal, pending: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    configure(monkeypatch, tmp_path, dead_url(), pending_dir=None)
    report([])
    err = capsys.readouterr().err
    assert "upload failed" in err
    assert "not kept (upload: pending_dir is null)" in err
    assert list(pending.iterdir()) == []


def test_pending_directory_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    configure(monkeypatch, tmp_path, dead_url(), pending_dir=tmp_path / "nope")
    assert report([]) == 2
    err = capsys.readouterr().err
    assert f"could not keep it: {tmp_path / 'nope'}: no such directory" in err
    assert not (tmp_path / "nope").exists()


def test_no_token(
    portal: Portal, pending: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    configure(monkeypatch, tmp_path, portal.url, pending_dir=pending,
              token_file=tmp_path / "token")  # fmt: skip
    monkeypatch.delenv("PYDEBUPREP_TOKEN")
    report([])
    err = capsys.readouterr().err
    assert f"upload failed: no upload token: set PYDEBUPREP_TOKEN or create {tmp_path}/token" in err
    assert portal.requests == []
    assert len(list(pending.iterdir())) == 1


def test_token_file_flag(
    portal: Portal, pending: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(monkeypatch, tmp_path, portal.url, pending_dir=pending)
    monkeypatch.delenv("PYDEBUPREP_TOKEN")
    token = tmp_path / "flagtoken"
    token.write_text("from-flag\n")
    token.chmod(0o600)
    report(["--token-file", str(token)])
    assert portal.requests[0].headers["Authorization"] == "Bearer from-flag"


def test_http_needs_allow_http(
    portal: Portal, pending: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    configure(monkeypatch, tmp_path, portal.url, pending_dir=pending)
    main(["report", "--no-baseline"], system=fake())
    assert "--allow-http" in capsys.readouterr().err
    assert portal.requests == []


def test_no_upload_url_means_no_network_and_no_writes(
    portal: Portal, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(monkeypatch, tmp_path, None)
    state = Path(os.environ["PYDEBUPREP_STATE_DIR"])
    report([])
    assert portal.requests == []
    assert list(state.iterdir()) == []


def test_snapshot_and_convert_never_upload(
    portal: Portal, pending: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(monkeypatch, tmp_path, portal.url, pending_dir=pending)
    snaps = tmp_path / "snaps"
    snaps.mkdir()
    assert main(["snapshot", "--snapshot-dir", str(snaps)], system=fake()) == 0
    saved = tmp_path / "r.json"
    saved.write_text(render(load_report_text(), "json"))
    assert main(["convert", str(saved), "-o", str(tmp_path / "r.txt")]) == 0
    assert portal.requests == []


def load_report_text() -> Any:
    from conftest import make_sample_report

    return make_sample_report()


# --- pydebuprep upload -------------------------------------------------------


def kept_reports(pending: Path, count: int) -> list[Path]:
    from pydebuprep.state import save_pending

    paths = []
    for i in range(count):
        body = json.dumps(json.loads(render(load_report_text(), "json")) | {"n": i}).encode()
        paths.append(Path(save_pending(str(pending), body, "h", f"2026-10-30T09:1{i}:00+00:00")))
    return paths


def test_upload_sends_everything_pending(
    portal: Portal, pending: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    configure(monkeypatch, tmp_path, portal.url, pending_dir=pending)
    first, second = kept_reports(pending, 2)
    bodies = [first.read_bytes(), second.read_bytes()]
    assert main(["upload", "--allow-http"]) == 0
    assert [r.body for r in portal.requests] == bodies  # oldest first, sent as kept
    assert list(pending.iterdir()) == []
    out = capsys.readouterr().out
    assert f"{first}: uploaded to {portal.url}/r/1" in out


def test_upload_keeps_what_was_refused(
    portal: Portal, pending: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    configure(monkeypatch, tmp_path, portal.url, pending_dir=pending)
    first, second = kept_reports(pending, 2)
    first_body = first.read_bytes()

    def accept_first(request: Any) -> Reply:
        return Reply(201, b"{}") if request.body == first_body else Reply(422, b"bad")

    portal.route("POST", REPORTS, accept_first)
    assert main(["upload", "--allow-http"]) == 3
    assert list(pending.iterdir()) == [second]
    err = capsys.readouterr().err
    assert f"pydebuprep: error: {second}: upload failed: " in err and "HTTP 422" in err


def test_upload_named_files(
    portal: Portal, pending: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    configure(monkeypatch, tmp_path, portal.url, pending_dir=pending)
    as_json = tmp_path / "r.json"
    as_json.write_text(render(load_report_text(), "json"))
    as_yaml = tmp_path / "r.yaml"
    as_yaml.write_text(render(load_report_text(), "yaml"))
    not_a_report = tmp_path / "notes.txt"
    not_a_report.write_text("hello")
    (kept,) = kept_reports(pending, 1)
    rc = main(["upload", "--allow-http", str(as_json), str(as_yaml), str(not_a_report)])
    assert rc == 3
    assert portal.requests[0].body == as_json.read_bytes()  # JSON sent as it is
    assert load_report(portal.requests[1].body.decode()) == load_report_text()  # YAML converted
    assert len(portal.requests) == 2
    assert as_json.exists() and as_yaml.exists()  # never removed: not pending
    assert kept.exists()  # not named, not sent
    assert f"pydebuprep: error: {not_a_report}: not a pydebuprep report" in capsys.readouterr().err


def test_upload_missing_file(
    portal: Portal, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    configure(monkeypatch, tmp_path, portal.url)
    assert main(["upload", "--allow-http", str(tmp_path / "gone.json")]) == 3
    assert "gone.json: No such file or directory" in capsys.readouterr().err


def test_upload_nothing_pending(
    portal: Portal, pending: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    configure(monkeypatch, tmp_path, portal.url, pending_dir=pending)
    assert main(["upload", "--allow-http"]) == 0
    assert "Nothing to upload" in capsys.readouterr().out
    configure(monkeypatch, tmp_path, portal.url, pending_dir=None)
    assert main(["upload", "--allow-http"]) == 0


def test_upload_without_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    configure(monkeypatch, tmp_path, None)
    assert main(["upload"]) == 3
    assert (
        "pydebuprep: error: no upload URL configured (upload: url: in the config file)"
        in capsys.readouterr().err
    )


def test_upload_without_token(
    portal: Portal, pending: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    configure(monkeypatch, tmp_path, portal.url, pending_dir=pending,
              token_file=tmp_path / "token")  # fmt: skip
    monkeypatch.delenv("PYDEBUPREP_TOKEN")
    kept_reports(pending, 1)
    assert main(["upload", "--allow-http"]) == 3
    assert "no upload token" in capsys.readouterr().err
    assert portal.requests == []


def test_upload_binary_file(
    portal: Portal, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    configure(monkeypatch, tmp_path, portal.url)
    binary = tmp_path / "report.json.gz"
    binary.write_bytes(b"\x1f\x8b\x08\x00\xff")
    assert main(["upload", "--allow-http", str(binary)]) == 3
    assert f"{binary}: not a UTF-8 text file" in capsys.readouterr().err
    assert portal.requests == []
