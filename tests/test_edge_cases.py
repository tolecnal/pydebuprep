"""Edge cases and error paths across modules, found by branch coverage."""

from __future__ import annotations

import argparse
import json
import runpy
import sys
from pathlib import Path
from typing import Any

import pytest

from checks.helpers import make_ctx, titles
from conftest import make_sample_report
from fakes import FakeSystem
from pydebuprep import checks, cli
from pydebuprep.checks._diskutil import _human, space_findings
from pydebuprep.checks._systemd import unit_rows
from pydebuprep.checks.apt_lists_age import AptListsAgeCheck
from pydebuprep.checks.apt_sources import AptSourcesCheck, parse_sources
from pydebuprep.checks.base import (
    Check,
    CommandFailed,
    Context,
    Option,
    run_checked,
    running_kernel,
)
from pydebuprep.checks.boot_time import ANALYZE, BootTimeCheck
from pydebuprep.checks.bootloader import BootloaderCheck
from pydebuprep.checks.disk_space import DF_INODES, DF_SPACE, DiskSpaceCheck
from pydebuprep.checks.dkms import parse_dkms_status
from pydebuprep.checks.dmesg_errors import DMESG_ERR, DmesgErrorsCheck
from pydebuprep.checks.journal_errors import JOURNAL, JournalErrorsCheck, _message
from pydebuprep.checks.kernel_running import compare_versions
from pydebuprep.checks.obsolete_packages import PKG_VERSIONS_ARGV, installed_versions
from pydebuprep.completion import _help, bash_completion
from pydebuprep.config import ConfigError, load_config, parse_config
from pydebuprep.model import CheckResult, Finding, Severity, Status, sort_results
from pydebuprep.osinfo import detect_os, parse_os_release
from pydebuprep.render import render
from pydebuprep.render._common import NO_BASELINE, baseline_state, valid_utf8
from pydebuprep.runner import run_check
from pydebuprep.snapshot import (
    SnapshotError,
    baseline_warnings,
    build_snapshot,
    find_latest,
    load_snapshot,
)
from pydebuprep.system import CommandResult, DiskUsage

OS_RELEASE = 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n'


# --- disk helpers --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("n", "text"),
    [(500, "500 B"), (1536, "1.5 KiB"), (5 * 1024**2, "5.0 MiB"), (3 * 1024**4, "3.0 TiB")],
)
def test_human_sizes(n: int, text: str) -> None:
    assert _human(n) == text


@pytest.mark.parametrize("settings", [{"warning_pct": 150}, {"critical_pct": -1}])
def test_thresholds_out_of_range(settings: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="between 0 and 100"):
        DiskSpaceCheck(settings)


def test_space_findings_with_unknown_size_still_checks_inodes() -> None:
    (f,) = space_findings("/x", DiskUsage(0, 0, 1000, 10), ["r"])
    assert f.title == "Low free inodes on /x: 1% free"


def test_df_short_lines_ignored() -> None:
    space = "Filesystem Type 1024-blocks Used Available Capacity Mounted on\ngarbage line\n"
    assert DiskSpaceCheck().run(make_ctx(commands={DF_SPACE: space, DF_INODES: ""})) == []


def test_unit_rows_skip_blank_lines() -> None:
    assert unit_rows("a.service loaded\n\n   \n● b.service x\n") == [
        ["a.service", "loaded"],
        ["b.service", "x"],
    ]


def test_apt_lists_age_rejects_negative() -> None:
    with pytest.raises(ValueError, match="max_age_days must not be negative"):
        AptListsAgeCheck({"max_age_days": -1})


# --- apt sources parsing -------------------------------------------------------------


def test_one_line_format_skips_blank_and_malformed_lines() -> None:
    text = "\n   \ndeb http://deb.debian.org/debian\ndeb-src\nfoo bar baz qux\ndeb http://deb.debian.org/debian trixie main\n"
    ctx = make_ctx(files={"/etc/apt/sources.list": text})
    assert [(e.uri, e.suite) for e in parse_sources(ctx.system)] == [
        ("http://deb.debian.org/debian", "trixie")
    ]


def test_deb822_comments_continuations_and_extra_blank_lines() -> None:
    text = (
        "# Debian archive\n"
        "Types: deb\n"
        "URIs: http://deb.debian.org/debian\n"
        "Suites: trixie\n"
        "  trixie-updates\n"
        "# a comment inside the stanza\n"
        "Components: main\n"
        "\n\n\n"
    )
    ctx = make_ctx(files={"/etc/apt/sources.list.d/debian.sources": text})
    assert [e.suite for e in parse_sources(ctx.system)] == ["trixie", "trixie-updates"]
    assert AptSourcesCheck().run(ctx) == []


def test_files_with_other_extensions_are_ignored() -> None:
    files = {
        "/etc/apt/sources.list": "deb http://deb.debian.org/debian trixie main\n",
        "/etc/apt/sources.list.d/notes.txt": "deb http://old.example/debian bookworm main\n",
    }
    assert [e.file for e in parse_sources(make_ctx(files=files).system)] == [
        "/etc/apt/sources.list"
    ]


# --- check base ----------------------------------------------------------------------


class Plain(Check):
    id = "plain"
    options = (Option("ratio", 1.5, "A float"), Option("name", "x", "A string"))


def test_base_check_must_implement_run() -> None:
    with pytest.raises(NotImplementedError):
        Plain().run(make_ctx())


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        ({"ratio": True}, "expected a number"),
        ({"name": {"a": 1}}, "expected a string"),
        ({"name": [1]}, "expected a string"),
    ],
)
def test_option_type_errors(settings: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        Plain(settings)


def test_baseline_for_with_empty_baseline() -> None:
    assert Context(FakeSystem(), detect_os(FakeSystem()), {}).baseline_for("x") is None


def test_missing_command_without_install_hint() -> None:
    class NeedsTool(Check):
        id = "needs-tool"
        requires_commands = ("tool",)

    r = run_check(NeedsTool(), make_ctx(available=set()))
    assert r.skipped_reason == "command not found: tool"


def test_run_checked_unexpected_exit_status() -> None:
    ctx = make_ctx(
        commands={("uname", "-r"): CommandResult(("uname", "-r"), 4, "", "bad thing\nmore\n")}
    )
    with pytest.raises(CommandFailed, match="uname exited with status 4: bad thing"):
        run_checked(ctx, ["uname", "-r"])


def test_running_kernel_empty_output() -> None:
    with pytest.raises(CommandFailed, match="printed nothing"):
        running_kernel(make_ctx(commands={("uname", "-r"): "\n"}))


# --- individual checks ---------------------------------------------------------------


def test_boot_time_other_failure_is_an_error() -> None:
    res = CommandResult(ANALYZE, 1, "", "Failed to connect: something odd\n")
    r = run_check(BootTimeCheck(), make_ctx(commands={ANALYZE: res}))
    assert r.status is Status.ERROR
    assert r.error == "CommandFailed: Failed to connect: something odd"


class UnreadableGrub(FakeSystem):
    def read_text(self, path: str) -> str | None:
        return None if path == "/boot/grub/grub.cfg" else super().read_text(path)


def test_bootloader_unreadable_grub_cfg() -> None:
    system = UnreadableGrub(
        files={"/etc/os-release": OS_RELEASE, "/boot/grub/grub.cfg": ""}, available=set()
    )
    (f,) = BootloaderCheck().run(Context(system, detect_os(system)))
    assert (f.severity, f.title) == (Severity.INFO, "/boot/grub/grub.cfg is not readable")


def test_bootloader_efibootmgr_failure_is_info() -> None:
    files = {"/sys/firmware/efi/fw_platform_size": "64"}
    res = CommandResult(("efibootmgr", "-v"), 2, "", "EFI variables are not supported\n")
    fs = BootloaderCheck().run(make_ctx(files=files, commands={("efibootmgr", "-v"): res}))
    assert titles(fs) == ["efibootmgr could not read UEFI boot entries"]


def test_dkms_lines_without_status_ignored() -> None:
    assert parse_dkms_status("Error! garbage\nzfs/2.2, 6.1.0: installed\n")[0].name == "zfs"


def test_dmesg_other_failure_is_an_error() -> None:
    res = CommandResult(DMESG_ERR, 1, "", "dmesg: klogctl failed: Input/output error\n")
    r = run_check(DmesgErrorsCheck(), make_ctx(commands={DMESG_ERR: res}))
    assert r.status is Status.ERROR
    assert "klogctl failed" in (r.error or "")


def test_journal_odd_entries() -> None:
    assert _message([1, "x"]) == "[1, 'x']"  # not a byte array
    out = "\n".join(["[1, 2]", json.dumps({"MESSAGE": "real", "_COMM": "x"})])
    (f,) = JournalErrorsCheck().run(make_ctx(commands={JOURNAL: out}))
    assert f.evidence == ["1x x: real"]


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [("1.2", "1.3", -1), ("1.10", "1.9", 1), ("x:1.0", "1.0", 1), ("1.0", "1.0-1", -1)],
)
def test_compare_versions_more(a: str, b: str, expected: int) -> None:
    assert compare_versions(a, b) == expected


def test_installed_versions_skips_malformed_lines() -> None:
    ctx = make_ctx(commands={PKG_VERSIONS_ARGV: "bash\t5.2\nbroken-line\n\t\n"})
    assert installed_versions(ctx) == {"bash": "5.2"}


# --- model, osinfo, render -----------------------------------------------------------


def test_unknown_category_sorts_last() -> None:
    results = [CheckResult("a", "", "weird", Status.OK), CheckResult("b", "", "storage", Status.OK)]
    assert [r.id for r in sort_results(results)] == ["b", "a"]


def test_os_release_unbalanced_quote_and_family_mismatch() -> None:
    assert parse_os_release('NAME="Debian\n')["NAME"] == "Debian"
    info = detect_os(FakeSystem(files={"/etc/os-release": "ID=ubuntu\nVERSION_CODENAME=trixie\n"}))
    assert info.release is None


def test_valid_utf8_with_non_escape_surrogate() -> None:
    assert valid_utf8("a\ud800b") == "a?b"


def test_baseline_state_without_baseline() -> None:
    r = make_sample_report()
    r.baseline = None
    assert baseline_state(r, r.results[0]) == NO_BASELINE


@pytest.mark.parametrize("fmt", ["text", "html", "markdown", "jira", "confluence"])
def test_errored_check_is_rendered(fmt: str) -> None:
    r = make_sample_report()
    r.results[2] = CheckResult(
        "fstab", "fstab", "storage", Status.ERROR, error="CommandFailed: boom"
    )
    assert "CommandFailed: boom" in render(r, fmt)


def test_markdown_fence_longer_than_backticks_in_evidence() -> None:
    r = make_sample_report()
    r.results[0].findings[1] = Finding(Severity.INFO, "t", evidence=["```", "````"])
    assert "`````\n" in render(r, "markdown")


def test_html_finding_without_remediation() -> None:
    r = make_sample_report()
    r.results[0].findings[1] = Finding(Severity.INFO, "bare", references=["https://x.example"])
    out = render(r, "html")
    assert "bare" in out
    assert 'href="https://x.example"' in out


# --- snapshots -----------------------------------------------------------------------


def test_snapshot_records_checks_without_data_as_skipped() -> None:
    class NoData(Check):
        id = "no-data"

        def collect_baseline(self, ctx: Context) -> Any:
            return None

    snap = build_snapshot([NoData()], make_ctx(commands={("uname", "-r"): "x\n"}))
    assert snap["skipped"] == ["no-data"]


def test_snapshot_without_checks_section(tmp_path: Path) -> None:
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"schema_version": "1", "checks": []}))
    with pytest.raises(SnapshotError, match="no checks section"):
        load_snapshot(str(p))


def test_find_latest_unreadable_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def broken_glob(self: Path, pattern: str) -> Any:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "glob", broken_glob)
    assert find_latest(str(tmp_path)) is None


def test_baseline_warnings_without_os_info() -> None:
    assert baseline_warnings({"hostname": "h"}, "h", "trixie") == []


# --- config --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (
            "report:\n  min_severity: loud\n",
            "report.min_severity: must be one of info, warning, critical",
        ),
        ("report:\n  color: maybe\n", "report.color: expected true or false"),
        ("report:\n  output_dir: [a]\n", "report.output_dir: expected a directory path or null"),
        ("report:\n  baseline: ''\n", "report.baseline: expected a non-empty string"),
        ("checks:\n  disk-space: [1]\n", "checks.disk-space: expected a mapping"),
    ],
)
def test_report_and_check_section_errors(text: str, message: str) -> None:
    with pytest.raises(ConfigError) as exc:
        parse_config(text, "x.conf")
    assert any(message in e for e in exc.value.errors), exc.value.errors


def test_check_section_without_values_is_fine() -> None:
    assert parse_config("checks:\n  disk-space:\n", "x.conf").check_settings == {}


def test_config_unreadable_formats(tmp_path: Path) -> None:
    bad = tmp_path / "bad.conf"
    bad.write_bytes(b"report:\n  format: \xff\n")
    with pytest.raises(ConfigError, match="cannot read config file"):
        load_config(str(bad))
    with pytest.raises(ConfigError, match="cannot read config file"):
        load_config(str(tmp_path))  # a directory


# --- completion ----------------------------------------------------------------------


def test_help_with_unknown_placeholder_is_left_alone() -> None:
    action = argparse.Action(["--x"], "x", help="see %(nope)s")
    assert _help(action, "prog") == "see %(nope)s"


def test_free_text_options_and_positionals(monkeypatch: pytest.MonkeyPatch) -> None:
    def build() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog="pydebuprep")
        parser.add_argument("topic", nargs="?")  # top-level positional
        sub = parser.add_subparsers(dest="command")
        report = sub.add_parser("report", help="r")
        report.add_argument("--label", help="free text")
        report.add_argument("name")  # positional without choices
        return parser

    monkeypatch.setattr("pydebuprep.cli.build_parser", build)
    script = bash_completion()
    assert "--label)\n            :\n" in script


# --- cli -----------------------------------------------------------------------------


def run(args: list[str], **kw: Any) -> int:
    system = FakeSystem(
        files={"/etc/os-release": OS_RELEASE}, commands={("uname", "-r"): "6.12\n"}, **kw
    )
    return cli.main(args, system=system)


class Quiet(Check):
    id = "quiet"
    title = "Quiet"
    category = "storage"

    def run(self, ctx: Context) -> list[Finding]:
        return []


@pytest.fixture
def quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checks, "ALL_CHECKS", [Quiet])


@pytest.mark.skipif(__import__("os").geteuid() == 0, reason="root can write anywhere")
def test_read_only_output_dir(
    tmp_path: Path, quiet: None, capsys: pytest.CaptureFixture[str]
) -> None:
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o555)
    try:
        assert run(["--output-dir", str(ro), "--no-baseline"]) == 3
        assert "is not writable" in capsys.readouterr().err
    finally:
        ro.chmod(0o755)


def test_write_failure_after_checks(
    tmp_path: Path, quiet: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "_ensure_writable_dir", lambda *a: None)
    assert run(["--output", str(tmp_path / "missing" / "r.txt"), "--no-baseline"]) == 3
    assert "cannot write" in capsys.readouterr().err


def test_unknown_kernel_when_uname_fails(quiet: None, capsys: pytest.CaptureFixture[str]) -> None:
    system = FakeSystem(
        files={"/etc/os-release": OS_RELEASE},
        commands={("uname", "-r"): CommandResult(("uname", "-r"), 1, "", "")},
    )
    cli.main(["--no-baseline", "--format", "json"], system=system)
    assert json.loads(capsys.readouterr().out)["host"]["kernel"] == "unknown"


def test_list_checks_verbose_shows_bools_and_lists(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["list-checks", "--verbose"]) == 0
    out = capsys.readouterr().out
    assert "include_remote = false" in out
    assert "exclude_mounts = (empty)" in out
    assert "critical_paths = /etc/ssh/sshd_config," in out


def test_configtest_no_config(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["configtest", "--no-config"]) == 0
    assert "Config file ignored (--no-config)" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("shell", "marker"), [("bash", "complete -F _pydebuprep"), ("zsh", "#compdef")]
)
def test_completion_command(shell: str, marker: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["completion", shell]) == 0
    assert marker in capsys.readouterr().out


def test_ctrl_c_exits_130(monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupted(*args: Any) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "cmd_report", interrupted)
    assert run(["--no-baseline"]) == 130


def test_python_dash_m_entry_point(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["pydebuprep", "--version"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("pydebuprep", run_name="__main__")
    assert exc.value.code == 0
    assert "pydebuprep" in capsys.readouterr().out
