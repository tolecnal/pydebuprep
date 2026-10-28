"""Shell completions are generated from the parser and registry, and must stay in sync."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from pydebuprep import checks
from pydebuprep.completion import bash_completion, completion_spec, zsh_completion
from pydebuprep.render import FORMATS

ROOT = Path(__file__).resolve().parent.parent
BASH_FILE = ROOT / "completions" / "bash" / "pydebuprep"
ZSH_FILE = ROOT / "completions" / "zsh" / "_pydebuprep"
BASH_COMPLETION = Path("/usr/share/bash-completion/bash_completion")


def test_spec_covers_every_command_and_option() -> None:
    spec = completion_spec()
    assert set(spec.commands) == {
        "report",
        "snapshot",
        "list-checks",
        "configtest",
        "example-config",
        "completion",
    }
    report = {o.flags[0]: o for o in spec.commands["report"].options}
    assert report["--format"].choices == list(FORMATS)
    assert report["--checks"].kind == "checks"
    assert report["--check-option"].kind == "check-options"
    assert report["--config"].kind == "file"
    assert report["--output-dir"].kind == "dir"
    assert report["--check-option"].repeatable
    assert spec.check_ids == sorted(cls.id for cls in checks.ALL_CHECKS)
    expected = sorted(f"{cls.id}.{o.name}=" for cls in checks.ALL_CHECKS for o in cls.options)
    assert spec.check_options == expected


def test_shipped_files_match_generator() -> None:
    hint = "regenerate with: make generated"
    assert BASH_FILE.read_text() == bash_completion(), hint
    assert ZSH_FILE.read_text() == zsh_completion(), hint


def test_every_check_and_option_in_both_scripts() -> None:
    bash, zsh = bash_completion(), zsh_completion()
    for cls in checks.ALL_CHECKS:
        assert cls.id in bash
        assert cls.id in zsh
        for option in cls.options:
            assert f"{cls.id}.{option.name}=" in bash
            assert f"{cls.id}.{option.name}=" in zsh


def test_zsh_syntax() -> None:
    if not shutil.which("zsh"):
        pytest.skip("zsh not installed")
    res = subprocess.run(
        ["zsh", "-n", "-c", zsh_completion()], capture_output=True, text=True, check=False
    )
    assert res.returncode == 0, res.stderr


def bash_complete(line: str) -> list[str]:
    """Run the generated completion in a real bash with bash-completion loaded."""
    script = f"""
source {BASH_COMPLETION}
source /dev/stdin <<'PYDEBUPREP_EOF'
{bash_completion()}
PYDEBUPREP_EOF
COMP_LINE={line!r}
COMP_POINT=${{#COMP_LINE}}
read -ra COMP_WORDS <<< "$COMP_LINE"
[[ "$COMP_LINE" == *" " ]] && COMP_WORDS+=("")
COMP_CWORD=$(( ${{#COMP_WORDS[@]}} - 1 ))
_pydebuprep pydebuprep "${{COMP_WORDS[COMP_CWORD]}}" "${{COMP_WORDS[COMP_CWORD-1]}}"
printf '%s\\n' "${{COMPREPLY[@]}}"
"""
    res = subprocess.run(
        ["bash", "--norc", "-c", script], capture_output=True, text=True, check=False
    )
    assert res.returncode == 0, res.stderr
    return [w for w in res.stdout.splitlines() if w]


needs_bash_completion = pytest.mark.skipif(
    not BASH_COMPLETION.exists(), reason="bash-completion not installed"
)


@needs_bash_completion
@pytest.mark.parametrize(
    ("line", "expected", "absent"),
    [
        ("pydebuprep ", ["report", "configtest", "example-config"], []),
        ("pydebuprep conf", ["configtest"], ["report"]),
        ("pydebuprep --for", ["--format"], []),
        ("pydebuprep report --format ", list(FORMATS), []),
        ("pydebuprep --format ji", ["jira"], ["json"]),
        ("pydebuprep report --min-severity ", ["info", "warning", "critical"], []),
        ("pydebuprep report --checks disk", ["disk-space"], []),
        ("pydebuprep report --skip apt-held,dis", ["apt-held,disk-space"], []),
        ("pydebuprep --check-option disk-space.inc", ["disk-space.include_remote="], []),
        ("pydebuprep snapshot --", ["--snapshot-dir", "--config", "--check-option"], ["--format"]),
        ("pydebuprep configtest --", ["--config", "--no-config"], ["--format"]),
        ("pydebuprep list-checks --", ["--verbose"], []),
        ("pydebuprep completion ", ["bash", "zsh"], []),
        # Subcommands are only valid as the first word.
        ("pydebuprep --no-color ", [], ["snapshot", "report"]),
        ("pydebuprep -o report --", ["--format"], []),
        ("pydebuprep --no-color --", ["--format"], ["--version"]),
        # items already in the list aren't offered again
        ("pydebuprep report --skip apt-held,apt-h", [], ["apt-held,apt-held"]),
    ],
)
def test_bash_completes(line: str, expected: list[str], absent: list[str]) -> None:
    got = bash_complete(line)
    for word in expected:
        assert word in got, (line, got)
    for word in absent:
        assert word not in got, (line, got)


PTY_HARNESS = r"""
# Type a line and press TAB in a real interactive shell, then press Ctrl-X Ctrl-P, which
# SETUP binds to print the line editor's buffer as BUF<...>. Waits on markers, not sleeps.
zmodload zsh/zpty
zpty z "env -i HOME=/tmp TERM=dumb PATH=/usr/bin:/bin $SHELLCMD"
wait_for() {
    local chunk i
    for i in {1..150}; do
        zpty -r -t z chunk && out+=$chunk
        [[ $out == $~1 ]] && return 0
        sleep 0.1
    done
    return 1
}
local out=""
zpty -w z "$SETUP"
zpty -w z 'echo RE''ADY'
wait_for '*READY*'
sleep 0.3
out=""
zpty -w -n z "pydebuprep $LINE"$'\t'
sleep 0.5
zpty -w -n z $'\x18\x10'
wait_for '*BUF<*>*'
print -r -- "$out"
zpty -d z
"""

BASH_SETUP = (
    "PS1='> '; bind 'set enable-bracketed-paste off' 2>/dev/null; "
    'bind -x \'"\\C-x\\C-p": echo "BUF<$READLINE_LINE>"\'; '
    "{bc}source {script}; pydebuprep() {{ :; }}"
)
ZSH_SETUP = (
    "unsetopt zle_bracketed_paste 2>/dev/null; PS1='> '; {fpath}"
    "autoload -Uz compinit; compinit -u -D; {source}pydebuprep() {{ :; }}; "
    '_show_buf() {{ zle -I; print -r -- "BUF<$BUFFER>"; }}; zle -N _show_buf; '
    "bindkey '^X^P' _show_buf"
)


def pty_complete(shell: str, setup: str, line: str) -> str:
    """Type LINE<TAB> into a real interactive shell and return the resulting command line."""
    res = subprocess.run(
        ["zsh", "-f", "-c", PTY_HARNESS],
        capture_output=True,
        text=True,
        check=False,
        env={"SHELLCMD": shell, "SETUP": setup, "LINE": line, "PATH": "/usr/bin:/bin"},
        timeout=60,
    )
    found = re.findall(r"BUF<(.*?)>", res.stdout.replace("\r", ""))
    return found[-1].rstrip() if found else ""


def zsh_complete(tmp_path: Path, line: str, *, sourced: bool = False) -> str:
    compdir = tmp_path / "zfunc"
    compdir.mkdir(exist_ok=True)
    script = compdir / "_pydebuprep"
    script.write_text(zsh_completion())
    setup = ZSH_SETUP.format(
        fpath="" if sourced else f"fpath=({compdir} $fpath); ",
        source=f"source {script}; " if sourced else "",
    )
    return pty_complete("zsh -f -i", setup, line)


def bash_pty_complete(
    tmp_path: Path, line: str, *, with_bash_completion: bool = True, cwd: Path | None = None
) -> str:
    script = tmp_path / "pydebuprep.bash"
    script.write_text(bash_completion())
    bc = f"source {BASH_COMPLETION}; " if with_bash_completion else ""
    if cwd is not None:
        bc = f"cd {cwd}; " + bc
    return pty_complete("bash --norc --noprofile -i", BASH_SETUP.format(bc=bc, script=script), line)


needs_zsh = pytest.mark.skipif(not shutil.which("zsh"), reason="zsh not installed")


@needs_zsh
@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("--format ji", "pydebuprep --format jira"),
        # long options taking a value complete with '=' so the value can follow directly
        ("report --min-sev", "pydebuprep report --min-severity="),
        ("--check-option disk-space.inc", "pydebuprep --check-option disk-space.include_remote="),
        ("conf", "pydebuprep configtest"),
        ("report --checks disk-sp", "pydebuprep report --checks disk-space,"),
        ("completion z", "pydebuprep completion zsh"),
        ("snapshot --snap", "pydebuprep snapshot --snapshot-dir="),
        ("--vers", "pydebuprep --version"),
        # --version is only valid as the first word
        ("report --vers", "pydebuprep report --vers"),
        ("--no-color --vers", "pydebuprep --no-color --vers"),
    ],
)
def test_zsh_completes(tmp_path: Path, line: str, expected: str) -> None:
    assert zsh_complete(tmp_path, line) == expected


@needs_zsh
def test_zsh_script_works_when_sourced(tmp_path: Path) -> None:
    assert zsh_complete(tmp_path, "--format ji", sourced=True) == "pydebuprep --format jira"


@needs_zsh
@needs_bash_completion
@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("--format ji", "pydebuprep --format jira"),
        ("--check-option disk-space.inc", "pydebuprep --check-option disk-space.include_remote="),
        # TAB after the '=' must not repeat the option name
        (
            "--check-option disk-space.warning_pct=",
            "pydebuprep --check-option disk-space.warning_pct=",
        ),
        (
            "--check-option disk-space.include_remote=t",
            "pydebuprep --check-option disk-space.include_remote=true",
        ),
        ("--vers", "pydebuprep --version"),
        ("--no-color --vers", "pydebuprep --no-color --vers"),
        ("report --vers", "pydebuprep report --vers"),
    ],
)
def test_bash_completes_interactively(tmp_path: Path, line: str, expected: str) -> None:
    assert bash_pty_complete(tmp_path, line) == expected


@needs_zsh
def test_bash_script_works_without_bash_completion(tmp_path: Path) -> None:
    got = bash_pty_complete(tmp_path, "--format ji", with_bash_completion=False)
    assert got == "pydebuprep --format jira"


def _parser_with(**kwargs: object) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pydebuprep")
    sub = parser.add_subparsers(dest="command")
    report = sub.add_parser("report", help="r")
    report.add_argument("--thing", **kwargs)  # type: ignore[arg-type]
    return parser


@pytest.mark.parametrize("choice", ["a b", "c$x", "it's", "q`x`", 'd"e'])
def test_unsafe_choices_rejected_at_generation(
    monkeypatch: pytest.MonkeyPatch, choice: str
) -> None:
    monkeypatch.setattr("pydebuprep.cli.build_parser", lambda: _parser_with(choices=["ok", choice]))
    with pytest.raises(ValueError, match="cannot be completed safely"):
        bash_completion()
    with pytest.raises(ValueError, match="cannot be completed safely"):
        zsh_completion()


def test_flag_with_different_values_per_command_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    def build() -> argparse.ArgumentParser:
        parser = _parser_with(choices=["a", "b"])
        sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
        other = sub.add_parser("other", help="o")
        other.add_argument("--thing", choices=["x", "y"])
        return parser

    monkeypatch.setattr("pydebuprep.cli.build_parser", build)
    with pytest.raises(ValueError, match="--thing completes differently"):
        bash_completion()


def test_help_placeholders_expanded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pydebuprep.cli.build_parser",
        lambda: _parser_with(default="7", help="use %(default)s or 100%% of %(prog)s"),
    )
    (opt,) = [o for o in completion_spec().commands["report"].options if "--thing" in o.flags]
    assert opt.help == "use 7 or 100% of pydebuprep"


def test_mutually_exclusive_flags_recorded() -> None:
    report = {o.flags[0]: o for o in completion_spec().commands["report"].options}
    assert set(report["--baseline"].exclusive) == {"--no-baseline"}
    assert set(report["--output"].exclusive) == {"--output-dir"}
    assert set(report["--config"].exclusive) == {"--no-config"}
    assert report["--format"].exclusive == []


@needs_zsh
@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("--no-baseline --basel", "pydebuprep --no-baseline --basel"),
        ("report --output-dir /tmp --outp", "pydebuprep report --output-dir /tmp --outp"),
        ("--format=ji", "pydebuprep --format=jira"),
        ("report --min-severity=crit", "pydebuprep report --min-severity=critical"),
    ],
)
def test_zsh_exclusions_and_equals_forms(tmp_path: Path, line: str, expected: str) -> None:
    assert zsh_complete(tmp_path, line) == expected


@needs_zsh
@needs_bash_completion
@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("--format=ji", "pydebuprep --format=jira"),
        ("report --min-severity=crit", "pydebuprep report --min-severity=critical"),
        ("--checks=disk-sp", "pydebuprep --checks=disk-space"),
        ("--skip=apt-held,dis", "pydebuprep --skip=apt-held,disk-space"),
    ],
)
def test_bash_equals_forms(tmp_path: Path, line: str, expected: str) -> None:
    assert bash_pty_complete(tmp_path, line) == expected


@needs_zsh
@pytest.mark.parametrize("with_bash_completion", [True, False])
def test_bash_file_names_with_spaces(tmp_path: Path, with_bash_completion: bool) -> None:
    if with_bash_completion and not BASH_COMPLETION.exists():
        pytest.skip("bash-completion not installed")
    work = tmp_path / "work"
    work.mkdir()
    (work / "my report.conf").write_text("")
    got = bash_pty_complete(
        tmp_path, "--config my", with_bash_completion=with_bash_completion, cwd=work
    )
    assert got == r"pydebuprep --config my\ report.conf"
