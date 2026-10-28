"""Shell completions are generated from the parser and registry, and must stay in sync."""

from __future__ import annotations

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
    ],
)
def test_bash_completes(line: str, expected: list[str], absent: list[str]) -> None:
    got = bash_complete(line)
    for word in expected:
        assert word in got, (line, got)
    for word in absent:
        assert word not in got, (line, got)


ZSH_HARNESS = r"""
zmodload zsh/zpty
zpty z 'env -i HOME=/tmp TERM=dumb PATH=/usr/bin:/bin zsh -f -i'
zpty -w z "unsetopt zle_bracketed_paste 2>/dev/null; PS1='> '; fpath=($COMPDIR \$fpath); autoload -Uz compinit; compinit -u -D; pydebuprep() { :; }"
sleep 0.5
local junk; while zpty -r -t z junk; do :; done
zpty -w -n z "pydebuprep $LINE"$'\t'
sleep 1
local out="" chunk
while zpty -r -t z chunk; do out+=$chunk; done
print -r -- "$out"
zpty -d z
"""


def zsh_complete(tmp_path: Path, line: str) -> str:
    """Type LINE<TAB> into a real interactive zsh and return the resulting command line."""
    compdir = tmp_path / "zfunc"
    compdir.mkdir(exist_ok=True)
    (compdir / "_pydebuprep").write_text(zsh_completion())
    res = subprocess.run(
        ["zsh", "-f", "-c", ZSH_HARNESS],
        capture_output=True,
        text=True,
        check=False,
        env={"COMPDIR": str(compdir), "LINE": line, "PATH": "/usr/bin:/bin"},
        timeout=30,
    )
    screen = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", res.stdout.replace("\r", ""))
    lines = [s for s in screen.splitlines() if "pydebuprep " in s]
    return lines[-1].split("> ", 1)[-1].strip() if lines else ""


@pytest.mark.skipif(not shutil.which("zsh"), reason="zsh not installed")
@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("--format ji", "pydebuprep --format jira"),
        ("report --min-sev", "pydebuprep report --min-severity"),
        ("--check-option disk-space.inc", "pydebuprep --check-option disk-space.include_remote="),
        ("conf", "pydebuprep configtest"),
        ("report --checks disk-sp", "pydebuprep report --checks disk-space,"),
        ("completion z", "pydebuprep completion zsh"),
        ("snapshot --snap", "pydebuprep snapshot --snapshot-dir"),
    ],
)
def test_zsh_completes(tmp_path: Path, line: str, expected: str) -> None:
    assert zsh_complete(tmp_path, line) == expected
