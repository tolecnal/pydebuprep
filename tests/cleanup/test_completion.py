"""bash and zsh completions for pydebuprep-cleanup, generated from its parser."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from pydebuprep.cleanup.cli import build_parser
from pydebuprep.cleanup.completion import bash_completion, zsh_completion

ROOT = Path(__file__).resolve().parent.parent.parent
BASH_FILE = ROOT / "completions" / "bash" / "pydebuprep-cleanup"
ZSH_FILE = ROOT / "completions" / "zsh" / "_pydebuprep-cleanup"


def options() -> list[str]:
    return [o for a in build_parser()._actions for o in a.option_strings if o.startswith("--")]


def test_shipped_files_match_generator() -> None:
    hint = "regenerate with: make generated"
    assert BASH_FILE.read_text() == bash_completion(), hint
    assert ZSH_FILE.read_text() == zsh_completion(), hint


def test_every_option_in_both_scripts() -> None:
    bash, zsh = bash_completion(), zsh_completion()
    for option in options():
        assert option in bash and option in zsh, option
    assert zsh.startswith("#compdef pydebuprep-cleanup")


def test_package_install_paths() -> None:
    install = (ROOT / "debian" / "pydebuprep.install").read_text()
    assert "completions/bash/pydebuprep-cleanup usr/share/bash-completion/completions/" in install
    assert "completions/zsh/_pydebuprep-cleanup usr/share/zsh/vendor-completions/" in install


def test_zsh_syntax() -> None:
    if not shutil.which("zsh"):
        pytest.skip("zsh not installed")
    res = subprocess.run(
        ["zsh", "-n", "-c", zsh_completion()], capture_output=True, text=True, check=False
    )
    assert res.returncode == 0, res.stderr


def bash_complete(line: str, tmp_path: Path) -> list[str]:
    """Run the generated completion in a plain bash (no bash-completion needed)."""
    fake = tmp_path / "bin"
    fake.mkdir(exist_ok=True)
    (fake / "dpkg-query").write_text("#!/bin/sh\nprintf 'hello\\nhelloworld\\nlibfoo1:i386\\n'\n")
    (fake / "dpkg-query").chmod(0o755)
    script = f"""
PATH={fake}:$PATH
source /dev/stdin <<'PYDEBUPREP_EOF'
{bash_completion()}
PYDEBUPREP_EOF
COMP_LINE={line!r}
COMP_POINT=${{#COMP_LINE}}
read -ra COMP_WORDS <<< "$COMP_LINE"
[[ "$COMP_LINE" == *" " ]] && COMP_WORDS+=("")
COMP_CWORD=$(( ${{#COMP_WORDS[@]}} - 1 ))
_pydebuprep_cleanup pydebuprep-cleanup "${{COMP_WORDS[COMP_CWORD]}}" "${{COMP_WORDS[COMP_CWORD-1]}}"
printf '%s\\n' "${{COMPREPLY[@]}}"
"""
    res = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=False, cwd=tmp_path
    )
    assert res.returncode == 0, res.stderr
    return [w for w in res.stdout.splitlines() if w]


@pytest.mark.parametrize(
    "line,expected,absent",
    [
        (
            "pydebuprep-cleanup --",
            ["--kernels", "--apply", "--keep-package", "--leftover-dirs"],
            [],
        ),
        ("pydebuprep-cleanup --re", ["--residual"], ["--kernels"]),
        ("pydebuprep-cleanup --keep ", ["1", "2", "10"], ["--apply"]),
        ("pydebuprep-cleanup --keep-package hel", ["hello", "helloworld"], ["libfoo1:i386"]),
    ],
)
def test_bash_completes(tmp_path: Path, line: str, expected: list[str], absent: list[str]) -> None:
    words = bash_complete(line, tmp_path)
    for word in expected:
        assert word in words, (line, words)
    for word in absent:
        assert word not in words, (line, words)


def test_bash_completes_config_files(tmp_path: Path) -> None:
    (tmp_path / "pydebuprep.conf").write_text("")
    assert "pydebuprep.conf" in bash_complete("pydebuprep-cleanup --config pyd", tmp_path)


def test_main_prints_a_script(capsys: pytest.CaptureFixture[str]) -> None:
    from pydebuprep.cleanup.completion import main

    assert main(["bash"]) == 0 and capsys.readouterr().out == bash_completion()
    assert main(["zsh"]) == 0 and capsys.readouterr().out == zsh_completion()
    assert main(["fish"]) == 2
