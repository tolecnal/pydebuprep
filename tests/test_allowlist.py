from __future__ import annotations

import re
from pathlib import Path

import pytest

from fakes import FakeSystem
from pydebuprep import checks
from pydebuprep.checks.base import CheckSkipped, Context
from pydebuprep.cli import main
from pydebuprep.model import CATEGORY_ORDER
from pydebuprep.osinfo import detect_os
from pydebuprep.render import FORMATS
from pydebuprep.system import APT_PROGRAMS, APT_RO_OPTS, check_allowed

SRC = Path(__file__).resolve().parent.parent / "src" / "pydebuprep"
OS_RELEASE = 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n'


def recording() -> FakeSystem:
    return FakeSystem(files={"/etc/os-release": OS_RELEASE}, strict=False)


def run_everything(system: FakeSystem) -> None:
    ctx = Context(system, detect_os(system))
    for check in checks.get_checks():
        try:
            check.run(ctx)
            data = check.collect_baseline(ctx)
            if data is not None:
                check.compare(ctx, data)
        except CheckSkipped:
            pass


def test_every_check_command_is_allowed() -> None:
    system = recording()
    run_everything(system)  # FakeSystem.run raises DisallowedCommandError on any violation
    assert system.calls
    for argv in system.calls:
        check_allowed(argv)


def test_all_apt_calls_use_ro_opts() -> None:
    system = recording()
    run_everything(system)
    apt_calls = [a for a in system.calls if a[0] in APT_PROGRAMS]
    assert apt_calls
    for argv in apt_calls:
        assert argv[1 : 1 + len(APT_RO_OPTS)] == APT_RO_OPTS, argv


def _sources() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def test_no_subprocess_outside_system() -> None:
    for path in _sources():
        text = path.read_text()
        if path.name != "system.py":
            assert "subprocess" not in text, path
            assert "os.walk" not in text, path


def test_open_only_where_writes_are_expected() -> None:
    allowed = {"system.py", "snapshot.py", "cli.py"}
    for path in _sources():
        if path.name not in allowed:
            assert not re.search(r"\bopen\(", path.read_text()), path


def test_registry_ids_unique_and_kebab() -> None:
    ids = [cls.id for cls in checks.ALL_CHECKS]
    assert len(ids) == 23
    assert len(set(ids)) == len(ids)
    for cls in checks.ALL_CHECKS:
        assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", cls.id), cls.id
        assert cls.category in CATEGORY_ORDER, cls.id
        assert cls.title, cls.id


@pytest.mark.parametrize("fmt", FORMATS)
def test_full_report_on_empty_system_renders_all_formats(
    fmt: str, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["report", "--format", fmt, "--no-baseline"], system=recording())
    assert rc in (0, 1, 2)
    out = capsys.readouterr().out
    assert "Traceback" not in out
    assert '"status": "error"' not in out
    assert "[ERROR]" not in out


def test_full_report_non_root_has_no_errors(capsys: pytest.CaptureFixture[str]) -> None:
    system = recording()
    system.root = False
    main(["report", "--format", "json", "--no-baseline"], system=system)
    assert '"status": "error"' not in capsys.readouterr().out
