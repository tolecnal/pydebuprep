"""The README, man page and package description must keep up with the code."""

from __future__ import annotations

import re
from pathlib import Path

from pydebuprep import checks
from pydebuprep.model import CATEGORY_ORDER

ROOT = Path(__file__).resolve().parent.parent
REPORT_ORDER = sorted(checks.ALL_CHECKS, key=lambda c: (CATEGORY_ORDER.index(c.category), c.id))


def _readme_checks_table() -> list[tuple[str, str]]:
    lines = (ROOT / "README.md").read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("| ID | Category |"))
    rows = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip("|").split("|")]
        rows.append((cells[0].strip("`"), cells[1]))
    return rows


def test_readme_lists_every_check_in_report_order() -> None:
    assert _readme_checks_table() == [(c.id, c.category) for c in REPORT_ORDER]


def _man_checks_section() -> str:
    text = (ROOT / "man" / "pydebuprep.1").read_text()
    section = text.split("\n.SH CHECKS\n", 1)[1].split("\n.SH ", 1)[0]
    return section.replace("\\-", "-")


def test_man_page_lists_every_check_in_report_order() -> None:
    found = re.findall(r"^\.TP\n\.B ([a-z0-9-]+)\n", _man_checks_section(), re.MULTILINE)
    assert found == [c.id for c in REPORT_ORDER]


def test_man_page_checks_name_their_category() -> None:
    section = _man_checks_section()
    for cls in checks.ALL_CHECKS:
        entry = section.split(f".B {cls.id}\n", 1)[1].split("\n.TP\n", 1)[0]
        assert f"({cls.category}" in entry, cls.id


def test_man_page_version_matches_package() -> None:
    from pydebuprep import __version__

    header = (ROOT / "man" / "pydebuprep.1").read_text().splitlines()[0]
    assert f'"pydebuprep {__version__}"' in header


def test_categories_documented() -> None:
    readme = (ROOT / "README.md").read_text()
    man = (ROOT / "man" / "pydebuprep.1").read_text().replace("\\-", "-")
    for category in CATEGORY_ORDER:
        assert f"| {category} |" in readme, category
        assert category in man, category


def test_readme_check_count() -> None:
    assert f"[{len(checks.ALL_CHECKS)} checks](#checks)" in (ROOT / "README.md").read_text()
