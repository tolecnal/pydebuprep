from __future__ import annotations

import argparse
from pathlib import Path

from pydebuprep.cli import build_parser

MANPAGE = Path(__file__).resolve().parent.parent / "man" / "pydebuprep.1"


def _long_options(parser: argparse.ArgumentParser) -> set[str]:
    opts = set()
    for action in parser._actions:
        opts.update(o for o in action.option_strings if o.startswith("--"))
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                opts |= _long_options(sub)
    return opts


def test_manpage_mentions_every_option() -> None:
    text = MANPAGE.read_text().replace("\\-", "-")
    missing = sorted(o for o in _long_options(build_parser()) if o not in text)
    assert missing == []


def test_manpage_mentions_every_command() -> None:
    text = MANPAGE.read_text().replace("\\-", "-")
    for command in ("report", "snapshot", "list-checks"):
        assert command in text


def test_cleanup_man_page_lists_every_option() -> None:
    from pydebuprep.cleanup.cli import build_parser as cleanup_parser

    page = MANPAGE.parent / "pydebuprep-cleanup.8"
    text = page.read_text().replace("\\-", "-")
    assert text.startswith(".TH PYDEBUPREP-CLEANUP 8")
    missing = sorted(o for o in _long_options(cleanup_parser()) if o not in text)
    assert missing == []
    for words in (
        "/var/log/pydebuprep/cleanup.log",
        "/var/backups/pydebuprep",
        "journalctl -t pydebuprep-cleanup",
    ):
        assert words in text
    assert (
        "man/pydebuprep-cleanup.8"
        in (MANPAGE.parent.parent / "debian" / "pydebuprep.manpages").read_text()
    )
