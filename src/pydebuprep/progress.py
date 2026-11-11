"""Says which check is running, on stderr: a report on stdout stays as it is, and a slow
check, such as debsums, doesn't look like a hang.

At a terminal it's one line, rewritten for each check and cleared at the end. Elsewhere
nothing is shown unless asked for (--progress), and then as a line for each check, so a log
doesn't fill with control characters.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from typing import TextIO

from pydebuprep.checks.base import Check

BAR_WIDTH = 10
DEFAULT_COLUMNS = 80
CLEAR_TO_END = "\x1b[K"


class Progress:
    def __init__(self, stream: TextIO, *, live: bool, columns: int | None = None) -> None:
        self.stream = stream
        self.live = live
        self.columns = columns

    def _write(self, text: str) -> None:
        try:
            self.stream.write(text)
            self.stream.flush()
        except (OSError, ValueError):  # a closed terminal mustn't stop the checks
            pass

    def _terminal_columns(self) -> int:
        """The width of the terminal written to. Not stdout's, which is often a file or a
        pipe while stderr is the terminal."""
        try:
            return os.get_terminal_size(self.stream.fileno()).columns
        except (OSError, ValueError):  # io.UnsupportedOperation is both
            return DEFAULT_COLUMNS

    def start(self, index: int, total: int, check: Check) -> None:
        """Check INDEX of TOTAL is about to run."""
        what = f"{check.id}: {check.title}"
        if not self.live:
            self._write(f"pydebuprep: [{index}/{total}] {what}\n")
            return
        done = (index - 1) * BAR_WIDTH // total
        bar = "#" * done + "-" * (BAR_WIDTH - done)
        line = f"[{index:>{len(str(total))}}/{total}] [{bar}] {what}"
        # One short of the width: writing in the last column makes some terminals wrap.
        room = (self.columns or self._terminal_columns()) - 1
        if len(line) > room:
            line = line[: room - 1] + "…"
        self._write(f"\r{line}{CLEAR_TO_END}")

    def finish(self) -> None:
        if self.live:
            self._write(f"\r{CLEAR_TO_END}")


def tracked(checks: Sequence[Check], progress: Progress | None) -> Iterator[Check]:
    """CHECKS, each announced before it's handed out. The line is cleared at the end, however
    the loop using this ends."""
    if progress is None:
        yield from checks
        return
    try:
        for index, check in enumerate(checks, 1):
            progress.start(index, len(checks), check)
            yield check
    finally:
        progress.finish()


def choose(wanted: bool | None, stream: TextIO) -> Progress | None:
    """WANTED is --progress (True), --no-progress (False) or neither: then only at a terminal."""
    terminal = stream.isatty() and os.environ.get("TERM") != "dumb"
    if wanted is False or (wanted is None and not terminal):
        return None
    return Progress(stream, live=terminal)
