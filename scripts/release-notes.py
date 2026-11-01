#!/usr/bin/env python3
"""Print a GitHub Release's notes for VERSION: its entry in debian/changelog as Markdown,
and how to verify the download. Usage: scripts/release-notes.py VERSION [CHANGELOG]"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HEADER = re.compile(r"^pydebuprep \(([^)]+)\)")
VERIFY = """
## Verify the download

```sh
sha256sum -c SHA256SUMS
gh attestation verify pydebuprep_{version}_all.deb -R tolecnal/pydebuprep
```
"""


def entry(text: str, version: str) -> list[str] | None:
    """The changes of VERSION, one string per bullet; None if it has no entry."""
    bullets: list[str] | None = None
    for line in text.splitlines():
        header = HEADER.match(line)
        if header:
            if bullets is not None:
                break
            bullets = [] if header.group(1) == version else None
        elif bullets is not None:
            if line.startswith(" -- "):
                break
            if line.startswith("  * "):
                bullets.append(line[4:].strip())
            elif line.strip() and bullets:
                bullets[-1] += " " + line.strip()
    return bullets


def main(argv: list[str]) -> int:
    version = argv[1]
    path = Path(argv[2]) if len(argv) > 2 else Path(__file__).parent.parent / "debian/changelog"
    bullets = entry(path.read_text(encoding="utf-8"), version)
    if not bullets:
        print(f"release-notes: no entry for {version} in {path}", file=sys.stderr)
        return 1
    print("## What changed\n")
    print("\n".join(f"- {b}" for b in bullets))
    print(VERIFY.format(version=version), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
