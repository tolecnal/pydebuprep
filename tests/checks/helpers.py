from __future__ import annotations

from typing import Any

from fakes import FakeSystem
from pydebuprep.checks.base import Context
from pydebuprep.osinfo import OsInfo, detect_os

OS_RELEASES = {
    "trixie": 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\nPRETTY_NAME="Debian 13"\n',
    "bookworm": 'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\nPRETTY_NAME="Debian 12"\n',
    "noble": 'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\nPRETTY_NAME="Ubuntu 24.04"\n',
    "jammy": 'ID=ubuntu\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy\nPRETTY_NAME="Ubuntu 22.04"\n',
    "forky": 'ID=debian\nVERSION_ID="14"\nVERSION_CODENAME=forky\nPRETTY_NAME="Debian 14"\n',
}


def make_ctx(
    codename: str = "trixie", baseline: dict[str, Any] | None = None, **kw: Any
) -> Context:
    files = {"/etc/os-release": OS_RELEASES[codename], **kw.pop("files", {})}
    system = FakeSystem(files=files, **kw)
    osinfo: OsInfo = detect_os(system)
    checks = None if baseline is None else {"checks": baseline}
    return Context(system, osinfo, checks)


def titles(findings: list[Any]) -> list[str]:
    return [f.title for f in findings]
