from __future__ import annotations

from pydebuprep.checks.os_release import OsReleaseCheck
from pydebuprep.model import Severity

from .helpers import make_ctx


def test_unsupported_is_critical() -> None:
    (f,) = OsReleaseCheck().run(make_ctx("forky"))
    assert f.severity is Severity.CRITICAL
    assert "Debian 14" in f.title
    assert f.remediation


def test_supported_no_findings() -> None:
    assert OsReleaseCheck().run(make_ctx("trixie")) == []


def test_collect_baseline() -> None:
    assert OsReleaseCheck().collect_baseline(make_ctx("bookworm")) == {
        "id": "debian",
        "version_id": "12",
        "codename": "bookworm",
        "hostname": "testhost",
    }


def test_compare_upgrade_info() -> None:
    before = {"id": "debian", "version_id": "12", "codename": "bookworm", "hostname": "testhost"}
    (f,) = OsReleaseCheck().compare(make_ctx("trixie"), before)
    assert f.severity is Severity.INFO
    assert f.title == "Upgraded from Debian 12 (bookworm) to Debian 13 (trixie)"
    assert f.references == ["https://www.debian.org/releases/trixie/releasenotes"]


def test_compare_same_release_warns() -> None:
    before = {"id": "debian", "version_id": "13", "codename": "trixie", "hostname": "testhost"}
    (f,) = OsReleaseCheck().compare(make_ctx("trixie"), before)
    assert f.severity is Severity.WARNING
    assert "same release" in f.title


def test_compare_other_host_warns() -> None:
    before = {"id": "debian", "version_id": "12", "codename": "bookworm", "hostname": "other"}
    fs = OsReleaseCheck().compare(make_ctx("trixie"), before)
    assert any(f.severity is Severity.WARNING and "other" in f.title for f in fs)
