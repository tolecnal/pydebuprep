from __future__ import annotations

from fakes import FROZEN_NOW
from pydebuprep.checks.apt_lists_age import AptListsAgeCheck
from pydebuprep.model import Severity

from .helpers import make_ctx

NOW = FROZEN_NOW.timestamp()
LIST = "/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease"


def test_no_lists_warns() -> None:
    (f,) = AptListsAgeCheck().run(make_ctx())
    assert f.severity is Severity.WARNING
    assert "sudo apt update" in f.remediation[0]


def test_old_lists_info() -> None:
    ctx = make_ctx(files={LIST: ""}, mtimes={LIST: NOW - 10 * 86400})
    (f,) = AptListsAgeCheck().run(ctx)
    assert f.severity is Severity.INFO
    assert f.title == "Package lists are 10 days old"


def test_fresh_lists_ok() -> None:
    ctx = make_ctx(files={LIST: ""}, mtimes={LIST: NOW - 3600})
    assert AptListsAgeCheck().run(ctx) == []


def test_max_age_configurable() -> None:
    ctx = make_ctx(files={LIST: ""}, mtimes={LIST: NOW - 10 * 86400})
    assert AptListsAgeCheck({"max_age_days": 30}).run(ctx) == []
