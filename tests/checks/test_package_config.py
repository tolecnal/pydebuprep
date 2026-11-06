"""package-config: APT pinning, architectures, diversions and alternatives."""

from __future__ import annotations

from typing import Any

from pydebuprep.checks.package_config import PackageConfigCheck, _digest
from pydebuprep.model import Finding, Severity

from .helpers import make_ctx

ALT = "/var/lib/dpkg/alternatives"
LINK = "/etc/alternatives"


def compare(before: dict[str, Any], **kw: Any) -> list[Finding]:
    return PackageConfigCheck().compare(make_ctx(**kw), before)


def test_a_working_alternative_is_fine() -> None:
    ctx = make_ctx(files={f"{ALT}/editor": "auto\n", "/usr/bin/vim": ""},
                   links={f"{LINK}/editor": "/usr/bin/vim"})  # fmt: skip
    assert PackageConfigCheck().run(ctx) == []


def test_an_alternative_whose_target_is_gone_is_a_warning() -> None:
    ctx = make_ctx(files={f"{ALT}/python": "manual\n"}, links={f"{LINK}/python": "/usr/bin/py3.9"})
    (f,) = PackageConfigCheck().run(ctx)
    assert (f.severity, f.title) == (Severity.WARNING, "1 alternative points to nothing")
    assert f.evidence == ["python: /usr/bin/py3.9"]


def test_an_alternative_without_a_link_is_left_alone() -> None:
    assert PackageConfigCheck().run(make_ctx(files={f"{ALT}/python": "auto\n"})) == []


def test_baseline_records_all_four() -> None:
    ctx = make_ctx(
        files={
            "/etc/apt/preferences": "Package: a\n",
            "/etc/apt/preferences.d/b": "Package: b\n",
            "/var/lib/dpkg/arch": "amd64\ni386\n",
            "/var/lib/dpkg/diversions": "/bin/a\n/bin/a.orig\n:\n/bin/b\n/bin/b.x\nfoo\nstray\n",
            f"{ALT}/editor": "manual\n/usr/bin/editor\n",
        },
        links={f"{LINK}/editor": "/usr/bin/vim"},
    )
    assert PackageConfigCheck().collect_baseline(ctx) == {
        "preferences": {
            "/etc/apt/preferences": _digest(b"Package: a\n"),
            "/etc/apt/preferences.d/b": _digest(b"Package: b\n"),
        },
        "architectures": ["amd64", "i386"],
        "diversions": {"/bin/a": ":", "/bin/b": "foo"},
        "alternatives": {"editor": ["manual", "/usr/bin/vim"]},
    }


def test_an_unreadable_preferences_file_is_left_out() -> None:
    check = PackageConfigCheck()
    ctx = make_ctx(files={"/etc/apt/preferences.d/b": "x"})
    ctx.system.unreadable = {"/etc/apt/preferences.d/b"}  # type: ignore[attr-defined]
    assert check.collect_baseline(ctx)["preferences"] == {}


def test_nothing_changed_is_silent() -> None:
    ctx = make_ctx()
    check = PackageConfigCheck()
    assert check.compare(ctx, check.collect_baseline(ctx)) == []


def test_a_snapshot_without_these_is_silent() -> None:
    assert compare({}) == []


def test_pinning_gone_is_a_warning_and_changed_is_information() -> None:
    fs = compare(
        {"preferences": {"/etc/apt/preferences.d/gone": "a", "/etc/apt/preferences.d/b": "old"}},
        files={"/etc/apt/preferences.d/b": "new", "/etc/apt/preferences.d/c": "new"},
    )
    assert [(f.severity, f.title, f.evidence) for f in fs] == [
        (Severity.WARNING, "1 APT pinning file is gone", ["/etc/apt/preferences.d/gone"]),
        (
            Severity.INFO,
            "2 APT pinning files are new or changed",
            ["/etc/apt/preferences.d/b", "/etc/apt/preferences.d/c"],
        ),
    ]


def test_architectures() -> None:
    fs = compare({"architectures": ["amd64", "i386"]},
                 files={"/var/lib/dpkg/arch": "amd64\narmhf\n"})  # fmt: skip
    assert [(f.severity, f.evidence) for f in fs] == [
        (Severity.WARNING, ["i386"]),
        (Severity.INFO, ["armhf"]),
    ]


def test_only_local_diversions_matter_when_gone() -> None:
    diversions = "/bin/b\n/bin/b.x\nnew-owner\n"
    fs = compare({"diversions": {"/bin/a": ":", "/bin/b": "old-owner", "/bin/c": "pkg"}},
                 files={"/var/lib/dpkg/diversions": diversions})  # fmt: skip
    assert [(f.severity, f.title, f.evidence) for f in fs] == [
        (Severity.WARNING, "1 local diversion is gone", ["/bin/a"]),
        (Severity.INFO, "1 diversion has a new owner", ["/bin/b: old-owner to new-owner"]),
    ]


def test_alternatives_chosen_by_hand_matter() -> None:
    fs = compare(
        {
            "alternatives": {
                "moved": ["manual", "/usr/bin/a"],
                "gone": ["manual", "/usr/bin/b"],
                "same": ["manual", "/usr/bin/c"],
                "auto": ["auto", "/usr/bin/d"],
                "auto-gone": ["auto", "/usr/bin/e"],
                "auto-same": ["auto", "/usr/bin/f"],
            }
        },
        files={
            f"{ALT}/moved": "manual\n",
            f"{ALT}/same": "manual\n",
            f"{ALT}/auto": "auto\n",
            f"{ALT}/auto-same": "auto\n",
        },
        links={
            f"{LINK}/moved": "/usr/bin/a2",
            f"{LINK}/same": "/usr/bin/c",
            f"{LINK}/auto": "/usr/bin/d2",
            f"{LINK}/auto-same": "/usr/bin/f",
        },
    )
    assert [(f.severity, f.title, f.evidence) for f in fs] == [
        (
            Severity.WARNING,
            "2 alternatives chosen by hand are different now",
            ["gone: /usr/bin/b, now gone", "moved: /usr/bin/a to /usr/bin/a2"],
        ),
        (
            Severity.INFO,
            "1 automatic alternative points elsewhere",
            ["auto: /usr/bin/d to /usr/bin/d2"],
        ),
    ]
