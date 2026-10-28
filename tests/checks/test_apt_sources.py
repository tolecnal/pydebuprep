from __future__ import annotations

from pydebuprep.checks.apt_sources import AptSourcesCheck, parse_sources
from pydebuprep.model import Severity

from .helpers import make_ctx, titles

DEBIAN_OK = """deb http://deb.debian.org/debian trixie main contrib
deb http://security.debian.org/debian-security trixie-security main
"""

DEB822 = """Types: deb deb-src
URIs: http://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: https://packages.example.com/apt
Suites: bookworm
Components: main
Enabled: no
"""

UBUNTU_SOURCES = """Types: deb
URIs: http://archive.ubuntu.com/ubuntu/
Suites: noble noble-updates noble-backports
Components: main restricted universe multiverse

Types: deb
URIs: http://security.ubuntu.com/ubuntu/
Suites: noble-security
Components: main restricted universe multiverse
"""


def test_parse_one_line_and_deb822() -> None:
    ctx = make_ctx(
        files={
            "/etc/apt/sources.list": "# comment\n" + DEBIAN_OK,
            "/etc/apt/sources.list.d/debian.sources": DEB822,
        }
    )
    entries = parse_sources(ctx.system)
    assert len(entries) == 2 + 4 + 1
    first = entries[0]
    assert (first.type, first.uri, first.suite, first.components, first.enabled) == (
        "deb",
        "http://deb.debian.org/debian",
        "trixie",
        ("main", "contrib"),
        True,
    )
    disabled = [e for e in entries if not e.enabled]
    assert [(e.uri, e.disabled_reason) for e in disabled] == [
        ("https://packages.example.com/apt", "Enabled: no")
    ]


def test_options_in_brackets() -> None:
    line = (
        "deb [arch=amd64 signed-by=/k.gpg] https://download.docker.com/linux/debian trixie stable\n"
    )
    ctx = make_ctx(files={"/etc/apt/sources.list.d/docker.list": line})
    (e,) = parse_sources(ctx.system)
    assert (e.uri, e.suite, e.components) == (
        "https://download.docker.com/linux/debian",
        "trixie",
        ("stable",),
    )


def test_clean_debian_ok() -> None:
    ctx = make_ctx(files={"/etc/apt/sources.list": DEBIAN_OK})
    assert AptSourcesCheck().run(ctx) == []


def test_clean_ubuntu_deb822_ok() -> None:
    ctx = make_ctx("noble", files={"/etc/apt/sources.list.d/ubuntu.sources": UBUNTU_SOURCES})
    assert AptSourcesCheck().run(ctx) == []


def test_old_codename_warns() -> None:
    ctx = make_ctx(
        "noble",
        files={
            "/etc/apt/sources.list.d/ubuntu.sources": UBUNTU_SOURCES,
            "/etc/apt/sources.list.d/ppa.list": "deb http://ppa.launchpadcontent.net/x/y/ubuntu jammy main\n",
        },
    )
    fs = AptSourcesCheck().run(ctx)
    assert titles(fs) == ["Repository still targets jammy"]
    assert fs[0].severity is Severity.WARNING
    assert "/etc/apt/sources.list.d/ppa.list" in fs[0].evidence[0]


def test_ubuntu_disabled_on_upgrade_comment() -> None:
    text = "# deb https://repo.example.com/ubuntu jammy main # disabled on upgrade to noble\n"
    ctx = make_ctx(
        "noble",
        files={
            "/etc/apt/sources.list.d/ubuntu.sources": UBUNTU_SOURCES,
            "/etc/apt/sources.list.d/example.list": text,
        },
    )
    (e,) = [e for e in parse_sources(ctx.system) if not e.enabled]
    assert e.disabled_reason == "disabled on upgrade to noble"
    fs = AptSourcesCheck().run(ctx)
    assert titles(fs) == ["Third-party repository disabled"]
    assert "https://repo.example.com/ubuntu" in fs[0].evidence[0]


def test_plain_commented_debian_line_not_flagged() -> None:
    ctx = make_ctx(
        files={
            "/etc/apt/sources.list": DEBIAN_OK
            + "# deb-src http://deb.debian.org/debian trixie main\n"
        }
    )
    assert AptSourcesCheck().run(ctx) == []


def test_distupgrade_file_disabled() -> None:
    ctx = make_ctx(
        files={
            "/etc/apt/sources.list": DEBIAN_OK,
            "/etc/apt/sources.list.d/vendor.list.distUpgrade": "deb https://vendor.example/apt bookworm main\n",
        }
    )
    (e,) = [e for e in parse_sources(ctx.system) if not e.enabled]
    assert e.disabled_reason == "file renamed to *.distUpgrade"
    assert titles(AptSourcesCheck().run(ctx)) == ["Third-party repository disabled"]


def test_debian_security_updates_suffix_ok() -> None:
    text = DEBIAN_OK + "deb http://security.debian.org/ bookworm/updates main\n"
    fs = AptSourcesCheck().run(make_ctx(files={"/etc/apt/sources.list": text}))
    assert titles(fs) == ["Repository still targets bookworm"]


def test_third_party_unknown_suite_ignored() -> None:
    files = {
        "/etc/apt/sources.list.d/ubuntu.sources": UBUNTU_SOURCES,
        "/etc/apt/sources.list.d/docker.list": "deb https://download.docker.com/linux/ubuntu noble stable\n",
        "/etc/apt/sources.list.d/flat.list": "deb https://example.com/repo ./\n",
        "/etc/apt/sources.list.d/any.list": "deb https://example.com/r stable main\n",
    }
    assert AptSourcesCheck().run(make_ctx("noble", files=files)) == []


def test_debian_alias_suite_info() -> None:
    text = "deb http://deb.debian.org/debian stable main\n"
    fs = AptSourcesCheck().run(make_ctx(files={"/etc/apt/sources.list": text}))
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.INFO, "Debian archive uses suite alias 'stable'")
    ]


def test_missing_distro_archive_critical() -> None:
    files = {
        "/etc/apt/sources.list.d/docker.list": "deb https://download.docker.com/linux/debian trixie stable\n"
    }
    fs = AptSourcesCheck().run(make_ctx(files=files))
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.CRITICAL, "No enabled repository for the Debian archive")
    ]


def test_duplicates_info() -> None:
    files = {
        "/etc/apt/sources.list": DEBIAN_OK,
        "/etc/apt/sources.list.d/dup.list": "deb http://deb.debian.org/debian trixie main\n",
    }
    fs = AptSourcesCheck().run(make_ctx(files=files))
    assert [(f.severity, f.title) for f in fs] == [(Severity.INFO, "Duplicate repository entries")]


def test_compare_repo_disabled_since_baseline() -> None:
    files = {
        "/etc/apt/sources.list": DEBIAN_OK,
        "/etc/apt/sources.list.d/vendor.list": "# deb https://vendor.example/apt bookworm main\n",
    }
    ctx = make_ctx(files=files)
    before = [
        {
            "file": "/etc/apt/sources.list.d/vendor.list",
            "uri": "https://vendor.example/apt",
            "suite": "bookworm",
            "enabled": True,
        },
        {
            "file": "/etc/apt/sources.list",
            "uri": "http://deb.debian.org/debian",
            "suite": "bookworm",
            "enabled": True,
        },
    ]
    fs = AptSourcesCheck().compare(ctx, before)
    assert titles(fs) == ["Repository https://vendor.example/apt was enabled before the upgrade"]
    assert fs[0].severity is Severity.WARNING


def test_collect_baseline_shape() -> None:
    ctx = make_ctx(files={"/etc/apt/sources.list": DEBIAN_OK})
    data = AptSourcesCheck().collect_baseline(ctx)
    assert data[0] == {
        "file": "/etc/apt/sources.list",
        "uri": "http://deb.debian.org/debian",
        "suite": "trixie",
        "enabled": True,
    }
