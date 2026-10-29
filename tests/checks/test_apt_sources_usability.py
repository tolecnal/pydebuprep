"""apt-sources: signing keys, downloaded metadata and the security archive."""

from __future__ import annotations

from typing import Any

import pytest

from pydebuprep.checks._apt_metadata import list_file, parse_release
from pydebuprep.checks.apt_sources import AptSourcesCheck, parse_sources
from pydebuprep.model import Severity

from .helpers import make_ctx, titles

LISTS = "/var/lib/apt/lists"
DEBIAN_KEY = "/usr/share/keyrings/debian-archive-keyring.gpg"
DEBIAN = f"""Types: deb
URIs: http://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main
Signed-By: {DEBIAN_KEY}

Types: deb
URIs: http://security.debian.org/debian-security
Suites: trixie-security
Components: main
Signed-By: {DEBIAN_KEY}
"""
VENDOR = "deb [arch=amd64 signed-by=/etc/apt/keyrings/vendor.asc] https://apt.example.com/repo trixie main\n"


def release(suite: str, codename: str, valid_until: str = "") -> str:
    lines = [
        "-----BEGIN PGP SIGNED MESSAGE-----",
        "Hash: SHA512",
        "",
        "Origin: Example",
        f"Suite: {suite}",
        f"Codename: {codename}",
        "Date: Sat, 25 Oct 2026 08:00:00 UTC",
    ]
    if valid_until:
        lines.append(f"Valid-Until: {valid_until}")
    lines += ["SHA256:", " abc 123 main/binary-amd64/Packages", "-----BEGIN PGP SIGNATURE-----"]
    return "\n".join(lines) + "\n"


DEBIAN_LISTS = {
    f"{LISTS}/deb.debian.org_debian_dists_trixie_InRelease": release("stable", "trixie"),
    f"{LISTS}/deb.debian.org_debian_dists_trixie-updates_InRelease": release(
        "stable-updates", "trixie-updates"
    ),
    f"{LISTS}/security.debian.org_debian-security_dists_trixie-security_InRelease": release(
        "stable-security", "trixie-security"
    ),
}
VENDOR_LIST = f"{LISTS}/apt.example.com_repo_dists_trixie_InRelease"


def ctx(**kw: Any) -> Any:
    files = {
        "/etc/apt/sources.list.d/debian.sources": DEBIAN,
        DEBIAN_KEY: "binary key",
        **DEBIAN_LISTS,
        **kw.pop("files", {}),
    }
    for path in kw.pop("remove", []):
        files.pop(path)
    return make_ctx(files=files, **kw)


def findings(**kw: Any) -> list[Any]:
    return AptSourcesCheck().run(ctx(**kw))


# --- helpers -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("uri", "suite", "expected"),
    [
        ("http://deb.debian.org/debian", "trixie", "deb.debian.org_debian_dists_trixie_InRelease"),
        ("http://deb.debian.org/debian/", "trixie", "deb.debian.org_debian_dists_trixie_InRelease"),
        (
            "https://user:secret@apt.example.com:8443/my_repo/",
            "stable",
            "apt.example.com:8443_my%5frepo_dists_stable_InRelease",
        ),
        (
            "http://security.debian.org",
            "buster/updates",
            "security.debian.org_dists_buster_updates_InRelease",
        ),
        (
            "http://ppa.launchpadcontent.net/a/b~c/ubuntu",
            "noble",
            "ppa.launchpadcontent.net_a_b%7ec_ubuntu_dists_noble_InRelease",
        ),
    ],
)
def test_list_file_names_like_apt(uri: str, suite: str, expected: str) -> None:
    assert list_file(uri, suite, "InRelease") == f"{LISTS}/{expected}"


@pytest.mark.parametrize(
    "uri", ["cdrom:[Debian GNU/Linux 13]/", "file:/srv/repo", "mirror+file:/etc/apt/mirrors.txt"]
)
def test_list_file_unknown_for_local_and_cdrom_sources(uri: str) -> None:
    assert list_file(uri, "trixie", "InRelease") is None


def test_list_file_unknown_for_flat_repositories() -> None:
    assert list_file("https://example.com/repo", "./", "InRelease") is None


def test_parse_release_reads_the_signed_header_only() -> None:
    fields = parse_release(release("stable", "trixie", "Sat, 01 Nov 2026 08:00:00 UTC"))
    assert fields == {
        "Origin": "Example",
        "Suite": "stable",
        "Codename": "trixie",
        "Date": "Sat, 25 Oct 2026 08:00:00 UTC",
        "Valid-Until": "Sat, 01 Nov 2026 08:00:00 UTC",
    }
    assert parse_release("Suite: x\nCodename: y\n") == {"Suite": "x", "Codename": "y"}


def test_signed_by_is_parsed_from_both_formats() -> None:
    entries = parse_sources(
        make_ctx(
            files={
                "/etc/apt/sources.list.d/debian.sources": DEBIAN,
                "/etc/apt/sources.list.d/vendor.list": VENDOR,
            }
        ).system
    )
    assert {e.uri: e.signed_by for e in entries} == {
        "http://deb.debian.org/debian": DEBIAN_KEY,
        "http://security.debian.org/debian-security": DEBIAN_KEY,
        "https://apt.example.com/repo": "/etc/apt/keyrings/vendor.asc",
    }


# --- findings ------------------------------------------------------------------------


def test_healthy_sources_have_no_findings() -> None:
    assert findings() == []


def test_missing_keyring_is_critical() -> None:
    fs = findings(
        files={
            "/etc/apt/sources.list.d/vendor.list": VENDOR,
            VENDOR_LIST: release("trixie", "trixie"),
        }
    )
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.CRITICAL, "Signing keyring /etc/apt/keyrings/vendor.asc is missing")
    ]
    assert fs[0].evidence == [
        "/etc/apt/sources.list.d/vendor.list: deb https://apt.example.com/repo trixie main"
    ]
    assert "apt update" in fs[0].detail


def test_inline_and_fingerprint_signed_by_are_not_files() -> None:
    inline = DEBIAN.replace(
        f"Signed-By: {DEBIAN_KEY}\n\nTypes",
        "Signed-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n abc\n -----END PGP PUBLIC KEY BLOCK-----\n\nTypes",
        1,
    )
    assert findings(files={"/etc/apt/sources.list.d/debian.sources": inline}, remove=[]) == []
    fingerprint = VENDOR.replace("/etc/apt/keyrings/vendor.asc", "0123456789ABCDEF")
    fs = findings(
        files={
            "/etc/apt/sources.list.d/vendor.list": fingerprint,
            VENDOR_LIST: release("trixie", "trixie"),
        }
    )
    assert fs == []


def test_one_of_several_keyrings_is_enough() -> None:
    two = VENDOR.replace("vendor.asc", "vendor.asc," + DEBIAN_KEY)
    fs = findings(
        files={"/etc/apt/sources.list.d/vendor.list": two, VENDOR_LIST: release("trixie", "trixie")}
    )
    assert fs == []


def test_legacy_trusted_gpg_warns() -> None:
    fs = findings(files={"/etc/apt/trusted.gpg": "keys"})
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.WARNING, "Keys in the legacy keyring /etc/apt/trusted.gpg")
    ]
    assert findings(files={"/etc/apt/trusted.gpg": ""}) == []


def test_missing_metadata_warns_once_lists_exist() -> None:
    vendor = {"/etc/apt/sources.list.d/vendor.list": VENDOR, "/etc/apt/keyrings/vendor.asc": "k"}
    (f,) = findings(files=vendor)
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "No downloaded metadata for 1 repository",
    )
    assert f.evidence == [
        "/etc/apt/sources.list.d/vendor.list: deb https://apt.example.com/repo trixie main"
    ]
    assert "pydebuprep never runs" in f.detail


def test_release_file_without_inrelease_counts() -> None:
    vendor = {
        "/etc/apt/sources.list.d/vendor.list": VENDOR,
        "/etc/apt/keyrings/vendor.asc": "k",
        f"{LISTS}/apt.example.com_repo_dists_trixie_Release": "Suite: trixie\nCodename: trixie\n",
    }
    assert findings(files=vendor) == []


def test_no_lists_at_all_is_left_to_apt_lists_age() -> None:
    assert findings(remove=list(DEBIAN_LISTS)) == []


def test_suite_mismatch_warns() -> None:
    vendor = {
        "/etc/apt/sources.list.d/vendor.list": VENDOR,
        "/etc/apt/keyrings/vendor.asc": "k",
        VENDOR_LIST: release("stable", "bookworm"),
    }
    (f,) = findings(files=vendor)
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "1 repository serves a different release than configured",
    )
    assert f.evidence == [
        "https://apt.example.com/repo trixie: the repository says Suite stable, Codename bookworm"
    ]


def test_valid_until_is_left_to_apt_lists_age() -> None:
    # A local Release past Valid-Until only means apt update hasn't run lately (apt rejects
    # expired files from the server and keeps the old one): apt-lists-age's business.
    # Vendor dates without a known time zone must not break the check either.
    path = f"{LISTS}/security.debian.org_debian-security_dists_trixie-security_InRelease"
    for until in ("Sat, 25 Oct 2026 08:00:00 UTC", "Sat, 07 Nov 2026 10:00:00 -0000", "soon"):
        assert findings(files={path: release("stable-security", "trixie-security", until)}) == []


def test_vendor_suites_with_a_slash_match_like_apt() -> None:
    # apt's CheckDist also accepts the suite without its last path element.
    mongo = (
        "deb [signed-by=/etc/apt/keyrings/vendor.asc] https://repo.example.org/apt/debian "
        "trixie/mongodb-org/7.0 main\n"
    )
    listed = f"{LISTS}/repo.example.org_apt_debian_dists_trixie_mongodb-org_7.0_InRelease"
    files = {
        "/etc/apt/sources.list.d/mongo.list": mongo,
        "/etc/apt/keyrings/vendor.asc": "k",
        listed: release("trixie", "trixie/mongodb-org"),
    }
    assert findings(files=files) == []
    files[listed] = release("bookworm", "bookworm/mongodb-org")
    assert titles(findings(files=files)) == [
        "1 repository serves a different release than configured"
    ]


def test_debian_unstable_has_no_security_archive_to_miss() -> None:
    sid = "deb http://deb.debian.org/debian sid main\n"
    ctx_ = make_ctx("forky", files={"/etc/apt/sources.list.d/sid.list": sid})
    assert "No security updates repository for forky" not in titles(AptSourcesCheck().run(ctx_))


def test_missing_security_archive_warns() -> None:
    no_security = DEBIAN.split("\n\n", maxsplit=1)[0] + "\n"
    fs = findings(files={"/etc/apt/sources.list.d/debian.sources": no_security})
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.WARNING, "No security updates repository for trixie")
    ]
    assert fs[0].remediation[0].startswith("Add trixie-security")


def test_ubuntu_security_from_the_archive_host_counts() -> None:
    sources = """Types: deb
URIs: http://archive.ubuntu.com/ubuntu/
Suites: noble noble-updates noble-security
Components: main
"""
    ctx_ = make_ctx("noble", files={"/etc/apt/sources.list.d/ubuntu.sources": sources})
    assert AptSourcesCheck().run(ctx_) == []
    without = sources.replace(" noble-security", "")
    ctx_ = make_ctx("noble", files={"/etc/apt/sources.list.d/ubuntu.sources": without})
    assert titles(AptSourcesCheck().run(ctx_)) == ["No security updates repository for noble"]


def test_no_security_finding_without_any_distribution_archive() -> None:
    vendor_only = {
        "/etc/apt/sources.list.d/debian.sources": VENDOR.replace(
            "signed-by=/etc/apt/keyrings/vendor.asc", ""
        )
    }
    fs = findings(files=vendor_only, remove=list(DEBIAN_LISTS))
    assert titles(fs) == ["No enabled repository for the Debian archive"]


def test_disabled_and_source_only_entries_are_not_checked() -> None:
    disabled = "# deb [signed-by=/nowhere.gpg] https://apt.example.com/repo trixie main\n"
    deb_src = "deb-src [signed-by=/nowhere.gpg] https://apt.example.com/repo trixie main\n"
    assert findings(files={"/etc/apt/sources.list.d/a.list": disabled}) == []
    assert titles(findings(files={"/etc/apt/sources.list.d/b.list": deb_src})) == [
        "Signing keyring /nowhere.gpg is missing"
    ]


def test_local_repositories_have_no_lists_to_check() -> None:
    local = "deb [trusted=yes] file:/srv/repo ./\ndeb [trusted=yes] file:/srv/other trixie main\n"
    assert findings(files={"/etc/apt/sources.list.d/local.list": local}) == []
