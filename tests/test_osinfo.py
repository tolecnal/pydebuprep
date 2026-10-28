from __future__ import annotations

from fakes import FakeSystem
from pydebuprep.osinfo import detect_os, known_codenames, parse_os_release

TRIXIE = """PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
VERSION_CODENAME=trixie
ID=debian
"""

NOBLE = """PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
UBUNTU_CODENAME=noble
"""

JAMMY_NO_VERSION_CODENAME = """# comment
NAME="Ubuntu"
VERSION_ID="22.04"
ID=ubuntu

UBUNTU_CODENAME=jammy
"""


def test_parse_handles_quotes_and_comments() -> None:
    d = parse_os_release(JAMMY_NO_VERSION_CODENAME)
    assert d == {
        "NAME": "Ubuntu",
        "VERSION_ID": "22.04",
        "ID": "ubuntu",
        "UBUNTU_CODENAME": "jammy",
    }


def test_detect_trixie() -> None:
    info = detect_os(FakeSystem(files={"/etc/os-release": TRIXIE}))
    assert (info.codename, info.version_id, info.id) == ("trixie", "13", "debian")
    assert info.release is not None
    assert info.release.version == "13"
    assert info.supported


def test_detect_noble() -> None:
    info = detect_os(FakeSystem(files={"/etc/os-release": NOBLE}))
    assert info.release is not None
    assert info.release.previous == "jammy"


def test_ubuntu_codename_fallback_and_usr_lib() -> None:
    info = detect_os(FakeSystem(files={"/usr/lib/os-release": JAMMY_NO_VERSION_CODENAME}))
    assert info.codename == "jammy"
    assert info.supported


def test_unknown_codename_unsupported() -> None:
    text = TRIXIE.replace("trixie", "forky").replace('"13"', '"14"')
    info = detect_os(FakeSystem(files={"/etc/os-release": text}))
    assert not info.supported
    assert info.release is None


def test_missing_os_release() -> None:
    info = detect_os(FakeSystem())
    assert not info.supported
    assert info.id == "unknown"


def test_known_codenames() -> None:
    assert known_codenames("debian") == {"bookworm", "trixie", "bullseye"}
    assert known_codenames("ubuntu") == {"focal", "jammy", "noble", "resolute"}
