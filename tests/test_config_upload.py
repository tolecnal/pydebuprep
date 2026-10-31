"""The upload: section of the config file."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from pydebuprep.config import (
    DEFAULT_TOKEN_FILE,
    UPLOAD_HELP,
    ConfigError,
    UploadSettings,
    example_config,
    load_config,
    parse_config,
)
from pydebuprep.state import DEFAULT_PENDING_DIR


def test_defaults() -> None:
    upload = parse_config("", "x.conf").upload
    assert upload == UploadSettings()
    assert upload.url is None
    assert upload.token_file == DEFAULT_TOKEN_FILE == "/etc/pydebuprep/token"
    assert upload.ca_file is None
    assert upload.pending_dir == DEFAULT_PENDING_DIR


def test_full_section() -> None:
    upload = parse_config(
        "upload:\n  url: https://portal.example.com:8443/base\n  token_file: /etc/t\n"
        "  ca_file: /etc/ca.pem\n  pending_dir: /srv/pending\n",
        "x.conf",
    ).upload
    assert upload == UploadSettings(
        "https://portal.example.com:8443/base", "/etc/t", "/etc/ca.pem", "/srv/pending"
    )


def test_http_url_and_disabled_pending() -> None:
    upload = parse_config(
        "upload:\n  url: http://localhost:8000\n  pending_dir: null\n", "x.conf"
    ).upload
    assert (upload.url, upload.pending_dir) == ("http://localhost:8000", None)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("upload: [1]", "upload: expected a mapping"),
        ("upload:\n  x: 1", "upload: unknown key 'x'"),
        ("upload:\n  url: ftp://portal", "upload.url: expected an https:// or http:// URL"),
        ("upload:\n  url: portal.example", "upload.url: expected an https:// or http:// URL"),
        ("upload:\n  url: 'https://'", "upload.url: expected an https:// or http:// URL"),
        ("upload:\n  url: https://u:p@portal", "upload.url: must not contain a user name"),
        ("upload:\n  url: https://portal/?a=1", "upload.url: must not have a query"),
        ("upload:\n  url: 'https://portal/#x'", "upload.url: must not have a query"),
        ("upload:\n  url: https://portal:99999", "upload.url: invalid port"),
        ("upload:\n  url: 7", "upload.url: expected an https:// or http:// URL"),
        ("upload:\n  token_file: ''", "upload.token_file: expected a non-empty string"),
        ("upload:\n  ca_file: 3", "upload.ca_file: expected a file path or null"),
        ("upload:\n  pending_dir: []", "upload.pending_dir: expected a directory path or null"),
    ],
)
def test_errors(text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_config(text, "x.conf")


def test_relative_paths_resolved_against_the_config_file(tmp_path: Path) -> None:
    p = tmp_path / "pydebuprep.conf"
    p.write_text("upload:\n  token_file: token\n  ca_file: ./ca.pem\n  pending_dir: pend\n")
    upload = load_config(str(p)).upload
    assert upload.token_file == str(tmp_path / "token")
    assert upload.ca_file == str(tmp_path / "ca.pem")
    assert upload.pending_dir == str(tmp_path / "pend")


def test_example_config_has_upload_section() -> None:
    text = example_config()
    assert "upload:\n" in text
    assert yaml.safe_load(text)["upload"]["url"] is None
    assert parse_config(text, "example").upload == UploadSettings()
    for help_text in UPLOAD_HELP.values():
        assert help_text.split()[0] in text


def test_load_with_pending_turned_off(tmp_path: Path) -> None:
    p = tmp_path / "pydebuprep.conf"
    p.write_text("upload:\n  pending_dir: null\n")
    upload = load_config(str(p)).upload
    assert upload.pending_dir is None
    assert upload.ca_file is None
