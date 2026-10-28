from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from pydebuprep import checks
from pydebuprep.config import (
    DEFAULT_CONFIG_PATH,
    Config,
    ConfigError,
    example_config,
    load_config,
    parse_config,
)
from pydebuprep.snapshot import DEFAULT_SNAPSHOT_DIR


def test_default_path() -> None:
    assert DEFAULT_CONFIG_PATH == "/etc/pydebuprep.conf"


def test_empty_file_gives_defaults() -> None:
    cfg = parse_config("", "x.conf")
    assert cfg.report.format == "text"
    assert cfg.report.output_dir is None
    assert cfg.report.min_severity == "info"
    assert cfg.report.color is True
    assert cfg.report.baseline == "auto"
    assert cfg.report.snapshot_dir == DEFAULT_SNAPSHOT_DIR
    assert cfg.disabled == set()
    assert cfg.check_settings == {}


def test_full_config() -> None:
    cfg = parse_config(
        """
report:
  format: json
  output_dir: /var/tmp/reports
  min_severity: warning
  color: false
  baseline: none
checks:
  debsums:
    enabled: false
  disk-space:
    include_remote: true
    exclude_mounts: [/mnt/backup*]
""",
        "x.conf",
    )
    assert (cfg.report.format, cfg.report.output_dir, cfg.report.min_severity) == (
        "json",
        "/var/tmp/reports",
        "warning",
    )
    assert cfg.report.color is False
    assert cfg.report.baseline == "none"
    assert cfg.disabled == {"debsums"}
    assert cfg.check_settings == {
        "disk-space": {"include_remote": True, "exclude_mounts": ["/mnt/backup*"]}
    }


def test_all_errors_reported_together() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_config(
            """
report:
  format: pdf
  colour: true
checks:
  no-such-check: {}
  disk-space:
    include_remote: maybe
    enabled: sometimes
extra: 1
""",
            "bad.conf",
        )
    errors = exc.value.errors
    assert "bad.conf: unknown top-level key 'extra'" in errors
    assert (
        "bad.conf: report.format: must be one of text, json, yaml, html, markdown, jira, confluence"
        in errors
    )
    assert "bad.conf: report: unknown key 'colour'" in errors
    assert "bad.conf: checks: unknown check: no-such-check" in errors
    assert "bad.conf: checks.disk-space.enabled: expected true or false" in errors
    assert "bad.conf: disk-space.include_remote: expected true or false" in errors


def test_yaml_syntax_error_has_location() -> None:
    with pytest.raises(ConfigError, match=r"bad\.conf: line 2"):
        parse_config("report:\n\tformat: json\n", "bad.conf")


@pytest.mark.parametrize("text", ["- a\n- b\n", "just a string\n", "report: [1]\n", "checks: 3\n"])
def test_wrong_shapes(text: str) -> None:
    with pytest.raises(ConfigError, match="expected a mapping"):
        parse_config(text, "x.conf")


def test_load_missing_default_is_fine(tmp_path: Path) -> None:
    cfg = load_config(None, default_path=str(tmp_path / "pydebuprep.conf"))
    assert cfg.path is None
    assert cfg == Config.defaults()


def test_load_existing_default(tmp_path: Path) -> None:
    p = tmp_path / "pydebuprep.conf"
    p.write_text("report:\n  format: yaml\n")
    cfg = load_config(None, default_path=str(p))
    assert cfg.path == str(p)
    assert cfg.report.format == "yaml"


def test_load_explicit_missing_is_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(str(tmp_path / "nope.conf"))


def test_example_config_parses_to_defaults() -> None:
    text = example_config()
    cfg = parse_config(text, "example")
    assert cfg.report == Config.defaults().report
    assert cfg.disabled == set()
    for cls in checks.ALL_CHECKS:
        assert f"  {cls.id}:\n    enabled: true" in text
        defaults = cls().settings
        assert cfg.check_settings.get(cls.id, {}) == defaults


def test_example_config_documents_every_option() -> None:
    text = example_config()
    data = yaml.safe_load(text)
    for cls in checks.ALL_CHECKS:
        for option in cls.options:
            assert option.name in data["checks"][cls.id]
            assert option.help.split()[0] in text
