"""The documentation site must cover every check, command and option the code has."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from pydebuprep import checks, config
from pydebuprep.cli import COMMANDS
from pydebuprep.system import ALLOWED_COMMANDS, SHOW_UNITS, UNIT_QUERIES

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
sys.path.insert(0, str(ROOT / "tools"))

import docs_hooks  # noqa: E402

CHECK_IDS = sorted(cls.id for cls in checks.ALL_CHECKS)


def nav_pages(node: Any) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, list):
        return [p for item in node for p in nav_pages(item)]
    if isinstance(node, dict):
        return [p for value in node.values() for p in nav_pages(value)]
    return []


def mkdocs_config() -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load((ROOT / "mkdocs.yml").read_text(encoding="utf-8"))
    return data


def test_every_check_has_a_page_and_every_page_a_check() -> None:
    pages = sorted(p.stem for p in (DOCS / "checks").glob("*.md") if p.stem != "index")
    assert pages == CHECK_IDS


@pytest.mark.parametrize("check_id", CHECK_IDS)
def test_check_page_structure(check_id: str) -> None:
    text = (DOCS / "checks" / f"{check_id}.md").read_text(encoding="utf-8")
    assert text.startswith(f"# {check_id} — "), "title: '# ID — Title'"
    assert f"<!-- facts: {check_id} -->" in text
    assert f"<!-- options: {check_id} -->" in text
    for section in ("## What it checks", "## Findings", "## Commands it runs", "## Limitations"):
        assert section in text, section
    supports = next(c for c in checks.ALL_CHECKS if c.id == check_id)().supports_baseline
    assert ("## Compared with a snapshot" in text) == supports


def test_navigation_lists_every_page() -> None:
    nav = nav_pages(mkdocs_config()["nav"])
    for check_id in CHECK_IDS:
        assert f"checks/{check_id}.md" in nav
    excluded = {"backlog.md"}
    on_disk = {
        str(p.relative_to(DOCS))
        for p in DOCS.rglob("*.md")
        if p.name not in excluded and "superpowers" not in p.parts
    }
    assert on_disk == set(nav)


def test_navigation_orders_checks_like_the_report() -> None:
    nav = [p for p in nav_pages(mkdocs_config()["nav"]) if p.startswith("checks/")]
    order = [f"checks/{c.id}.md" for c in docs_hooks.check_classes()]
    assert nav == ["checks/index.md", *order]


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("'", "").replace("\\n", "\n").replace("\\t", "\t"))


def _command(argv: tuple[str, ...]) -> str:
    return re.sub(r"\s+", " ", " ".join(argv))


def test_every_allowlisted_command_is_documented_on_a_check_page() -> None:
    pages = " ".join(
        _normalize(p.read_text(encoding="utf-8")) for p in (DOCS / "checks").glob("*.md")
    )
    commands = [*ALLOWED_COMMANDS, SHOW_UNITS, *UNIT_QUERIES]
    missing = [_command(argv) for argv in commands if _command(argv) not in pages]
    assert missing == []


def test_every_command_and_config_key_is_in_the_reference() -> None:
    cli = docs_hooks.cli_reference()
    for command in COMMANDS:
        assert f"## `{command}`" in cli
    reference = docs_hooks.config_reference()
    for key in config.REPORT_HELP:
        assert f"| `{key}` |" in reference
    for cls in checks.ALL_CHECKS:
        for opt in cls.options:
            assert f"[`{cls.id}`](../checks/{cls.id}.md) | `{opt.name}` |" in reference


def test_checks_index_links_every_check() -> None:
    index = docs_hooks.checks_index()
    for check_id in CHECK_IDS:
        assert f"[`{check_id}`]({check_id}.md)" in index


def test_facts_box() -> None:
    debsums = docs_hooks.facts("debsums")
    assert "| Needs root | yes (skipped without it) |" in debsums
    assert "| Needs programs | `debsums` |" in debsums
    assert "| Compares with a snapshot | no |" in docs_hooks.facts("debsums")
    assert "| Needs root | no |" in docs_hooks.facts("apt-sources")
    assert "| Compares with a snapshot | yes |" in docs_hooks.facts("apt-sources")
    assert "| Needs programs | none |" in docs_hooks.facts("apt-sources")


def test_options_section() -> None:
    disk = docs_hooks.options("disk-space")
    assert "| `min_free_mib` | `2048` |" in disk
    assert '    important_mounts: ["/", "/var"]' in disk
    assert "--check-option disk-space.include_remote=false" in disk
    assert "repeat it to give several items" in disk
    venvs = docs_hooks.options("python-venvs")
    assert "--check-option python-venvs.search_paths=/opt" in venvs
    critical = docs_hooks.options("systemd-critical-services")
    assert "--check-option systemd-critical-services.required_active=VALUE" in critical
    assert "has no options" in docs_hooks.options("dkms")
    assert "repeat it" not in docs_hooks.options("apt-lists-age")


def test_expand_replaces_every_marker() -> None:
    page = "\n".join(
        [
            "<!-- facts: dkms -->",
            "<!-- options: dkms -->",
            "<!-- checks-index -->",
            "<!-- config-reference -->",
            "<!-- example-config -->",
            "<!-- cli-reference -->",
        ]
    )
    out = docs_hooks.on_page_markdown(page, page=None, config=None, files=None)
    assert "<!--" not in out
    assert config.example_config().splitlines()[0] in out


@pytest.mark.parametrize("marker", ["<!-- facts -->", "<!-- options -->", "<!-- facts: nope -->"])
def test_bad_markers_fail_the_build(marker: str) -> None:
    with pytest.raises(docs_hooks.DocsError):
        docs_hooks.expand(marker)


def test_table_cells_are_escaped() -> None:
    assert docs_hooks._cell("a|b\nc") == "a\\|b c"
