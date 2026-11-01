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

import docs_build  # noqa: E402

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
    order = [f"checks/{c.id}.md" for c in docs_build.check_classes()]
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
    cli = docs_build.cli_reference()
    for command in COMMANDS:
        assert f"## `{command}`" in cli
    reference = docs_build.config_reference()
    for key in config.REPORT_HELP:
        assert f"| `{key}` |" in reference
    assert "## `upload`" in reference
    for key in config.UPLOAD_HELP:
        assert f"| `{key}` |" in reference
    for cls in checks.ALL_CHECKS:
        for opt in cls.options:
            assert f"[`{cls.id}`](../checks/{cls.id}.md) | `{opt.name}` |" in reference


def test_checks_index_links_every_check() -> None:
    index = docs_build.checks_index()
    for check_id in CHECK_IDS:
        assert f"[`{check_id}`]({check_id}.md)" in index


def test_facts_box() -> None:
    debsums = docs_build.facts("debsums")
    assert "| Needs root | yes (skipped without it) |" in debsums
    assert "| Needs programs | `debsums` |" in debsums
    assert "| Compares with a snapshot | no |" in docs_build.facts("debsums")
    assert "| Needs root | no |" in docs_build.facts("apt-sources")
    assert "| Compares with a snapshot | yes |" in docs_build.facts("apt-sources")
    assert "| Needs programs | none |" in docs_build.facts("apt-sources")


def test_options_section() -> None:
    disk = docs_build.options("disk-space")
    assert "| `min_free_mib` | `2048` |" in disk
    assert '    important_mounts: ["/", "/var"]' in disk
    assert "--check-option disk-space.include_remote=false" in disk
    assert "repeat it to give several items" in disk
    venvs = docs_build.options("python-venvs")
    assert "--check-option python-venvs.search_paths=/opt" in venvs
    critical = docs_build.options("systemd-critical-services")
    assert "--check-option systemd-critical-services.required_active=VALUE" in critical
    assert "has no options" in docs_build.options("dkms")
    assert "repeat it" not in docs_build.options("apt-lists-age")


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
    out = docs_build.expand(page)
    assert "<!--" not in out
    assert config.example_config().splitlines()[0] in out


@pytest.mark.parametrize("marker", ["<!-- facts -->", "<!-- options -->", "<!-- facts: nope -->"])
def test_bad_markers_fail_the_build(marker: str) -> None:
    with pytest.raises(docs_build.DocsError):
        docs_build.expand(marker)


def test_table_cells_are_escaped() -> None:
    assert docs_build._cell("a|b\nc") == "a\\|b c"


def test_build_tree_expands_every_marker(tmp_path: Path) -> None:
    docs_build.write_tree(tmp_path)
    pages = sorted(tmp_path.rglob("*.md"))
    assert len(pages) > 40
    for page in pages:
        assert not docs_build.MARKER.search(page.read_text()), page
    assert "| Needs root |" in (tmp_path / "checks" / "disk-space.md").read_text()


def test_build_tree_leaves_out_the_planning_notes(tmp_path: Path) -> None:
    docs_build.write_tree(tmp_path)
    assert not (tmp_path / "backlog.md").exists()
    assert not (tmp_path / "superpowers").exists()


def test_build_config_points_zensical_at_the_tree(tmp_path: Path) -> None:
    path = docs_build.write_config(tmp_path / "zensical.yml", docs_dir="docs-src")
    built = yaml.safe_load(path.read_text())
    source = mkdocs_config()
    assert built["docs_dir"] == "docs-src"
    assert built["site_dir"] == "site"
    assert "hooks" not in built and "exclude_docs" not in built
    assert built["nav"] == source["nav"] and built["theme"] == source["theme"]


def test_docs_are_built_with_zensical() -> None:
    assert "zensical" in (ROOT / "requirements-docs.in").read_text()
    assert "mkdocs-material" not in (ROOT / "requirements-docs.in").read_text()
    for path in (ROOT / "Makefile", ROOT / ".github/workflows/docs.yml"):
        text = path.read_text()
        assert "tools/docs_build.py" in text and "zensical build --strict" in text, path
