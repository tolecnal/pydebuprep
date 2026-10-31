"""Portal support is documented: the man page, the docs site and the published schemas."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
sys.path.insert(0, str(ROOT / "tools"))

import docs_hooks  # noqa: E402


def man() -> str:
    return (ROOT / "man" / "pydebuprep.1").read_text().replace("\\-", "-")


def test_man_page_environment_and_files() -> None:
    text = man()
    environment = text[text.index(".SH ENVIRONMENT") : text.index(".SH EXAMPLES")]
    for name in ("PYDEBUPREP_TOKEN", "PYDEBUPREP_CA_FILE", "PYDEBUPREP_STATE_DIR"):
        assert name in environment
    files = text[text.index(".SH FILES") : text.index(".SH ENVIRONMENT")]
    for path in ("/etc/pydebuprep/token", "/var/lib/pydebuprep/pending/",
                 "/var/lib/pydebuprep/configs/"):  # fmt: skip
        assert path in files


def test_man_page_config_url_and_upload_section() -> None:
    text = man()
    options = text[text.index(".SH OPTIONS") : text.index(".SH EXIT STATUS")]
    assert "https://" in options[options.index("--config") :]
    configuration = text[text.index(".SH CONFIGURATION") : text.index(".SH CHECKS")]
    assert "upload" in configuration


def test_portal_guide_is_in_the_navigation() -> None:
    page = DOCS / "guide" / "portal.md"
    assert page.exists()
    assert "guide/portal.md" in (ROOT / "mkdocs.yml").read_text()
    text = page.read_text()
    for topic in ("token", "--config https://", "pending", "--allow-http", "--ca-file",
                  "could not be fetched", "same server"):  # fmt: skip
        assert topic in text, topic


def test_read_only_page_lists_the_new_writes() -> None:
    text = (DOCS / "about" / "read-only.md").read_text()
    assert "/var/lib/pydebuprep/pending" in text
    assert "/var/lib/pydebuprep/configs" in text


def test_report_format_documents_config_and_links_the_schemas() -> None:
    text = (DOCS / "reference" / "report-format.md").read_text()
    assert "**`config`**" in text
    assert "/schema/report.schema.json" in text
    assert "/schema/config.schema.json" in text


def test_schemas_are_published_with_the_site(tmp_path: Path) -> None:
    docs_hooks.on_post_build(config={"site_dir": str(tmp_path)})
    for name in ("report", "config"):
        published = tmp_path / "schema" / f"{name}.schema.json"
        source = ROOT / "schema" / f"{name}.schema.json"
        assert published.read_text() == source.read_text()
        assert json.loads(published.read_text())["$id"].endswith(f"/schema/{name}.schema.json")
