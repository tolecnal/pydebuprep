from __future__ import annotations

import json

import pytest
import yaml

from conftest import make_sample_report
from pydebuprep.model import Finding, Severity
from pydebuprep.render import EXTENSIONS, FORMATS, render


def expected_sequence() -> list[str]:
    """Items every human-readable format must show, in document order."""
    report = make_sample_report()
    seq: list[str] = []
    for r in report.results:
        seq.append(r.id)
        for f in r.findings:
            seq.append(f.title)
            seq.extend(f.remediation)
        if r.baseline_diff is None:
            seq.append("not applicable")
        elif not r.baseline_diff:
            seq.append("no changes")
        else:
            for f in r.baseline_diff:
                seq.append(f.title)
                seq.extend(f.remediation)
    return seq


def test_formats_and_extensions() -> None:
    assert FORMATS == ("text", "json", "yaml", "html", "markdown")
    assert EXTENSIONS == {
        "text": "txt",
        "json": "json",
        "yaml": "yaml",
        "html": "html",
        "markdown": "md",
    }


def test_json_roundtrip_equals_to_dict() -> None:
    r = make_sample_report()
    assert json.loads(render(r, "json")) == r.to_dict()


def test_yaml_roundtrip_equals_to_dict() -> None:
    r = make_sample_report()
    assert yaml.safe_load(render(r, "yaml")) == r.to_dict()


@pytest.mark.parametrize("fmt", ["text", "html", "markdown"])
def test_all_formats_contain_same_items_in_same_order(fmt: str) -> None:
    out = render(make_sample_report(), fmt)
    pos = 0
    for item in expected_sequence():
        found = out.find(item, pos)
        assert found >= 0, f"{fmt}: {item!r} missing after position {pos}"
        pos = found + len(item)


@pytest.mark.parametrize("fmt", ["text", "html", "markdown"])
def test_no_baseline_wording(fmt: str) -> None:
    r = make_sample_report()
    r.baseline = None
    for res in r.results:
        res.baseline_diff = None
    out = render(r, fmt)
    assert out.count("no baseline") >= len(r.results)


def test_html_escapes_and_has_no_script() -> None:
    r = make_sample_report()
    r.results[0].findings[0].title = "<script>alert(1)</script>"
    out = render(r, "html")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "<script" not in out.lower()
    assert "prefers-color-scheme: dark" in out


def test_markdown_escapes_inline() -> None:
    r = make_sample_report()
    r.results[0].findings[1] = Finding(Severity.INFO, "a|b *c* _d_")
    out = render(r, "markdown")
    assert r"a\|b \*c\* \_d\_" in out


def test_text_no_ansi_without_color() -> None:
    assert "\x1b[" not in render(make_sample_report(), "text")


def test_text_ansi_with_color() -> None:
    assert "\x1b[" in render(make_sample_report(), "text", color=True)


def test_unknown_format_raises() -> None:
    with pytest.raises(ValueError, match="unknown format"):
        render(make_sample_report(), "pdf")
