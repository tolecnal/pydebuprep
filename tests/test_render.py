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
    assert FORMATS == ("text", "json", "yaml", "html", "markdown", "jira", "confluence")
    assert EXTENSIONS == {
        "text": "txt",
        "json": "json",
        "yaml": "yaml",
        "html": "html",
        "markdown": "md",
        "jira": "jira.txt",
        "confluence": "confluence.txt",
    }


def test_json_roundtrip_equals_to_dict() -> None:
    r = make_sample_report()
    assert json.loads(render(r, "json")) == r.to_dict()


def test_yaml_roundtrip_equals_to_dict() -> None:
    r = make_sample_report()
    assert yaml.safe_load(render(r, "yaml")) == r.to_dict()


HUMAN_FORMATS = ["text", "html", "markdown", "jira", "confluence"]


@pytest.mark.parametrize("fmt", HUMAN_FORMATS)
def test_all_formats_contain_same_items_in_same_order(fmt: str) -> None:
    out = render(make_sample_report(), fmt)
    pos = 0
    for item in expected_sequence():
        found = out.find(item, pos)
        assert found >= 0, f"{fmt}: {item!r} missing after position {pos}"
        pos = found + len(item)


@pytest.mark.parametrize("fmt", HUMAN_FORMATS)
def test_no_baseline_mentioned_once(fmt: str) -> None:
    """Without a baseline, say so once in the header instead of in every check."""
    r = make_sample_report()
    r.baseline = None
    for res in r.results:
        res.baseline_diff = None
    out = render(r, fmt)
    assert out.lower().count("baseline") == 1
    assert "Baseline: none" in out
    assert "Changes since baseline" not in out


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


SURROGATE_PATH = "/etc/foo\udcff.conf.dpkg-dist"


@pytest.mark.parametrize("fmt", FORMATS)
def test_surrogate_escaped_paths_render_as_valid_utf8(fmt: str) -> None:
    r = make_sample_report()
    r.results[0].findings[0].evidence = [SURROGATE_PATH]
    out = render(r, fmt)
    out.encode("utf-8")  # must not raise
    assert "foo" in out


@pytest.mark.parametrize("fmt", ["text", "markdown", "jira", "confluence"])
def test_terminal_control_sequences_stripped(fmt: str) -> None:
    r = make_sample_report()
    r.results[0].findings[0].evidence = ["\x1b]2;pwned\x07 evil \x9b31m"]
    r.results[0].findings[0].title = "title \x1b[2J"
    out = render(r, fmt)
    assert "\x1b" not in out
    assert "\x07" not in out
    assert "\x9b" not in out
    assert "evil" in out


def test_jira_markup() -> None:
    out = render(make_sample_report(), "jira")
    assert out.startswith("h1. pydebuprep report\n")
    assert "||Critical||Warning||Info||OK||Skipped||Error||Exit code||" in out
    assert "|1|1|1|1|1|0|2|" in out
    assert "h2. Release" in out
    assert "h3. {{apt-sources}} - APT sources" in out
    assert "{color:#de350b}*CRITICAL*{color}: Repository still targets bookworm" in out
    assert (
        "{noformat}\n/etc/apt/sources.list: deb http://deb.debian.org/debian bookworm\n{noformat}"
        in out
    )
    assert "# Edit /etc/apt/sources.list: change bookworm to trixie" in out
    assert "* [https://www.debian.org/releases/trixie/releasenotes]" in out
    assert "{status" not in out


def test_confluence_markup() -> None:
    out = render(make_sample_report(), "confluence")
    assert out.startswith("h1. pydebuprep report\n")
    assert "{status:colour=Red|title=CRITICAL}" in out
    assert "{warning}" in out  # critical findings sit in a warning panel
    assert "{info}" in out
    assert (
        "{noformat}\n/etc/apt/sources.list: deb http://deb.debian.org/debian bookworm\n{noformat}"
        in out
    )
    assert "{status:colour=Grey|title=SKIPPED}" in out
    assert "{color:" not in out


@pytest.mark.parametrize("fmt", ["jira", "confluence"])
def test_wiki_escaping(fmt: str) -> None:
    r = make_sample_report()
    r.results[0].findings[1] = Finding(
        Severity.INFO,
        "a|b {c} [d] *e* _f_ !g! ^h^ ~i~ +j+ #k \\l",
        evidence=["{noformat} escape attempt"],
    )
    out = render(r, fmt)
    assert r"a\|b \{c\} \[d\] \*e\* \_f\_ \!g\! \^h\^ \~i\~ \+j\+ \#k \\l" in out
    assert "{noformat} escape attempt" not in out


@pytest.mark.parametrize("fmt", ["jira", "confluence"])
def test_wiki_double_hyphen_not_turned_into_dash(fmt: str) -> None:
    r = make_sample_report()
    r.results[0].findings[1] = Finding(
        Severity.INFO, "x", remediation=["sudo apt autoremove --purge"]
    )
    out = render(r, fmt)
    assert r"# sudo apt autoremove \-\-purge" in out


@pytest.mark.parametrize("fmt", ["jira", "confluence"])
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("- not a list item", r"\- not a list item"),
        ("keep -this- intact", r"keep \-this- intact"),
        ("apt-sources stays", "apt-sources stays"),
        ("a--b", r"a\-\-b"),
        ("??not a citation??", r"\?\?not a citation\?\?"),
        (
            "no (i) (x) (on) (off) (-) (/) (y) emoticons",
            r"no \(i) \(x) \(on) \(off) \(-) \(/) \(y) emoticons",
        ),
        ("ordinary (parentheses) stay", "ordinary (parentheses) stay"),
    ],
)
def test_wiki_markup_triggers_escaped(fmt: str, text: str, expected: str) -> None:
    r = make_sample_report()
    r.results[0].findings[1] = Finding(Severity.INFO, "t", detail=text)
    assert f"\n{expected}\n" in render(r, fmt)


@pytest.mark.parametrize("fmt", ["jira", "confluence"])
@pytest.mark.parametrize("start", ["h1. x", "h6. x", "bq. x", "----"])
def test_wiki_block_markers_at_line_start_neutralised(fmt: str, start: str) -> None:
    r = make_sample_report()
    r.results[0].findings[1] = Finding(Severity.INFO, "t", detail=start)
    out = render(r, fmt)
    assert f"\n{start}" not in out.replace(r"\-\-\-\-", "")
