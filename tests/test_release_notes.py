"""A GitHub Release's notes come from the version's entry in debian/changelog."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "release-notes.py"
CHANGELOG = """\
pydebuprep (0.9.0) unstable; urgency=medium

  * A change that wraps
    onto a second line.
  * Upgrade a portal first.

 -- A Person <a@example.org>  Sun, 01 Nov 2026 13:30:00 +0100

pydebuprep (0.8.0) unstable; urgency=medium

  * Older.

 -- A Person <a@example.org>  Sat, 31 Oct 2026 16:34:01 +0100
"""


def notes(tmp_path: Path, version: str) -> subprocess.CompletedProcess[str]:
    changelog = tmp_path / "changelog"
    changelog.write_text(CHANGELOG)
    return subprocess.run(
        [sys.executable, str(SCRIPT), version, str(changelog)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip


def test_notes_are_the_versions_changelog_entry(tmp_path: Path) -> None:
    res = notes(tmp_path, "0.9.0")
    assert res.returncode == 0, res.stderr
    assert res.stdout.startswith(
        "## What changed\n\n- A change that wraps onto a second line.\n- Upgrade a portal first.\n"
    )
    assert "Older." not in res.stdout


def test_notes_say_how_to_verify_the_download(tmp_path: Path) -> None:
    out = notes(tmp_path, "0.9.0").stdout
    assert "sha256sum -c SHA256SUMS" in out
    assert "gh attestation verify pydebuprep_0.9.0_all.deb -R tolecnal/pydebuprep" in out


def test_a_version_without_an_entry_fails(tmp_path: Path) -> None:
    res = notes(tmp_path, "1.0.0")
    assert res.returncode == 1
    assert "no entry for 1.0.0" in res.stderr


def test_every_released_version_has_notes() -> None:
    res = subprocess.run(
        [sys.executable, str(SCRIPT), "0.8.0"], capture_output=True, text=True, check=False
    )
    assert res.returncode == 0 and "machine ID" in res.stdout


def test_the_release_workflow_uses_them() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    steps = workflow["jobs"]["publish"]["steps"]
    run = "\n".join(s.get("run", "") for s in steps)
    assert "scripts/release-notes.py" in run and "--notes-file" in run
    assert any(s.get("uses", "").startswith("actions/checkout@") for s in steps)
