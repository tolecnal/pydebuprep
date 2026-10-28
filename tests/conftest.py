from __future__ import annotations

import sys
from pathlib import Path

import pytest

# pytest < 7 (Ubuntu 22.04) has no `pythonpath` ini option; make src importable directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pydebuprep.model import (
    BaselineInfo,
    CheckResult,
    Finding,
    Host,
    Report,
    Severity,
    Status,
    compute_summary,
)


def make_sample_report() -> Report:
    results = [
        CheckResult(
            "apt-sources",
            "APT sources",
            "release",
            Status.FINDINGS,
            findings=[
                Finding(
                    Severity.CRITICAL,
                    "Repository still targets bookworm",
                    detail="One source points at the previous release.",
                    evidence=["/etc/apt/sources.list: deb http://deb.debian.org/debian bookworm"],
                    remediation=["Edit /etc/apt/sources.list: change bookworm to trixie"],
                    references=["https://www.debian.org/releases/trixie/releasenotes"],
                ),
                Finding(Severity.INFO, "Duplicate source entry", remediation=["Remove one"]),
            ],
            baseline_diff=[
                Finding(
                    Severity.WARNING,
                    "Repository https://example.com was enabled before the upgrade",
                    remediation=["Re-enable it once the vendor supports trixie"],
                )
            ],
        ),
        CheckResult(
            "debsums",
            "Package file checksums",
            "packages",
            Status.SKIPPED,
            skipped_reason="command not found: debsums",
        ),
        CheckResult("fstab", "fstab", "storage", Status.OK, baseline_diff=None),
    ]
    return Report(
        tool={"name": "pydebuprep", "version": "0.2.0"},
        generated_at="2026-10-28T12:00:00+00:00",
        host=Host("testhost", "debian", "13", "trixie", "6.12.0-1-amd64", True),
        baseline=BaselineInfo(
            "/var/lib/pydebuprep/snapshots/20261027T100000Z.json",
            "2026-10-27T10:00:00+00:00",
            "12",
            "testhost",
        ),
        summary=compute_summary(results),
        results=results,
    )


@pytest.fixture(autouse=True)
def _no_host_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Never let a real /etc/pydebuprep.conf on the test machine leak into tests."""
    empty = tmp_path_factory.mktemp("conf") / "pydebuprep.conf"
    empty.write_text("")
    monkeypatch.setenv("PYDEBUPREP_CONFIG", str(empty))
