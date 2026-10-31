"""The read-only audit covers runs that upload and use a config from a URL."""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from test_readonly_audit import audit

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
STATE_WRITE = (
    '100 openat(AT_FDCWD, "{d}/.x.json.0a1b", O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600)'
    " = 3\n"
    '100 rename("{d}/.x.json.0a1b", "{d}/x.json") = 0\n'
)


def test_postinst_creates_the_state_directories() -> None:
    text = (ROOT / "debian" / "pydebuprep.postinst").read_text()
    assert (
        "install -d -m 0700 /var/lib/pydebuprep /var/lib/pydebuprep/snapshots "
        "/var/lib/pydebuprep/pending /var/lib/pydebuprep/configs"
    ) in text


def test_state_writes_pass_only_under_the_allowed_prefix(tmp_path: Path) -> None:
    ok = STATE_WRITE.format(d="/var/lib/pydebuprep/pending")
    assert audit(tmp_path, ok, "/var/lib/pydebuprep/")[0] == 0
    rc, out = audit(tmp_path, STATE_WRITE.format(d="/etc"), "/var/lib/pydebuprep/")
    assert rc == 1 and "/etc/x.json" in out


def test_the_audit_runs_the_portal_cases() -> None:
    text = (SCRIPTS / "readonly-audit.sh").read_text()
    assert 'if [ -n "${AUDIT_PORTAL_URL:-}" ]; then' in text
    assert (
        'audit portal /var/lib/pydebuprep/ pydebuprep report --config "$AUDIT_PORTAL_URL" '
        "--allow-http --no-baseline --format json -o -"
    ) in text
    assert "audit portal-offline /var/lib/pydebuprep/" in text
    assert 'kill "$AUDIT_PORTAL_PID"' in text
    for check in ("pending/*.json", "configs/*.json", '"stale": true'):
        assert check in text
    # The plain report run still may not write anywhere.
    assert 'audit report "" pydebuprep report --no-baseline --format json -o -' in text


def test_ci_starts_the_stand_in_portal() -> None:
    text = (SCRIPTS / "ci-readonly-audit.sh").read_text()
    assert "install -d -m 0700 /etc/pydebuprep" in text
    assert "install -m 0600" in text and "/etc/pydebuprep/token" in text
    assert "audit-portal-stub.py" in text
    assert "export AUDIT_PORTAL_URL AUDIT_PORTAL_PID" in text


def test_stand_in_portal(tmp_path: Path) -> None:
    url_file = tmp_path / "url"
    stub = subprocess.Popen(
        [sys.executable, str(SCRIPTS / "audit-portal-stub.py"), str(url_file)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            if url_file.exists() and url_file.read_text().endswith("\n"):
                break
            subprocess.run(["sleep", "0.05"], check=True)
        config_url = url_file.read_text().strip()
        assert config_url.endswith("/api/v1/configs/audit/default")
        base = config_url.removesuffix("/api/v1/configs/audit/default")
        with urllib.request.urlopen(config_url, timeout=5) as resp:
            text = resp.read().decode()
        assert f"upload:\n  url: {base}\n" in text
        assert "debsums:\n    enabled: false" in text
        post = urllib.request.Request(base + "/api/v1/reports", data=b"{}", method="POST")
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(post, timeout=5)
        assert exc.value.code == 503
        assert json.loads(exc.value.read())["detail"]
    finally:
        stub.terminate()
        stub.wait(5)
