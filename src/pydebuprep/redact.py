"""Keep secrets out of reports: they quote logs and crontabs, and may leave the host.

Best effort, by the shape of what is usually secret. It can't recognise a secret that looks
like anything else, so reports should still be treated as private.
"""

from __future__ import annotations

import dataclasses
import re

from pydebuprep.model import Finding

REDACTED = "<redacted>"
_WORD = r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)"
_RULES = (
    # pdp_<id>_<secret>: the portal's upload tokens
    (re.compile(r"pdp_[0-9a-f]{8}_[A-Za-z0-9_-]{43}"), REDACTED),
    # Authorization: Bearer xyz, bearer xyz
    (re.compile(r"(?i)\b(authorization:\s*|bearer\s+)(?:bearer\s+)?\S+"), rf"\1{REDACTED}"),
    # scheme://user:secret@host
    (re.compile(r"(://[^/\s:@]+:)[^/\s@]+(@)"), rf"\1{REDACTED}\2"),
    # --password secret, --auth-token=secret
    (re.compile(rf"(?i)(--[\w-]*{_WORD}[\w-]*[= ]+)\S+"), rf"\1{REDACTED}"),
    # password=secret, DB_PASSWORD: secret, "api_key": "secret"
    (re.compile(rf"(?i)([\w-]*{_WORD}[\w-]*[\"']?\s*[=:]\s*[\"']?)[^\s\"'&;,]+"), rf"\1{REDACTED}"),
    # mysql -psecret: the password follows -p with no space
    (
        re.compile(
            r"\b((?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump|mariadb-admin)\b[^;|&\n]*?\s-p)\S+"
        ),
        rf"\1{REDACTED}",
    ),
)


def redact(text: str) -> str:
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text


def redact_finding(finding: Finding) -> Finding:
    return dataclasses.replace(
        finding,
        title=redact(finding.title),
        detail=redact(finding.detail),
        evidence=[redact(line) for line in finding.evidence],
        remediation=[redact(step) for step in finding.remediation],
    )
