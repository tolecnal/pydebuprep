from __future__ import annotations

import json
from collections import Counter

from pydebuprep.checks.base import Check, Context, count
from pydebuprep.model import Finding, Severity, truncate_evidence

JOURNAL = ("journalctl", "-p", "err", "-b", "--no-pager", "-o", "json")
PERMISSION_HINTS = ("insufficient permissions", "not seeing messages from other users")
MAX_MESSAGE = 200


def _message(value: object) -> str:
    if isinstance(value, list):
        try:
            return bytes(value).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            return str(value)
    return str(value)


class JournalErrorsCheck(Check):
    id = "journal-errors"
    title = "Errors in the journal (current boot)"
    category = "services"
    requires_commands = ("journalctl",)

    def run(self, ctx: Context) -> list[Finding]:
        res = ctx.system.run(list(JOURNAL), timeout=60)
        counts: Counter[tuple[str, str]] = Counter()
        for line in res.stdout.splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if not isinstance(entry, dict):
                continue
            ident = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM") or "kernel"
            msg = " ".join(_message(entry.get("MESSAGE", "")).split())[:MAX_MESSAGE]
            counts[(str(ident), msg)] += 1
        findings = []
        if counts:
            total = sum(counts.values())
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"{count(total, 'error message')} in the current boot ({len(counts)} distinct)",
                    detail="Most common first. Some noise is normal; look for services you rely "
                    "on and anything new since the upgrade.",
                    evidence=truncate_evidence(
                        [f"{n}x {ident}: {msg}" for (ident, msg), n in counts.most_common()]
                    ),
                    remediation=["journalctl -p err -b", "journalctl -u UNIT -b for a service"],
                )
            )
        if any(h in res.stderr for h in PERMISSION_HINTS):
            findings.append(
                Finding(
                    Severity.INFO,
                    "Journal only partially readable",
                    remediation=["Run as root, or add your user to the adm group"],
                )
            )
        return findings
