from __future__ import annotations

import json
import re
from collections import Counter

from pydebuprep.checks.base import Check, Context, Option, count, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence

JOURNAL = ("journalctl", "-p", "err", "-b", "--no-pager", "-o", "json")
PERMISSION_HINTS = ("insufficient permissions", "not seeing messages from other users")
MAX_MESSAGE = 200
# Hex/decimal runs containing a digit (PIDs, interface suffixes, addresses) vary between
# otherwise identical messages; collapse them for grouping.
VARIABLE = re.compile(r"[0-9a-fA-F]*[0-9][0-9a-fA-F]*")


def compile_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
    compiled = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern))
        except re.error as exc:
            raise ValueError(f"invalid ignore pattern {pattern!r}: {exc}") from None
    return compiled


def shared_patterns(ctx: Context) -> list[re.Pattern[str]]:
    return compile_patterns(list(ctx.log_ignore))


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
    options = (
        Option(
            "ignore",
            [],
            "Regular expressions; messages matching any of them (as 'IDENTIFIER: message') "
            "are left out",
            split=False,
        ),
    )

    def validate(self) -> None:
        self.patterns = compile_patterns(self.opt("ignore"))

    def run(self, ctx: Context) -> list[Finding]:
        res = run_checked(ctx, JOURNAL, timeout=60)
        counts: Counter[tuple[str, str]] = Counter()
        examples: dict[tuple[str, str], str] = {}
        ignored = 0
        shared = shared_patterns(ctx)
        variants: dict[tuple[str, str], set[str]] = {}
        for line in res.stdout.splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if not isinstance(entry, dict):
                continue
            ident = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM") or "kernel"
            msg = " ".join(_message(entry.get("MESSAGE", "")).split())[:MAX_MESSAGE]
            if any(p.search(msg) for p in shared) or any(
                p.search(f"{ident}: {msg}") for p in self.patterns
            ):
                ignored += 1
                continue
            key = (str(ident), VARIABLE.sub("#", msg))
            counts[key] += 1
            examples.setdefault(key, msg)
            variants.setdefault(key, set()).add(msg)
        findings = []
        if counts:
            total = sum(counts.values())
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"{count(total, 'error message')} in the current boot ({len(counts)} distinct)",
                    detail="Most common first. Some noise is normal; look for services you rely "
                    "on and anything new since the upgrade."
                    + (f" ({ignored} ignored by configuration.)" if ignored else ""),
                    evidence=truncate_evidence(
                        [
                            f"{n}x {key[0]}: {examples[key]}"
                            + (" (and similar)" if n > 1 and len(variants[key]) > 1 else "")
                            for key, n in counts.most_common()
                        ]
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
