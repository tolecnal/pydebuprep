from __future__ import annotations

import fnmatch
import os
import re

from pydebuprep.checks.base import Check, Context, Option, count
from pydebuprep.model import Finding, Severity, truncate_evidence

SEARCH_PATHS = ["/opt", "/srv", "/usr/local", "/root", "/home", "/var/www"]
VERSION = re.compile(r"^version(?:_info)?\s*=\s*(\d+)\.(\d+)", re.MULTILINE)


class PythonVenvsCheck(Check):
    id = "python-venvs"
    title = "Python virtualenvs"
    category = "applications"
    options = (
        Option("search_paths", SEARCH_PATHS, "Directories searched for virtualenvs (pyvenv.cfg)"),
        Option("max_depth", 5, "How many directories deep to search below each path"),
        Option(
            "exclude_paths",
            ["*/.cache/*"],
            "Virtualenvs to leave out (shell-style patterns), e.g. tools' throwaway "
            "environments under ~/.cache",
        ),
    )

    def validate(self) -> None:
        if self.opt("max_depth") < 1:
            raise ValueError("max_depth must be at least 1")

    def run(self, ctx: Context) -> list[Finding]:
        system_python = ctx.system.python_version()
        current = tuple(int(p) for p in system_python.split("."))
        broken, older = [], []
        for cfg in ctx.system.find_files(
            self.opt("search_paths"), "pyvenv.cfg", self.opt("max_depth")
        ):
            m = VERSION.search(ctx.system.read_text(cfg) or "")
            if not m:
                continue
            venv = os.path.dirname(cfg)
            if any(fnmatch.fnmatchcase(venv, p) for p in self.opt("exclude_paths")):
                continue
            label = f"{venv} (Python {m.group(1)}.{m.group(2)})"
            if not ctx.system.exists(f"{venv}/bin/python"):
                broken.append(label)
            elif (int(m.group(1)), int(m.group(2))) < current:
                older.append(label)
        findings = []
        if broken:
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"{count(len(broken), 'virtualenv points', 'virtualenvs point')} to a Python "
                    "that no longer exists",
                    detail="The upgrade replaced the Python they were built with, so anything "
                    "they run fails.",
                    evidence=truncate_evidence(broken),
                    remediation=[
                        "Recreate each one: python3 -m venv --clear PATH, then reinstall its "
                        "requirements",
                    ],
                )
            )
        if older:
            findings.append(
                Finding(
                    Severity.INFO,
                    f"{count(len(older), 'virtualenv was', 'virtualenvs were')} built for an older "
                    f"Python than the system's {system_python}",
                    detail="They still work while that Python stays installed, but won't get "
                    "its security updates for long.",
                    evidence=truncate_evidence(older),
                    remediation=["Recreate them with the current python3 when convenient"],
                )
            )
        return findings
