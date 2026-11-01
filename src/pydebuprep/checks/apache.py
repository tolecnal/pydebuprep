from __future__ import annotations

import re
from collections.abc import Iterator

from pydebuprep.checks._webconfig import (
    MAX_FILES,
    Ref,
    findings,
    include,
    missing_sockets,
    resolve,
    socket_path,
)
from pydebuprep.checks.base import Check, CheckSkipped, Context
from pydebuprep.model import Finding

SERVER_ROOT = "/etc/apache2"  # relative Include and LoadModule paths start here
MAIN = f"{SERVER_ROOT}/apache2.conf"
WORD = re.compile(r'"((?:\\.|[^"\\])*)"|(\S+)')


def directives(text: str) -> Iterator[tuple[str, list[str]]]:
    """The directives of an Apache configuration as (name, arguments); comments and
    section tags (<VirtualHost ...>) left out, continued lines joined."""
    for raw in text.replace("\\\n", " ").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "<")):
            continue
        words = [m.group(1) if m.group(1) is not None else m.group(2) for m in WORD.finditer(line)]
        yield words[0], words[1:]


class ApacheCheck(Check):
    id = "apache"
    title = "Apache configuration references"
    category = "applications"

    def run(self, ctx: Context) -> list[Finding]:
        if not ctx.system.exists(MAIN):
            raise CheckSkipped("Apache is not installed")
        queue, seen = [MAIN], set[str]()
        includes: list[str] = []
        modules: list[str] = []
        sockets: list[Ref] = []
        while queue and len(seen) < MAX_FILES:
            path = queue.pop(0)
            if path in seen:
                continue
            seen.add(path)
            for name, args in directives(ctx.system.read_text(path) or ""):
                lower = name.lower()
                if lower in ("include", "includeoptional") and args and "$" not in args[0]:
                    ref = Ref(resolve(SERVER_ROOT, args[0]), f"{name} {args[0]}", path)
                    found, missing = include(ctx, ref, optional=lower == "includeoptional")
                    queue += found
                    includes += missing
                elif lower == "loadmodule" and len(args) > 1 and "$" not in args[1]:
                    module = resolve(SERVER_ROOT, args[1])
                    if not ctx.system.exists(module):
                        modules.append(f"{module} doesn't exist ({name} {args[0]} in {path})")
                else:
                    sockets += [Ref(s, name, path) for a in args if (s := socket_path(a))]
        return findings(
            "Apache", "apache2", SERVER_ROOT,
            includes=includes, modules=modules, sockets=missing_sockets(ctx, sockets),
        )  # fmt: skip
