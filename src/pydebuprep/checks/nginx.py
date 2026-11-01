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

CONF_DIR = "/etc/nginx"  # relative include paths start here
PREFIX = "/usr/share/nginx"  # relative load_module paths start here (Debian's --prefix)
MAIN = f"{CONF_DIR}/nginx.conf"
TOKEN = re.compile(r'"((?:\\.|[^"\\])*)"|\'((?:\\.|[^\'\\])*)\'|#[^\n]*|([{};])|([^\s{};"\'#]+)')


def statements(text: str) -> Iterator[list[str]]:
    """The directives of an nginx configuration, each as its words, comments left out."""
    words: list[str] = []
    for match in TOKEN.finditer(text):
        double, single, punctuation, word = match.groups()
        if punctuation:
            if words:
                yield words
            words = []
        elif double is not None or single is not None or word is not None:
            words.append(next(w for w in (double, single, word) if w is not None))
    if words:
        yield words


class NginxCheck(Check):
    id = "nginx"
    title = "nginx configuration references"
    category = "applications"

    def run(self, ctx: Context) -> list[Finding]:
        if not ctx.system.exists(MAIN):
            raise CheckSkipped("nginx is not installed")
        queue, seen = [MAIN], set[str]()
        includes: list[str] = []
        modules: list[str] = []
        sockets: list[Ref] = []
        while queue and len(seen) < MAX_FILES:
            path = queue.pop(0)
            if path in seen:
                continue
            seen.add(path)
            for name, *args in statements(ctx.system.read_text(path) or ""):
                if not args or "$" in args[0]:
                    continue
                if name == "include":
                    ref = Ref(resolve(CONF_DIR, args[0]), f"include {args[0]}", path)
                    found, missing = include(ctx, ref)
                    queue += found
                    includes += missing
                elif name == "load_module":
                    module = resolve(PREFIX, args[0])
                    if not ctx.system.exists(module):
                        modules.append(f"{module} doesn't exist (load_module {args[0]} in {path})")
                elif name.endswith("_pass") or name == "server":
                    sockets += [Ref(s, name, path) for a in args if (s := socket_path(a))]
        return findings(
            "nginx", "nginx", CONF_DIR,
            includes=includes, modules=modules, sockets=missing_sockets(ctx, sockets),
        )  # fmt: skip
