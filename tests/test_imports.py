from __future__ import annotations

import pkgutil
import subprocess
import sys
from pathlib import Path

import pytest

import pydebuprep

SRC = Path(pydebuprep.__file__).parent.parent
MODULES = sorted(
    m.name
    for m in pkgutil.walk_packages(pydebuprep.__path__, "pydebuprep.")
    if "__main__" not in m.name
)


@pytest.mark.parametrize("module", MODULES)
def test_module_imports_standalone(module: str) -> None:
    """Every module must import first in a fresh interpreter (no circular imports)."""
    res = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(SRC)},
        check=False,
    )
    assert res.returncode == 0, res.stderr


def test_report_never_imports_cleanup() -> None:
    """Only pydebuprep-cleanup changes the system: nothing else may import its code."""
    import ast

    package = SRC / "pydebuprep"
    for path in sorted(package.rglob("*.py")):
        if (package / "cleanup") in path.parents:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or "", *(f"{node.module}.{a.name}" for a in node.names)]
            assert not any(n.startswith("pydebuprep.cleanup") for n in names), path
