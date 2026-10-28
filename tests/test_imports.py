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
