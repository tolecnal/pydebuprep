"""Optional-at-runtime dependencies.

PyYAML (python3-yaml) is a package dependency, so apt installs it. Without it the tool
still runs, and only the features that need YAML stop with an install hint.
"""

from __future__ import annotations

from types import ModuleType

YAML_HINT = "python3-yaml is not installed; install it with: sudo apt install python3-yaml"


class MissingDependency(Exception):
    pass


def require_yaml() -> ModuleType:
    try:
        import yaml
    except ImportError:
        raise MissingDependency(YAML_HINT) from None
    return yaml
