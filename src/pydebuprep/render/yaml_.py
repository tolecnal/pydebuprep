from __future__ import annotations

from pydebuprep.deps import require_yaml
from pydebuprep.model import Report


def render(report: Report) -> str:
    yaml = require_yaml()
    text: str = yaml.safe_dump(
        report.to_dict(), sort_keys=False, allow_unicode=True, default_flow_style=False
    )
    return text
