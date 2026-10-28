from __future__ import annotations

import yaml

from pydebuprep.model import Report


def render(report: Report) -> str:
    return yaml.safe_dump(
        report.to_dict(), sort_keys=False, allow_unicode=True, default_flow_style=False
    )
