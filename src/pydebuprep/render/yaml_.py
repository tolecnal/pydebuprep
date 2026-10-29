from __future__ import annotations

from pydebuprep.deps import require_yaml
from pydebuprep.model import Report
from pydebuprep.render._common import report_data


def render(report: Report, *, todo: bool = False) -> str:
    yaml = require_yaml()
    text: str = yaml.safe_dump(
        report_data(report, todo), sort_keys=False, allow_unicode=True, default_flow_style=False
    )
    return text
