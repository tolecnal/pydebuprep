from __future__ import annotations

import json

from pydebuprep.model import Report
from pydebuprep.render._common import report_data


def render(report: Report, *, todo: bool = False) -> str:
    return json.dumps(report_data(report, todo), indent=2, ensure_ascii=False) + "\n"
