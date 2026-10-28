from __future__ import annotations

import json

from pydebuprep.model import Report


def render(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"
