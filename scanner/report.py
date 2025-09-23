# -*- coding: utf-8 -*-

import json
from pathlib import Path
from jinja2 import Template

def to_json(report: dict, path: str):
    Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

def to_html(report: dict, path: str):
    tpl_path = Path(__file__).with_name("report_template.html")
    tpl_str = tpl_path.read_text(encoding="utf-8")
    # garantir chaves do summary
    report.setdefault("summary", {})
    for k in ("high", "medium", "low"):
        report["summary"].setdefault(k, 0)
    html = Template(tpl_str).render(data=report)
    Path(path).write_text(html, encoding="utf-8")
