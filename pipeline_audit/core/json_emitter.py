from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pipeline_audit.core.rule_base import Finding
from pipeline_audit.core.severity import Severity


def _finding_to_dict(f: Finding, root: Path | None) -> dict:
    file_path = Path(f.file)
    if root is not None:
        try:
            file_str = file_path.relative_to(root).as_posix()
        except ValueError:
            file_str = file_path.as_posix()
    else:
        file_str = file_path.as_posix()

    return {
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity.label,
        "target": f.target,
        "file": file_str,
        "line": f.location.line,
        "end_line": f.location.end_line,
        "column": f.location.col,
        "snippet": f.location.snippet,
        "remediation": f.remediation,
        "references": list(f.references),
    }


def render_json(findings: list[Finding], *, root: Path | None = None) -> str:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    payload = {
        "schema": "pipeline-audit/v1",
        "generated_at": now,
        "summary": _summary(findings),
        "findings": [_finding_to_dict(f, root) for f in findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _summary(findings: list[Finding]) -> dict:
    counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f.severity.label] += 1
    return {"total": len(findings), "by_severity": counts}


__all__ = ["render_json"]