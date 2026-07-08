from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pipeline_audit import __version__
from pipeline_audit.core.rule_base import Finding
from pipeline_audit.core.severity import Severity


SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
    "cs01/schemas/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def _relative(file_path: Path, root: Path | None) -> str:
    if root is not None:
        try:
            return file_path.relative_to(root).as_posix()
        except ValueError:
            pass
    return file_path.as_posix()


def _build_rules_index(findings: list[Finding]) -> dict[str, dict]:
    """Build a de-duplicated rules dictionary keyed by rule_id."""
    rules: dict[str, dict] = {}
    for f in findings:
        if f.rule_id in rules:
            continue
        rules[f.rule_id] = {
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.remediation or f.title},
            "helpUri": f.references[0] if f.references else "",
            "help": {"text": f.remediation or ""},
            "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL[f.severity]},
        }
    return rules


def _result(f: Finding, root: Path | None) -> dict:
    region: dict = {}
    if f.location.line is not None:
        region["startLine"] = f.location.line
        if f.location.end_line is not None and f.location.end_line != f.location.line:
            region["endLine"] = f.location.end_line
        if f.location.col is not None:
            region["startColumn"] = f.location.col

    artifact_location = {"uri": _relative(f.file, root)}
    physical_location = {"artifactLocation": artifact_location}
    if region:
        physical_location["region"] = region

    return {
        "ruleId": f.rule_id,
        "level": _SEVERITY_TO_LEVEL[f.severity],
        "message": {
            "text": f.title,
            "markdown": f.location.snippet or "",
        },
        "locations": [{"physicalLocation": physical_location}],
        "partialFingerprints": {
            "primaryLocationLineHash": f"{f.rule_id}:{f.file.as_posix()}:{f.location.line or 0}",
        },
    }


def render_sarif(findings: list[Finding], *, root: Path | None = None) -> str:
    rules_index = _build_rules_index(findings)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pipeline-audit",
                        "version": __version__,
                        "informationUri": "https://github.com/jrmywm/pipeline-audit",
                        "rules": list(rules_index.values()),
                    }
                },
                "results": [_result(f, root) for f in findings],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": now,
                    }
                ],
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


__all__ = ["render_sarif"]