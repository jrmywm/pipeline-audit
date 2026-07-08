from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline_audit.core.location import Location
from pipeline_audit.core.json_emitter import render_json
from pipeline_audit.core.rule_base import Finding
from pipeline_audit.core.sarif_emitter import render_sarif
from pipeline_audit.core.severity import Severity


def _f(
    rule_id: str = "DOCKER-R001",
    sev: Severity = Severity.HIGH,
    file: str = "Dockerfile",
    line: int | None = 1,
    snippet: str | None = "FROM alpine",
    remediation: str = "Add USER.",
    references: list[str] | None = None,
    title: str = "Test rule",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=sev,
        target="dockerfile",
        location=Location(file=Path(file), line=line, snippet=snippet),
        remediation=remediation,
        references=references or [],
    )


# ─── JSON emitter ────────────────────────────────────────────────────────────


class TestJsonEmitter:
    def test_empty_findings(self):
        out = render_json([])
        data = json.loads(out)
        assert data["schema"] == "pipeline-audit/v1"
        assert data["summary"]["total"] == 0
        assert data["findings"] == []

    def test_summary_counts(self):
        findings = [
            _f(sev=Severity.HIGH, file="a"),
            _f(sev=Severity.HIGH, file="b", line=2),
            _f(sev=Severity.MEDIUM, file="c"),
            _f(sev=Severity.CRITICAL, file="d"),
        ]
        data = json.loads(render_json(findings))
        assert data["summary"]["total"] == 4
        assert data["summary"]["by_severity"]["High"] == 2
        assert data["summary"]["by_severity"]["Medium"] == 1
        assert data["summary"]["by_severity"]["Critical"] == 1

    def test_finding_dict_fields(self):
        findings = [_f(references=["https://x.com"])]
        data = json.loads(render_json(findings))
        f = data["findings"][0]
        assert f["rule_id"] == "DOCKER-R001"
        assert f["severity"] == "High"
        assert f["line"] == 1
        assert f["snippet"] == "FROM alpine"
        assert f["remediation"] == "Add USER."
        assert f["references"] == ["https://x.com"]

    def test_relative_path_with_root(self, tmp_path):
        f = _f(file=str(tmp_path / "Dockerfile"))
        data = json.loads(render_json([f], root=tmp_path))
        assert data["findings"][0]["file"] == "Dockerfile"

    def test_absolute_path_without_root(self):
        f = _f(file="/some/abs/Dockerfile")
        data = json.loads(render_json([f]))
        assert data["findings"][0]["file"] == "/some/abs/Dockerfile"

    def test_iso_timestamp(self):
        data = json.loads(render_json([]))
        assert "T" in data["generated_at"]
        # Should be parseable as ISO 8601
        from datetime import datetime
        datetime.fromisoformat(data["generated_at"])

    def test_output_is_valid_json(self):
        findings = [_f(), _f(rule_id="GHA-R001", sev=Severity.MEDIUM, file="wf.yml")]
        out = render_json(findings)
        # Must not raise
        json.loads(out)


# ─── SARIF emitter ──────────────────────────────────────────────────────────


class TestSarifEmitter:
    def test_empty_findings(self):
        out = render_sarif([])
        doc = json.loads(out)
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc
        assert len(doc["runs"]) == 1
        assert doc["runs"][0]["results"] == []

    def test_tool_metadata(self):
        doc = json.loads(render_sarif([_f()]))
        tool = doc["runs"][0]["tool"]["driver"]
        assert tool["name"] == "pipeline-audit"
        assert "version" in tool
        assert "rules" in tool

    def test_result_has_locations(self):
        doc = json.loads(render_sarif([_f(line=5)]))
        result = doc["runs"][0]["results"][0]
        assert result["ruleId"] == "DOCKER-R001"
        assert "locations" in result
        loc = result["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] == 5
        assert "uri" in loc["artifactLocation"]

    def test_level_mapping(self):
        for sev, expected in [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
        ]:
            doc = json.loads(render_sarif([_f(sev=sev)]))
            assert doc["runs"][0]["results"][0]["level"] == expected

    def test_rules_index_dedup(self):
        findings = [
            _f(rule_id="DOCKER-R001", file="a"),
            _f(rule_id="DOCKER-R001", file="b", line=2),
            _f(rule_id="GHA-R001", sev=Severity.MEDIUM, file="c"),
        ]
        doc = json.loads(render_sarif(findings))
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert sorted(set(rule_ids)) == ["DOCKER-R001", "GHA-R001"]
        # Should not duplicate DOCKER-R001
        assert rule_ids.count("DOCKER-R001") == 1

    def test_artifact_uri_relative(self, tmp_path):
        f = _f(file=str(tmp_path / "Dockerfile"))
        doc = json.loads(render_sarif([f], root=tmp_path))
        uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "Dockerfile"

    def test_partial_fingerprints_present(self):
        doc = json.loads(render_sarif([_f()]))
        result = doc["runs"][0]["results"][0]
        assert "partialFingerprints" in result
        assert "primaryLocationLineHash" in result["partialFingerprints"]

    def test_invocation_record(self):
        doc = json.loads(render_sarif([_f()]))
        inv = doc["runs"][0]["invocations"][0]
        assert inv["executionSuccessful"] is True
        assert "endTimeUtc" in inv

    def test_help_uri_for_referenced_rule(self):
        findings = [_f(references=["https://example.com/ref"])]
        doc = json.loads(render_sarif(findings))
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["helpUri"] == "https://example.com/ref"

    def test_output_is_valid_json(self):
        findings = [_f(), _f(rule_id="GHA-R001", sev=Severity.MEDIUM, file="wf.yml", line=3)]
        out = render_sarif(findings)
        json.loads(out)