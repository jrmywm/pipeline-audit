from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_audit.core.location import Location
from pipeline_audit.core.reporter import render_markdown
from pipeline_audit.core.rule_base import Finding
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


class TestEmptyReport:
    def test_no_findings_says_clean(self):
        md = render_markdown([])
        assert "Pipeline Audit Report" in md
        assert "No findings" in md
        assert "appear clean" in md

    def test_total_is_zero(self):
        md = render_markdown([])
        assert "**0**" in md


class TestSingleFinding:
    def test_summary_count(self):
        md = render_markdown([_f()])
        assert "High" in md
        # Count column should show 1 for High
        assert "| 1 |" in md

    def test_finding_section_by_file(self):
        md = render_markdown([_f(file="Dockerfile")])
        assert "`Dockerfile`" in md
        assert "`DOCKER-R001`" in md

    def test_remediation_in_details(self):
        md = render_markdown([_f(remediation="Add USER 1001.")])
        assert "Add USER 1001." in md

    def test_reference_links_rendered(self):
        md = render_markdown([_f(references=["https://example.com/foo"])])
        assert "<https://example.com/foo>" in md

    def test_severity_emoji_present(self):
        md = render_markdown([_f(sev=Severity.CRITICAL)])
        assert ":red_circle:" in md


class TestMultipleFindings:
    def test_grouped_by_file(self):
        findings = [
            _f(rule_id="DOCKER-R001", sev=Severity.HIGH, file="Dockerfile", line=1),
            _f(rule_id="DOCKER-R002", sev=Severity.CRITICAL, file="Dockerfile", line=5),
            _f(rule_id="GHA-R001", sev=Severity.MEDIUM, file=".github/workflows/ci.yml", line=10),
        ]
        md = render_markdown(findings)
        # Both file groupings appear
        assert "`Dockerfile`" in md
        assert "`.github/workflows/ci.yml`" in md

    def test_severity_counts_aggregated(self):
        findings = [
            _f(sev=Severity.HIGH, file="Dockerfile"),
            _f(sev=Severity.HIGH, file="Dockerfile", line=2),
            _f(sev=Severity.MEDIUM, file="wf.yml"),
        ]
        md = render_markdown(findings)
        # Two High, one Medium
        assert "| 2 |" in md
        assert "| 1 |" in md

    def test_details_section_has_all_rules(self):
        findings = [
            _f(rule_id="DOCKER-R001", file="a/Dockerfile"),
            _f(rule_id="GHA-R001", sev=Severity.MEDIUM, file="b/wf.yml", line=3),
        ]
        md = render_markdown(findings)
        assert "DOCKER-R001" in md
        assert "GHA-R001" in md
        assert "## Details" in md


class TestRelativePaths:
    def test_relative_to_root(self, tmp_path):
        f = _f(file=str(tmp_path / "Dockerfile"))
        md = render_markdown([f], root=tmp_path)
        assert "`Dockerfile`" in md
        assert str(tmp_path) not in md

    def test_no_root_shows_full_path(self):
        f = _f(file="/some/abs/Dockerfile")
        md = render_markdown([f], root=None)
        assert "/some/abs/Dockerfile" in md

    def test_outside_root_shows_full_path(self, tmp_path):
        other = tmp_path.parent / "outside-Dockerfile"
        f = _f(file=str(other))
        md = render_markdown([f], root=tmp_path)
        # Should fall back to full path since it's not under root
        # (posix-normalized for cross-platform consistency)
        assert other.as_posix() in md