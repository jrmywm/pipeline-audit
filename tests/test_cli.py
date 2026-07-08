from __future__ import annotations

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from pipeline_audit.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class TestScanGoodRepo:
    def test_exits_zero_when_clean(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "report.md"
        result = runner.invoke(
            main, ["scan", str(FIXTURES / "repo_good"), "--output", str(out)]
        )
        assert result.exit_code == 0, result.output

    def test_writes_markdown_file(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "report.md"
        runner.invoke(main, ["scan", str(FIXTURES / "repo_good"), "--output", str(out)])
        assert out.is_file()
        text = out.read_text(encoding="utf-8")
        assert "Pipeline Audit Report" in text

    def test_clean_report_says_no_findings(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "report.md"
        runner.invoke(main, ["scan", str(FIXTURES / "repo_good"), "--output", str(out)])
        text = out.read_text(encoding="utf-8")
        assert "No findings" in text


class TestScanBadRepo:
    def test_exits_zero_without_fail_on(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "report.md"
        result = runner.invoke(
            main, ["scan", str(FIXTURES / "repo_bad"), "--output", str(out)]
        )
        # Without --fail-on, exit 0 even with findings
        assert result.exit_code == 0, result.output

    def test_report_contains_findings(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "report.md"
        runner.invoke(main, ["scan", str(FIXTURES / "repo_bad"), "--output", str(out)])
        text = out.read_text(encoding="utf-8")
        assert "DOCKER-R001" in text
        assert "GHA-R001" in text
        assert "## Findings by File" in text
        assert "## Details" in text

    def test_fail_on_high_exits_nonzero(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "report.md"
        result = runner.invoke(
            main,
            ["scan", str(FIXTURES / "repo_bad"), "--output", str(out), "--fail-on", "High"],
        )
        assert result.exit_code == 1

    def test_fail_on_medium_exits_nonzero(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "report.md"
        result = runner.invoke(
            main,
            ["scan", str(FIXTURES / "repo_bad"), "--output", str(out), "--fail-on", "Medium"],
        )
        assert result.exit_code == 1


class TestFailOnCleanRepo:
    def test_fail_on_critical_clean_exits_zero(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "report.md"
        result = runner.invoke(
            main,
            ["scan", str(FIXTURES / "repo_good"), "--output", str(out), "--fail-on", "Critical"],
        )
        assert result.exit_code == 0


class TestNonexistentPath:
    def test_nonexistent_path_errors(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(tmp_path / "nope")])
        # Click rejects nonexistent path argument
        assert result.exit_code != 0


class TestFormatFlag:
    def test_md_format_default(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "default.md"
        result = runner.invoke(
            main, ["scan", str(FIXTURES / "repo_good"), "--output", str(out)]
        )
        assert result.exit_code == 0
        assert out.is_file()

    def test_json_format_writes_file(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "report.md"
        result = runner.invoke(
            main,
            ["scan", str(FIXTURES / "repo_bad"), "--format", "json", "--output", str(out)],
        )
        assert result.exit_code == 0
        json_path = tmp_path / "report.json"
        assert json_path.is_file()

    def test_sarif_format_writes_file(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "report.md"
        result = runner.invoke(
            main,
            ["scan", str(FIXTURES / "repo_bad"), "--format", "sarif", "--output", str(out)],
        )
        assert result.exit_code == 0
        sarif_path = tmp_path / "report.sarif"
        assert sarif_path.is_file()

    def test_multi_format_writes_all_files(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "scan.md"
        result = runner.invoke(
            main,
            ["scan", str(FIXTURES / "repo_bad"),
             "--format", "md", "--format", "json", "--format", "sarif",
             "--output", str(out)],
        )
        assert result.exit_code == 0
        assert (tmp_path / "scan.md").is_file()
        assert (tmp_path / "scan.json").is_file()
        assert (tmp_path / "scan.sarif").is_file()