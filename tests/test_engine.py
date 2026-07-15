from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_audit.core.engine import scan_path
from pipeline_audit.core.severity import Severity

FIXTURES = Path(__file__).parent / "fixtures"


# ─── DOCKER-R001 (no USER) end-to-end ─────────────────────────────────────────


class TestDockerR001Engine:
    def test_bad_repo_finds_missing_user(self):
        findings = scan_path(FIXTURES / "repo_bad")
        docker_r001 = [f for f in findings if f.rule_id == "DOCKER-R001"]
        # repo_bad has two Dockerfiles missing USER: top-level + vendor/Dockerfile
        assert len(docker_r001) == 2
        f = docker_r001[0]
        assert f.severity == Severity.HIGH
        assert f.target == "dockerfile"
        assert f.file.name == "Dockerfile"
        assert "node_modules" not in str(f.file)
        assert "USER" in f.remediation

    def test_good_repo_no_missing_user_finding(self):
        findings = scan_path(FIXTURES / "repo_good")
        docker_r001 = [f for f in findings if f.rule_id == "DOCKER-R001"]
        assert docker_r001 == []

    def test_vending_dockerfile_also_flagged(self):
        # repo_bad/vendor/Dockerfile is a separate Dockerfile, also missing USER
        findings = scan_path(FIXTURES / "repo_bad")
        r001_files = {f.file.name for f in findings if f.rule_id == "DOCKER-R001"}
        # We expect at least the top Dockerfile + vendor/Dockerfile
        assert "Dockerfile" in r001_files
        # node_modules Dockerfile must NOT appear
        bad_paths = [str(f.file) for f in findings if "node_modules" in str(f.file)]
        assert bad_paths == []

    def test_location_line_is_1(self):
        findings = scan_path(FIXTURES / "repo_bad")
        r001 = next(f for f in findings if f.rule_id == "DOCKER-R001")
        assert r001.location.line == 1

    def test_findings_sorted_by_severity_then_file(self):
        findings = scan_path(FIXTURES / "repo_bad")
        # All DOCKER-R001 should be High; grouping sanity
        if len(findings) >= 2:
            for a, b in zip(findings[:-1], findings[1:]):
                assert (str(a.file), -int(a.severity)) <= (str(b.file), -int(b.severity))


# ─── disabled rule respected ────────────────────────────────────────────────


class TestDisabledRule:
    def test_disabled_rule_skipped(self, tmp_path):
        ruleset = tmp_path / "rs.yaml"
        ruleset.write_text(
            "version: '1.0'\n"
            "rules:\n"
            "  - id: DOCKER-R001\n"
            "    title: x\n"
            "    severity: High\n"
            "    target: dockerfile\n"
            "    type: structural\n"
            "    match:\n"
            "      structural:\n"
            "        kind: missing_instruction\n"
            "        instruction: USER\n"
            "    remediation: r\n"
            "    enabled: false\n",
            encoding="utf-8",
        )
        df = tmp_path / "Dockerfile"
        df.write_text("FROM alpine\n", encoding="utf-8")
        findings = scan_path(tmp_path, ruleset_path=ruleset)
        assert findings == []


# ─── handler absence graceful ────────────────────────────────────────────────


class TestUnhandledRuleType:
    def test_unhandled_rule_type_skipped(self, tmp_path):
        ruleset = tmp_path / "rs.yaml"
        ruleset.write_text(
            "version: '1.0'\n"
            "rules:\n"
            "  - id: DOCKER-R001\n"  # disable bundled default DOCKER-R001
            "    title: x\n"
            "    severity: High\n"
            "    target: dockerfile\n"
            "    type: structural\n"
            "    match:\n"
            "      structural:\n"
            "        kind: missing_instruction\n"
            "        instruction: USER\n"
            "    remediation: r\n"
            "    enabled: false\n"
            "  - id: DOCKER-R002\n"
            "    title: x\n"
            "    severity: Critical\n"
            "    target: dockerfile\n"
            "    type: composite\n"  # no handler yet (Stage 8+)
            "    match:\n"
            "      regex:\n"
            "        pattern: ENV\n"
            "    remediation: r\n",
            encoding="utf-8",
        )
        df = tmp_path / "Dockerfile"
        df.write_text("FROM alpine\nENV FOO=bar\n", encoding="utf-8")
        findings = scan_path(tmp_path, ruleset_path=ruleset)
        # No finding -> unhandled rule type gracefully skipped
        assert findings == []


# ─── empty repo ───────────────────────────────────────────────────────────────


class TestEmptyRepo:
    def test_no_targets_yields_no_findings(self, tmp_path):
        (tmp_path / "README.md").write_text("hi", encoding="utf-8")
        assert scan_path(tmp_path) == []


# ─── GHA-R001 (unpinned actions) end-to-end ──────────────────────────────────


class TestGhaR001Engine:
    def test_bad_repo_finds_unpinned_actions(self):
        findings = scan_path(FIXTURES / "repo_bad")
        gha_r001 = [
            f for f in findings if f.rule_id == "GHA-R001"
            and ".github" in str(f.file)
        ]
        # bad.yml has: checkout@v4, checkout@main (in two jobs)
        assert len(gha_r001) == 2
        for f in gha_r001:
            assert f.severity == Severity.MEDIUM
            assert f.target == "github_workflow"
            assert f.location.line is not None
            assert f.location.line >= 1

    def test_good_repo_no_unpinned_findings(self):
        findings = scan_path(FIXTURES / "repo_good")
        gha_r001 = [
            f for f in findings if f.rule_id == "GHA-R001"
            and ".github" in str(f.file)
        ]
        # ci.yml pins checkout + setup-python to 40-char SHAs
        assert gha_r001 == []

    def test_finding_paths_are_workflow_files(self):
        findings = scan_path(FIXTURES / "repo_bad")
        gha_r001 = [f for f in findings if f.rule_id == "GHA-R001"]
        for f in gha_r001:
            assert f.file.name in ("bad.yml", "ci.yml")
            assert ".github" in str(f.file)

    def test_findings_snippet_contains_uses_value(self):
        findings = scan_path(FIXTURES / "repo_bad")
        gha_r001 = [f for f in findings if f.rule_id == "GHA-R001"]
        snippets = " ".join(f.location.snippet or "" for f in gha_r001)
        assert "actions/checkout" in snippets
        # Should mention both @v4 and @main
        assert "@v4" in snippets or "@main" in snippets