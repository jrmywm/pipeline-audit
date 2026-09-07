from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_audit.core.parser import parse_workflow
from pipeline_audit.core.rule_loader import Rule as RuleSpec
from pipeline_audit.core.severity import Severity
from pipeline_audit.core.workflow_rule import WorkflowStructuralRule

SHA = "a" * 40


def _spec() -> RuleSpec:
    return RuleSpec(
        id="GHA-R001",
        title="Unpinned GitHub Action",
        severity=Severity.MEDIUM,
        target="github_workflow",
        type="structural",
        match={"structural": {"kind": "uses_unpinned", "sha_pattern": r"^[0-9a-f]{40}$"}},
        remediation="Pin to SHA",
        references=["https://example.com"],
    )


HANDLER = WorkflowStructuralRule()


def _scan(text: str) -> list:
    wf = parse_workflow(text)
    return HANDLER.match(_spec(), file=Path("wf.yml"), workflow=wf, raw_text=text)


# ─── unit cases ──────────────────────────────────────────────────────────────


class TestUsesUnpinned:
    def test_tag_fires(self):
        findings = _scan(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "GHA-R001"
        assert "actions/checkout@v4" in (findings[0].location.snippet or "")

    def test_branch_fires(self):
        findings = _scan(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@main\n"
        )
        assert len(findings) == 1

    def test_sha_pinned_no_finding(self):
        findings = _scan(
            f"on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            f"      - uses: actions/checkout@{SHA}\n"
        )
        assert findings == []

    def test_local_action_exempt(self):
        findings = _scan(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: ./local-action\n"
        )
        assert findings == []

    def test_docker_action_exempt(self):
        findings = _scan(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: docker://alpine:3.19\n"
        )
        assert findings == []

    def test_multiple_steps_mixed(self):
        findings = _scan(
            f"on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            f"      - uses: actions/checkout@{SHA}\n"
            f"      - uses: actions/setup-python@v5\n"
            f"      - uses: ./local\n"
        )
        # Only setup-python@v5 should fire
        assert len(findings) == 1
        assert "setup-python@v5" in (findings[0].location.snippet or "")

    def test_multiple_jobs(self):
        findings = _scan(
            "on: push\njobs:\n"
            "  a:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@main\n"
        )
        assert len(findings) == 2

    def test_line_number_reported(self):
        findings = _scan(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
        )
        assert findings[0].location.line is not None
        assert findings[0].location.line >= 1

    def test_empty_steps(self):
        findings = _scan("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n")
        assert findings == []

    def test_no_steps(self):
        findings = _scan("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n")
        assert findings == []

    def test_no_jobs(self):
        findings = _scan("on: push\n")
        assert findings == []

    def test_uses_without_at(self):
        findings = _scan(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: some-action\n"
        )
        assert len(findings) == 1

    def test_unpinned_reusable_workflow_fires(self):
        findings = _scan(
            "on: push\njobs:\n  deploy:\n"
            "    uses: owner/repo/.github/workflows/deploy.yml@main\n"
        )
        assert len(findings) == 1
        assert "deploy.yml@main" in (findings[0].location.snippet or "")

    def test_custom_sha_pattern(self):
        custom = RuleSpec(
            id="GHA-R001",
            title="x",
            severity=Severity.MEDIUM,
            target="github_workflow",
            type="structural",
            match={"structural": {"kind": "uses_unpinned", "sha_pattern": r"^v\d+\.\d+\.\d+$"}},
            remediation="r",
            references=[],
        )
        wf = parse_workflow(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v1.2.3\n"
            "      - uses: actions/checkout@v4\n"
        )
        findings = HANDLER.match(custom, file=Path("wf.yml"), workflow=wf, raw_text="")
        # v1.2.3 matches custom pattern -> no finding; v4 does not -> 1 finding
        assert len(findings) == 1
