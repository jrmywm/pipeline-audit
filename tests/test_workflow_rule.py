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


def _permissions_spec() -> RuleSpec:
    return RuleSpec(
        id="GHA-R003",
        title="Workflow grants write-all permissions",
        severity=Severity.HIGH,
        target="github_workflow",
        type="structural",
        match={"structural": {"kind": "permissions_write_all"}},
        remediation="Use least-privilege permissions",
        references=["https://docs.github.com/actions/using-workflows/workflow-syntax-for-github-actions#permissions"],
    )


HANDLER = WorkflowStructuralRule()


def _scan(text: str) -> list:
    wf = parse_workflow(text)
    return HANDLER.match(_spec(), file=Path("wf.yml"), workflow=wf, raw_text=text)


def _scan_permissions(text: str) -> list:
    wf = parse_workflow(text)
    return HANDLER.match(_permissions_spec(), file=Path("wf.yml"), workflow=wf, raw_text=text)


def _scan_privileged_checkout(text: str) -> list:
    spec = RuleSpec(
        id="GHA-R005",
        title="Untrusted pull request code executes in a privileged workflow",
        severity=Severity.CRITICAL,
        target="github_workflow",
        type="structural",
        match={"structural": {"kind": "privileged_pr_checkout_execution"}},
        remediation="Avoid executing untrusted pull request code in a privileged workflow",
        references=["https://docs.github.com/actions"],
    )
    wf = parse_workflow(text)
    return HANDLER.match(spec, file=Path("wf.yml"), workflow=wf, raw_text=text)


def _scan_workflow_run_artifact(text: str) -> list:
    spec = RuleSpec(
        id="GHA-R006",
        title="Workflow run artifact is executed",
        severity=Severity.HIGH,
        target="github_workflow",
        type="structural",
        match={"structural": {"kind": "workflow_run_artifact_execution"}},
        remediation="Treat downloaded workflow artifacts as untrusted data",
        references=["https://docs.github.com/actions"],
    )
    wf = parse_workflow(text)
    return HANDLER.match(spec, file=Path("wf.yml"), workflow=wf, raw_text=text)


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


class TestPermissionsWriteAll:
    def test_workflow_level_scalar_fires_case_insensitively(self):
        findings = _scan_permissions("permissions: WRITE-All\non: push\njobs: {}\n")
        assert len(findings) == 1
        assert findings[0].rule_id == "GHA-R003"
        assert findings[0].location.line == 1


class TestPrivilegedPrCheckoutExecution:
    @pytest.mark.parametrize(
        "trigger",
        [
            "pull_request_target",
            "[push, pull_request_target]",
            "{pull_request_target: {types: [opened]}}",
        ],
    )
    def test_trigger_forms_detect_head_checkout_followed_by_run(self, trigger):
        text = (
            f"on: {trigger}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: Actions/Checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: make test\n"
        )
        findings = _scan_privileged_checkout(text)
        assert len(findings) == 1
        assert findings[0].location.line == 8
        assert findings[0].location.snippet == "with.ref: ${{ github.event.pull_request.head.sha }}"

    @pytest.mark.parametrize(
        ("field", "value", "expected_line"),
        [
            ("ref", "${{ github.event.pull_request.head.ref }}", 8),
            ("repository", "${{ github.event.pull_request.head.repo.full_name }}", 8),
            ("ref", "refs/pull/${{ github.event.pull_request.number }}/merge", 8),
        ],
    )
    def test_other_untrusted_checkout_inputs_point_to_input_line(self, field, value, expected_line):
        text = (
            "on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n"
            "      - uses: actions/checkout@main\n"
            "        with:\n"
            f"          {field}: {value}\n"
            "      - run: ./test.sh\n"
        )
        findings = _scan_privileged_checkout(text)
        assert len(findings) == 1
        assert findings[0].location.line == expected_line
        assert "${{ github.event.pull_request" in findings[0].location.snippet

    @pytest.mark.parametrize(
        "text",
        [
            "on: pull_request\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: make test\n",
            "on: pull_request_target\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: main\n      - run: make test\n",
            "on: pull_request_target\njobs:\n  b:\n    steps:\n      - run: make test\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
            "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n  b:\n    steps:\n      - run: make test\n",
            "on: pull_request_target\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
        ],
    )
    def test_safe_or_nonexecuting_patterns_do_not_fire(self, text):
        assert _scan_privileged_checkout(text) == []

    def test_later_local_action_is_execution_sink(self):
        findings = _scan_privileged_checkout(
            "on: pull_request_target\njobs:\n  b:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - uses: ./ci/run-tests\n"
        )
        assert len(findings) == 1

    def test_job_level_scalar_fires(self):
        findings = _scan_permissions(
            "on: push\njobs:\n  deploy:\n    permissions: write-all\n    runs-on: ubuntu-latest\n"
        )
        assert len(findings) == 1
        assert findings[0].location.line == 4

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

    def test_multiple_explicit_declarations_reported(self):
        findings = _scan_permissions(
            "permissions: write-all\njobs:\n  deploy:\n    permissions: write-all\n"
        )
        assert len(findings) == 2

    @pytest.mark.parametrize(
        "text",
        [
            "permissions: read-all\njobs: {}\n",
            "permissions:\n  contents: write\njobs: {}\n",
            "on: push\njobs:\n  build:\n    permissions:\n      contents: write\n",
            "on: push\njobs:\n  build:\n    env:\n      permissions: write-all\n",
            "on: push\njobs:\n  build:\n    steps:\n      - run: echo 'permissions: write-all'\n",
        ],
    )
    def test_non_scalar_or_non_permissions_locations_do_not_fire(self, text):
        assert _scan_permissions(text) == []

    def test_job_override_does_not_create_inferred_finding(self):
        findings = _scan_permissions(
            "permissions: write-all\njobs:\n  safe:\n    permissions:\n      contents: read\n"
        )
        assert len(findings) == 1
        assert findings[0].location.line == 1


class TestWorkflowRunArtifactExecution:
    @pytest.mark.parametrize(
        "trigger",
        [
            "workflow_run",
            "[push, workflow_run]",
            "{workflow_run: {workflows: [CI], types: [completed]}}",
        ],
    )
    def test_trigger_forms_and_direct_execution(self, trigger):
        text = (
            f"on: {trigger}\njobs:\n  build:\n    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "        with:\n"
            "          run-id: ${{ github.event.workflow_run.id }}\n"
            "          github-token: ${{ secrets.GITHUB_TOKEN }}\n"
            "          path: output/artifact\n"
            "      - run: python3 output/artifact/check.py\n"
        )
        findings = _scan_workflow_run_artifact(text)
        assert len(findings) == 1
        assert findings[0].location.line == 10
        assert findings[0].location.snippet == "run: executes a file from the downloaded artifact"

    @pytest.mark.parametrize(
        ("path", "command"),
        [
            ("artifact", "bash ./artifact/run.sh"),
            ("./artifact", "./artifact/run.sh"),
            ("output/artifact", "source output/artifact/setup.sh"),
            ("artifact", ". artifact/env.sh"),
            ("artifact", "node artifact/runner.js"),
        ],
    )
    def test_supported_download_and_execution_forms(self, path, command):
        text = (
            "on: workflow_run\njobs:\n  b:\n    steps:\n"
            "      - uses: actions/download-artifact@main\n"
            "        with:\n"
            "          run-id: ${{  GITHUB.EVENT.WORKFLOW_RUN.ID  }}\n"
            "          github-token: ${{ secrets.GITHUB_TOKEN }}\n"
            f"          path: {path}\n"
            f"      - run: {command}\n"
        )
        assert len(_scan_workflow_run_artifact(text)) == 1

    @pytest.mark.parametrize(
        "text",
        [
            # Missing explicit run-id means current-run download.
            "on: workflow_run\njobs:\n  b:\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          path: artifact\n      - run: bash artifact/run.sh\n",
            # No direct execution: artifact is only read/copied.
            "on: workflow_run\njobs:\n  b:\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          run-id: ${{ github.event.workflow_run.id }}\n          github-token: ${{ secrets.GITHUB_TOKEN }}\n          path: artifact\n      - run: cat artifact/readme.txt\n",
            # Different jobs do not establish the relationship.
            "on: workflow_run\njobs:\n  a:\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          run-id: ${{ github.event.workflow_run.id }}\n          github-token: ${{ secrets.GITHUB_TOKEN }}\n          path: artifact\n  b:\n    steps:\n      - run: bash artifact/run.sh\n",
            # Execution before the download.
            "on: workflow_run\njobs:\n  b:\n    steps:\n      - run: bash artifact/run.sh\n      - uses: actions/download-artifact@v4\n        with:\n          run-id: ${{ github.event.workflow_run.id }}\n          github-token: ${{ secrets.GITHUB_TOKEN }}\n          path: artifact\n",
            # Traversal path is not accepted.
            "on: workflow_run\njobs:\n  b:\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          run-id: ${{ github.event.workflow_run.id }}\n          github-token: ${{ secrets.GITHUB_TOKEN }}\n          path: ../artifact\n      - run: bash ../artifact/run.sh\n",
            # Another trigger alone is insufficient.
            "on: push\njobs:\n  b:\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          run-id: ${{ github.event.workflow_run.id }}\n          github-token: ${{ secrets.GITHUB_TOKEN }}\n          path: artifact\n      - run: bash artifact/run.sh\n",
            # Cross-run download without a token is not configured.
            "on: workflow_run\njobs:\n  b:\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          run-id: ${{ github.event.workflow_run.id }}\n          path: artifact\n      - run: bash artifact/run.sh\n",
        ],
    )
    def test_nonmatching_patterns_do_not_fire(self, text):
        assert _scan_workflow_run_artifact(text) == []

    def test_multiple_executions_report_once_per_sink_step(self):
        findings = _scan_workflow_run_artifact(
            "on: workflow_run\njobs:\n  b:\n    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "        with:\n"
            "          run-id: ${{ github.event.workflow_run.id }}\n"
            "          github-token: ${{ secrets.GITHUB_TOKEN }}\n"
            "          path: artifact\n"
            "      - run: |\n"
            "          bash artifact/a.sh\n"
            "          python artifact/b.py\n"
            "      - run: node artifact/c.js\n"
        )
        assert len(findings) == 2
        assert findings[0].location.line == 10
        assert findings[1].location.line == 13
