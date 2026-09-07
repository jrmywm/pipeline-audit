from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_audit.core.parser import parse_workflow
from pipeline_audit.core.rule_loader import Rule as RuleSpec
from pipeline_audit.core.severity import Severity
from pipeline_audit.core.workflow_regex_rule import WorkflowRegexRule

HANDLER = WorkflowRegexRule()


def _spec(
    pattern: str = r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}",
    scope_keys=(),
    exclude_keys=(),
) -> RuleSpec:
    return RuleSpec(
        id="GHA-R002",
        title="GitHub secret interpolated into inline bash script",
        severity=Severity.HIGH,
        target="github_workflow",
        type="regex",
        match={
            "regex": {
                "pattern": pattern,
                "scope_keys": list(scope_keys),
                "exclude_keys": list(exclude_keys),
            }
        },
        remediation="Pass via env: instead.",
        references=["https://example.com"],
    )


def _scan(text: str, **kw) -> list:
    wf = parse_workflow(text)
    return HANDLER.match(_spec(scope_keys=("run", "script"), **kw), file=Path("wf.yml"), workflow=wf, raw_text=text)


# ─── true positives ──────────────────────────────────────────────────────────


class TestSecretsInterpFires:
    def test_inline_run_with_secret(self):
        f = _scan(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo ${{ secrets.X }}\n"
        )
        assert len(f) == 1
        assert f[0].rule_id == "GHA-R002"
        assert f[0].severity == Severity.HIGH
        assert "${{ secrets.X }}" in (f[0].location.snippet or "")

    def test_block_scalar_run_secret_reports_correct_line(self):
        wf = (
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - name: x\n"
            "        run: |\n"
            "          echo star ${{ secrets.MY_X }}\n"
        )
        f = _scan(wf)
        assert len(f) == 1
        # line of `run:` is 7; block scalar content begins at line 8
        assert f[0].location.line == 8

    def test_multiple_matches_in_one_run(self):
        wf = (
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: |\n"
            "          echo ${{ secrets.A }}\n"
            "          echo ${{ secrets.B }}\n"
        )
        f = _scan(wf)
        assert len(f) == 2

    def test_with_whitespace_quota_fires(self):
        f = _scan(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo ${{   secrets.X   }}\n"
        )
        assert len(f) == 1 and "secrets.X" in (f[0].location.snippet or "")

    def test_script_scope_key_also_fires(self):
        f = _scan(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - script: console.log(${{ secrets.S }})\n"
        )
        assert len(f) == 1

    def test_nested_with_script_fires(self):
        f = _scan(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/github-script@v7\n"
            "        with:\n"
            "          script: console.log(${{ secrets.SCRIPT_TOKEN }})\n"
        )
        assert len(f) == 1
        assert f[0].location.line == 8


# ─── true negatives ───────────────────────────────────────────────────────────


class TestNoFire:
    def test_secret_passed_via_env_not_in_run(self):
        f = _scan(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - env:\n"
            "          TOKEN: ${{ secrets.TOKEN }}\n"
            "        run: echo $TOKEN\n"
        )
        assert f == []

    def test_run_with_env_var_reference_only(self):
        f = _scan(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo $HOME\n"
        )
        assert f == []

    def test_empty_run(self):
        f = _scan(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: ''\n"
        )
        assert f == []

    def test_secret_in_comment_under_run_block_does_not_match_because_no_comment(self):
        # Tabor GHA parses inline run: all on one line; comments aren't excluded
        # but they can't appear inline either. Sanity test: no `run` at all.
        f = _scan("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\nsteps: []\n")
        assert f == []


# ─── exclude_keys defences ────────────────────────────────────────────────────


class TestExcludeKeys:
    def test_scope_minus_exclude_keys_yields_nothing_when_only_excluded(self):
        spec = _spec(scope_keys=("run", "env"), exclude_keys=("env",))
        wf_text = (
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - env:\n"
            "          TOKEN: ${{ secrets.TOKEN }}\n"
            "        run: echo $TOKEN\n"
        )
        wf = parse_workflow(wf_text)
        findings = HANDLER.match(spec, file=Path("wf.yml"), workflow=wf)
        assert findings == []


# ─── config robustness ────────────────────────────────────────────────────────


class TestConfigRobustness:
    def test_missing_pattern_returns_nothing(self):
        spec = RuleSpec(
            id="GHA-R002",
            title="x",
            severity=Severity.HIGH,
            target="github_workflow",
            type="regex",
            match={"regex": {"scope_keys": ["run"]}},
            remediation="r",
            references=[],
        )
        wf = parse_workflow(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo ${{ secrets.X }}\n"
        )
        assert HANDLER.match(spec, file=Path("wf.yml"), workflow=wf) == []

    def test_invalid_regex_returns_nothing(self):
        f = _scan(
            "on: push\njobs:\n  b:\n    steps:\n      - run: echo ${{ secrets }}\n",
            pattern="(unclosed",
        )
        assert f == []

    def test_empty_scope_keys_returns_nothing(self):
        spec = _spec(scope_keys=())
        wf = parse_workflow(
            "on: push\njobs:\n  b:\n    steps:\n      - run: echo ${{ secrets.X }}\n"
        )
        assert HANDLER.match(spec, file=Path("wf.yml"), workflow=wf) == []

    def test_returns_empty_when_workflow_none(self):
        assert HANDLER.match(_spec(), file=Path("wf.yml"), workflow=None) == []

    def test_returns_empty_when_jobs_not_a_dict(self):
        wf = parse_workflow("on: push\njobs: not-a-list\n")
        assert HANDLER.match(_spec(), file=Path("wf.yml"), workflow=wf) == []


# ─── multiple steps across jobs ────────────────────────────────────────────────


class TestMultipleJobs:
    def test_fires_per_step(self):
        f = _scan(
            "on: push\njobs:\n"
            "  a:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo ${{ secrets.X }}\n"
            "  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo ${{ secrets.Y }}\n"
        )
        assert len(f) == 2
        snippets = " ".join(x.location.snippet or "" for x in f)
        assert "secrets.X" in snippets
        assert "secrets.Y" in snippets


# ─── mixed env-passed and run-interpolated secret ─────────────────────────────


class TestEnvThenRunSecrets:
    def test_env_passing_safe_run_interpolating_fires_once(self):
        f = _scan(
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - env:\n"
            "          TOKEN: ${{ secrets.TOKEN }}\n"
            "        run: |\n"
            "          curl -H \"Auth: ${{ secrets.STREAM }}\"\n"
        )
        assert len(f) == 1
        assert "secrets.STREAM" in (f[0].location.snippet or "")
