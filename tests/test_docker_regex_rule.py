from __future__ import annotations

import math
from pathlib import Path

import pytest

from pipeline_audit.core.docker_regex_rule import DockerRegexRule
from pipeline_audit.core.parser import parse_dockerfile
from pipeline_audit.core.rule_loader import Rule as RuleSpec
from pipeline_audit.core.severity import Severity

HANDLER = DockerRegexRule()


def _spec(
    pattern: str = r"(?i)\b(?:ENV|ARG)\s+\S*(?:TOKEN|KEY|PASSWORD|SECRET|PASSWD|PWD|API_KEY|CREDENTIAL)[=\s]+(\S+)",
    exclude_names=(),
    min_entropy: float = 3.5,
    capture_group: int = 1,
) -> RuleSpec:
    return RuleSpec(
        id="DOCKER-R002",
        title="Hardcoded secret in ENV or ARG",
        severity=Severity.CRITICAL,
        target="dockerfile",
        type="regex",
        match={
            "regex": {
                "pattern": pattern,
                "exclude_names": list(exclude_names),
                "min_entropy": min_entropy,
                "capture_group": capture_group,
            }
        },
        remediation="Don't bake secrets in.",
        references=["https://example.com"],
    )


def _scan(text: str, **kw) -> list:
    df = parse_dockerfile(text)
    return HANDLER.match(_spec(**kw), file=Path("Dockerfile"), dockerfile=df, raw_text=text)


# ─── true positives ──────────────────────────────────────────────────────────


class TestSecretInEnvFires:
    def test_high_entropy_env_fires(self):
        secret = "ak_live_8a9b3c7d2e1f4a6b5c8d9e2f1a"
        f = _scan(f"FROM alpine\nENV API_KEY={secret}\n")
        assert len(f) == 1
        assert f[0].rule_id == "DOCKER-R002"
        assert f[0].severity == Severity.CRITICAL
        assert f[0].line == 2
        assert "API_KEY" in (f[0].location.snippet or "")
        assert secret not in (f[0].location.snippet or "")
        assert "<redacted>" in (f[0].location.snippet or "")

    def test_arg_secret_fires(self):
        f = _scan("FROM alpine\nARG GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVw012345\n")
        assert len(f) == 1
        assert "GITHUB_TOKEN" in (f[0].location.snippet or "")

    def test_secret_keyword_substring_in_name_fires(self):
        f = _scan("FROM alpine\nENV SECRETAPI_KEY=qW7vBn4KpR2Lm9SzTqFy6XcJ3MqNePZ\n")
        assert len(f) == 1

    def test_lowercase_keyword_fires(self):
        f = _scan("FROM alpine\nENV password=hDx8Vn4KpR2Lm9SzTqFy6XcJ3MqNePZ\n")
        assert len(f) == 1

    def test_quoted_secret_produces_one_finding(self):
        f = _scan(
            'FROM alpine\nENV API_KEY="super-secret-value"\n',
            min_entropy=0.0,
        )
        assert len(f) == 1

    def test_quoted_secret_with_spaces_produces_one_finding(self):
        f = _scan(
            'FROM alpine\nENV API_KEY="super secret value"\n',
            min_entropy=0.0,
        )
        assert len(f) == 1

    def test_parameter_expansion_with_literal_fallback_fires(self):
        f = _scan(
            "FROM alpine\nENV API_KEY=${OTHER_KEY:-hardcoded-secret}\n",
            min_entropy=0.0,
        )
        assert len(f) == 1


# ─── true negatives ───────────────────────────────────────────────────────────


class TestNoSecretFires:
    def test_allowlisted_name_skipped(self):
        assert _scan("FROM alpine\nENV NODE_ENV=production\nUSER 1001\n") == []

    def test_short_value_below_entropy_threshold(self):
        assert _scan("FROM alpine\nENV API_KEY=abc\n") == []

    def test_no_secret_keyword_in_name(self):
        assert _scan("FROM alpine\nENV APP_VERSION=1.2.3\nUSER 1001\n") == []

    def test_substitution_placeholder_low_entropy(self):
        assert _scan("FROM alpine\nENV API_KEY={{EV_VAR}}\nUSER 1001\n") == []

    @pytest.mark.parametrize("value", ["$API_KEY", "${API_KEY}", "{{API_KEY}}"])
    def test_pure_runtime_reference_is_skipped(self, value):
        assert _scan(
            f"FROM alpine\nENV API_KEY={value}\nUSER 1001\n",
            min_entropy=0.0,
        ) == []

    def test_non_env_arg_instruction_skipped(self):
        assert _scan("FROM alpine\nRUN echo abc\nUSER 1001\n") == []


# ─── entropy threshold tunable ────────────────────────────────────────────────


class TestEntropyThreshold:
    def test_min_entropy_zero_fires_short_values(self):
        f = _scan("FROM alpine\nENV API_KEY=ab\n", min_entropy=0.0)
        assert len(f) == 1

    def test_min_entropy_six_blocks_low_entropy_secrets(self):
        f = _scan("FROM alpine\nENV API_KEY=ab\n", min_entropy=6.0)
        assert f == []


# ─── capture group selection ─────────────────────────────────────────────────


class TestCaptureGroup:
    def test_capture_group_invalid_index_silently_skipped(self):
        # `capture_group: 2` is out of range for the single-group pattern
        assert _scan("FROM alpine\nENV API_KEY=abcdef\n", capture_group=2) == []


# ─── config robustness ────────────────────────────────────────────────────────


class TestConfigRobustness:
    def test_missing_pattern_returns_nothing(self):
        spec = RuleSpec(
            id="DOCKER-R002",
            title="x",
            severity=Severity.CRITICAL,
            target="dockerfile",
            type="regex",
            match={"regex": {}},
            remediation="r",
            references=[],
        )
        df = parse_dockerfile("FROM alpine\nENV TOKEN=abcdef0123\n")
        assert HANDLER.match(spec, file=Path("Dockerfile"), dockerfile=df) == []

    def test_invalid_regex_pattern_returns_nothing(self):
        f = _scan("FROM alpine\nENV TOKEN=abcdef\n", pattern="(?:[unterminated")
        assert f == []

    def test_returns_empty_on_non_dockerfile(self):
        assert HANDLER.match(_spec(), file=Path("wf.yml"), dockerfile=None) == []


# ─── multiple secrets in same instruction ────────────────────────────────────


class TestMultipleSecretsPerInstruction:
    def test_two_separate_env_instructions_each_fire(self):
        text = (
            "FROM alpine\n"
            "ENV API_TOKEN=hDx8Vn4KpR2Lm9SzTqFy6XcJ3MqNePZ\n"
            "ENV API_KEY=ak_live_8a9b3c7d2e1f4a6b5c8d9e2f1a\n"
            "USER 1001\n"
        )
        f = _scan(text)
        assert len(f) == 2
        snippets = " ".join(x.location.snippet or "" for x in f)
        assert "API_TOKEN" in snippets
        assert "API_KEY" in snippets

    def test_extra_pair_with_allowlisted_name_still_finds_secret_pair(self):
        text = (
            "FROM alpine\n"
            "ENV NODE_ENV=production API_TOKEN=hDx8Vn4KpR2Lm9SzTqFy6XcJ3MqNePZ\n"
            "USER 1001\n"
        )
        findings = _scan(text)
        assert len(findings) == 1
        assert "API_TOKEN=<redacted>" in (findings[0].location.snippet or "")
