from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from pipeline_audit.core.exceptions import RulesetSyntaxError, RulesetValidationError
from pipeline_audit.core.rule_loader import load_merged_ruleset, load_ruleset
from pipeline_audit.core.severity import Severity


# ─── bundled default ruleset ────────────────────────────────────────────────


class TestBundledRuleset:
    def test_loads_without_error(self):
        rules = load_ruleset()
        assert len(rules) == 4

    def test_rule_ids(self):
        rules = {r.id: r for r in load_ruleset()}
        assert set(rules.keys()) == {"DOCKER-R001", "DOCKER-R002", "GHA-R001", "GHA-R002"}

    def test_docker_r001_fields(self):
        rules = {r.id: r for r in load_ruleset()}
        r = rules["DOCKER-R001"]
        assert r.severity == Severity.HIGH
        assert r.target == "dockerfile"
        assert r.type == "structural"
        assert r.match["structural"]["kind"] == "missing_instruction"
        assert r.match["structural"]["instruction"] == "USER"
        assert "USER" in r.remediation

    def test_docker_r002_fields(self):
        rules = {r.id: r for r in load_ruleset()}
        r = rules["DOCKER-R002"]
        assert r.severity == Severity.CRITICAL
        assert r.type == "regex"
        assert r.match["regex"]["min_entropy"] == 0.0

    def test_gha_r001_fields(self):
        rules = {r.id: r for r in load_ruleset()}
        r = rules["GHA-R001"]
        assert r.severity == Severity.MEDIUM
        assert r.target == "github_workflow"
        assert r.match["structural"]["kind"] == "uses_unpinned"

    def test_gha_r002_fields(self):
        rules = {r.id: r for r in load_ruleset()}
        r = rules["GHA-R002"]
        assert r.severity == Severity.HIGH
        assert r.match["regex"]["scope_keys"] == ["run", "script"]

    def test_all_enabled_by_default(self):
        for r in load_ruleset():
            assert r.enabled is True

    def test_references_populated(self):
        rules = {r.id: r for r in load_ruleset()}
        for rid in ("DOCKER-R001", "GHA-R001"):
            assert len(rules[rid].references) >= 1


# ─── malformed YAML ──────────────────────────────────────────────────────────


class TestMalformedRuleset:
    def test_missing_file_raises_syntax_error(self, tmp_path):
        with pytest.raises(RulesetSyntaxError, match="not found"):
            load_ruleset(tmp_path / "nonexistent.yaml")

    def test_empty_file_raises_syntax_error(self, tmp_path):
        p = tmp_path / "empty.yaml"
        p.write_text("", encoding="utf-8")
        with pytest.raises(RulesetSyntaxError, match="mapping"):
            load_ruleset(p)

    def test_list_root_raises_syntax_error(self, tmp_path):
        p = tmp_path / "list.yaml"
        p.write_text("- item\n- item2\n", encoding="utf-8")
        with pytest.raises(RulesetSyntaxError, match="mapping"):
            load_ruleset(p)

    def test_missing_required_field_raises_validation_error(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text(
            textwrap.dedent("""\
            version: "1.0"
            rules:
              - id: DOCKER-R001
                title: Missing
                severity: High
                target: dockerfile
                type: structural
                # 'match' and 'remediation' missing
            """),
            encoding="utf-8",
        )
        with pytest.raises(RulesetValidationError, match="schema validation failed"):
            load_ruleset(p)

    def test_bad_severity_raises_validation_error(self, tmp_path):
        p = tmp_path / "bad_sev.yaml"
        p.write_text(
            textwrap.dedent("""\
            version: "1.0"
            rules:
              - id: DOCKER-R001
                title: Test
                severity: Extreme
                target: dockerfile
                type: structural
                match: {}
                remediation: fix it
            """),
            encoding="utf-8",
        )
        with pytest.raises(RulesetValidationError, match="schema validation failed"):
            load_ruleset(p)

    def test_bad_rule_id_raises_validation_error(self, tmp_path):
        p = tmp_path / "bad_id.yaml"
        p.write_text(
            textwrap.dedent("""\
            version: "1.0"
            rules:
              - id: FOO-001
                title: Test
                severity: High
                target: dockerfile
                type: structural
                match: {}
                remediation: fix it
            """),
            encoding="utf-8",
        )
        with pytest.raises(RulesetValidationError, match="schema validation failed"):
            load_ruleset(p)

    @pytest.mark.parametrize(
        ("target", "regex_config", "message"),
        [
            ("github_workflow", "scope_keys: run", "scope_keys"),
            ("github_workflow", "scope_keys: [run]\nexclude_keys: env", "exclude_keys"),
            ("dockerfile", "exclude_names: API_KEY", "exclude_names"),
            ("dockerfile", "min_entropy: .inf", "min_entropy"),
            ("dockerfile", "min_entropy: -1", "min_entropy"),
        ],
    )
    def test_invalid_regex_option_types_raise(
        self, tmp_path, target, regex_config, message
    ):
        p = tmp_path / "bad_regex_options.yaml"
        indented_config = regex_config.replace("\n", "\n                    ")
        p.write_text(
            textwrap.dedent(f"""\
            version: "1.0"
            rules:
              - id: {"GHA-R099" if target == "github_workflow" else "DOCKER-R099"}
                title: Test
                severity: High
                target: {target}
                type: regex
                match:
                  regex:
                    pattern: "(secret)"
                    {indented_config}
                remediation: fix it
            """),
            encoding="utf-8",
        )
        with pytest.raises(RulesetValidationError, match=message):
            load_ruleset(p)


# ─── merge behaviour ──────────────────────────────────────────────────────────


class TestMergedRuleset:
    def test_no_user_path_returns_default(self):
        rules = load_merged_ruleset(None)
        assert len(rules) == 4

    def test_user_overrides_default_by_id(self, tmp_path):
        p = tmp_path / "custom.yaml"
        p.write_text(
            textwrap.dedent("""\
            version: "1.0"
            rules:
              - id: DOCKER-R001
                title: Custom override
                severity: Critical
                target: dockerfile
                type: structural
                match:
                  structural:
                    kind: missing_instruction
                    instruction: USER
                remediation: Override it
            """),
            encoding="utf-8",
        )
        rules = {r.id: r for r in load_merged_ruleset(p)}
        assert len(rules) == 4
        r = rules["DOCKER-R001"]
        assert r.severity == Severity.CRITICAL
        assert r.title == "Custom override"

    def test_user_adds_new_rule(self, tmp_path):
        p = tmp_path / "extra.yaml"
        p.write_text(
            textwrap.dedent("""\
            version: "1.0"
            rules:
              - id: DOCKER-R099
                title: Extra rule
                severity: Low
                target: dockerfile
                type: structural
                match:
                  structural:
                    kind: missing_instruction
                    instruction: HEALTHCHECK
                remediation: fix it
            """),
            encoding="utf-8",
        )
        rules = {r.id: r for r in load_merged_ruleset(p)}
        assert "DOCKER-R099" in rules
        assert len(rules) == 5
