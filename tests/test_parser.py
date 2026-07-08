from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_audit.core.parser import (
    ParsedWorkflow,
    parse_dockerfile,
    parse_workflow,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ─── Dockerfile parsing ────────────────────────────────────────────────────


class TestDockerfileParser:
    @pytest.fixture
    def good(self):
        return parse_dockerfile((FIXTURES / "repo_good" / "Dockerfile").read_text(encoding="utf-8"))

    @pytest.fixture
    def bad(self):
        return parse_dockerfile((FIXTURES / "repo_bad" / "Dockerfile").read_text(encoding="utf-8"))

    def test_no_parse_errors_good(self, good):
        assert good.parse_errors == []

    def test_no_parse_errors_bad(self, bad):
        assert bad.parse_errors == []

    def test_instruction_count_good(self, good):
        instrs = [i for i in good.instructions if not i.is_directive]
        # FROM, WORKDIR, COPY, RUN, USER, CMD
        assert len(instrs) == 6
        names = [i.instruction_upper for i in good.instructions if not i.is_directive]
        assert names == ["FROM", "WORKDIR", "COPY", "RUN", "USER", "CMD"]

    def test_user_present_in_good(self, good):
        names = [i.instruction_upper for i in good.instructions if not i.is_directive]
        assert "USER" in names

    def test_user_absent_in_bad(self, bad):
        names = [i.instruction_upper for i in bad.instructions if not i.is_directive]
        assert "USER" not in names

    def test_env_args_captured(self, bad):
        envs = [i for i in bad.instructions if i.instruction_upper == "ENV"]
        assert len(envs) == 2
        assert "NODE_ENV=production" in envs[0].args.replace("  ", " ")
        assert "API_KEY=" in envs[1].args

    def test_line_numbers(self, bad):
        env_api_key = next(i for i in bad.instructions if i.instruction_upper == "ENV" and "API_KEY" in i.args)
        assert env_api_key.line == 5  # line 5: ENV API_KEY=...

    def test_end_line_matches_line_for_simple_instr(self, good):
        for i in good.instructions:
            if not i.is_directive:
                if "\\" not in i.raw:
                    assert i.end_line == i.line

    def test_directive_recognized(self, bad):
        directives = [i for i in bad.instructions if i.is_directive]
        assert len(directives) == 1
        assert directives[0].instruction.lower() == "syntax"

    def test_continations_joined(self):
        text = (
            "FROM alpine\n"
            "RUN apt-get update && \\\n"
            "    apt-get install -y curl && \\\n"
            "    rm -rf /var/lib/apt/lists/*\n"
        )
        result = parse_dockerfile(text)
        runs = [i for i in result.instructions if i.instruction_upper == "RUN"]
        assert len(runs) == 1
        assert runs[0].line == 2
        assert runs[0].end_line == 4
        assert "apt-get install -y curl" in runs[0].args

    def test_comment_lines_skipped(self):
        text = "# a comment\n# another\nFROM alpine\n"
        result = parse_dockerfile(text)
        names = [i.instruction_upper for i in result.instructions if not i.is_directive]
        assert names == ["FROM"]

    def test_empty_input(self):
        result = parse_dockerfile("")
        assert result.instructions == []
        assert result.parse_errors == []

    def test_unterminated_continuation(self):
        text = "FROM alpine\nRUN echo hello \\\n"
        result = parse_dockerfile(text)
        assert any("unterminated" in e for e in result.parse_errors)


# ─── Workflow parsing ──────────────────────────────────────────────────────


class TestWorkflowParser:
    @pytest.fixture
    def good_wf(self):
        return parse_workflow((FIXTURES / "repo_good" / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))

    @pytest.fixture
    def bad_wf(self):
        return parse_workflow((FIXTURES / "repo_bad" / ".github" / "workflows" / "bad.yml").read_text(encoding="utf-8"))

    def test_no_parse_errors_good(self, good_wf):
        assert good_wf.parse_errors == []

    def test_no_parse_errors_bad(self, bad_wf):
        assert bad_wf.parse_errors == []

    def test_top_level_keys_good(self, good_wf):
        assert "name" in good_wf.data
        assert "on" in good_wf.data
        assert "jobs" in good_wf.data

    def test_line_of_top_level(self, good_wf):
        assert good_wf.line_of("name") == 1
        assert good_wf.line_of("jobs", "build") is not None

    def test_step_line_numbers_bad(self, bad_wf):
        steps_path = ("jobs", "build", "steps", 0, "uses")
        line = bad_wf.line_of(*steps_path)
        assert line is not None
        assert line >= 1

    def test_run_block_content(self, bad_wf):
        steps = bad_wf.data["jobs"]["build"]["steps"]
        dirty_step = next(s for s in steps if "run" in s)
        assert "${{ secrets.DEPLOY_TOKEN }}" in dirty_step["run"]

    def test_yaml_syntax_error(self):
        result = parse_workflow("name: [\n")
        assert result.parse_errors != []
        assert "YAML parse error" in result.parse_errors[0]

    def test_empty_document(self):
        result = parse_workflow("")
        assert result.parse_errors != []

    def test_non_mapping_root(self):
        result = parse_workflow("- item1\n- item2\n")
        assert result.parse_errors != []
        assert "mapping" in result.parse_errors[0]

    def test_line_map_round_trip(self, bad_wf):
        # Every top-level key should have a line entry
        for key in bad_wf.data:
            assert bad_wf.line_of(key) is not None