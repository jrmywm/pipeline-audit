from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_audit.core.finder import FileKind, find_audit_targets

FIXTURES = Path(__file__).parent / "fixtures"


# ─── repo_good ──────────────────────────────────────────────────────────────


class TestRepoGood:
    @pytest.fixture
    def targets(self):
        return find_audit_targets(FIXTURES / "repo_good")

    def test_finds_dockerfile(self, targets):
        kinds = {p.name: k for p, k in targets}
        assert "Dockerfile" in kinds
        assert kinds["Dockerfile"] == FileKind.DOCKERFILE

    def test_finds_workflow(self, targets):
        paths = [p for p, k in targets if k == FileKind.GITHUB_WORKFLOW]
        assert any(p.name == "ci.yml" for p in paths)

    def test_no_node_modules(self, targets):
        assert not any("node_modules" in p.parts for p, _ in targets)

    def test_returns_only_files(self, targets):
        for p, _ in targets:
            assert p.is_file()


# ─── repo_bad ──────────────────────────────────────────────────────────────


class TestRepoBad:
    @pytest.fixture
    def targets(self):
        return find_audit_targets(FIXTURES / "repo_bad")

    def test_finds_top_dockerfile(self, targets):
        dockerfiles = [p for p, k in targets if k == FileKind.DOCKERFILE]
        assert any(p.name == "Dockerfile" and "node_modules" not in p.parts for p in dockerfiles)

    def test_skips_node_modules_dockerfile(self, targets):
        assert not any("node_modules" in p.parts and p.name == "Dockerfile" for p, _ in targets)

    def test_finds_bad_workflow(self, targets):
        paths = [p for p, k in targets if k == FileKind.GITHUB_WORKFLOW]
        assert any(p.name == "bad.yml" for p in paths)


# ─── gitignore behaviour ───────────────────────────────────────────────────


class TestGitignore:
    def test_repo_good_gitignore_present(self):
        gi = FIXTURES / "repo_good" / ".gitignore"
        assert gi.is_file()
        assert "node_modules/" in gi.read_text(encoding="utf-8")

    def test_ignored_directory_not_returned(self, tmp_path):
        # Create a fake repo with .gitignore + ignored workflow path
        (tmp_path / ".gitignore").write_text("ci.yml\n", encoding="utf-8")
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text("on: push\n", encoding="utf-8")
        targets = find_audit_targets(tmp_path)
        paths = [p for p, _ in targets]
        assert not any(p.name == "ci.yml" for p in paths), "ci.yml should be gitignored"


# ─── directory error ────────────────────────────────────────────────────────


class TestErrors:
    def test_nonexistent_directory_raises(self, tmp_path):
        nonexistent = tmp_path / "nope"
        with pytest.raises(NotADirectoryError):
            find_audit_targets(nonexistent)