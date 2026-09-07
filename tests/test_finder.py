from __future__ import annotations

from pathlib import Path
import os
import subprocess

import pytest

from pipeline_audit.core.finder import FileKind, find_audit_targets
from pipeline_audit.core.exceptions import ScanInputError

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

    def test_nested_gitignore_is_respected(self, tmp_path):
        nested = tmp_path / "service"
        generated = nested / "generated"
        generated.mkdir(parents=True)
        (nested / ".gitignore").write_text("generated/\n", encoding="utf-8")
        (generated / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        assert find_audit_targets(tmp_path) == []

    def test_tracked_security_target_overrides_gitignore(self, tmp_path):
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        (tmp_path / ".gitignore").write_text("ci.yml\n", encoding="utf-8")
        workflow_dir = tmp_path / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)
        workflow = workflow_dir / "ci.yml"
        workflow.write_text("on: push\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(tmp_path), "add", "-f", ".github/workflows/ci.yml"],
            check=True,
        )

        assert (workflow, FileKind.GITHUB_WORKFLOW) in find_audit_targets(tmp_path)

    def test_invalid_utf8_gitignore_fails_closed(self, tmp_path):
        (tmp_path / ".gitignore").write_bytes(b"Dockerfile\xff\n")
        with pytest.raises(ScanInputError, match="Cannot read ignore file"):
            find_audit_targets(tmp_path)


class TestWorkflowRoots:
    def test_workflow_directory_can_be_scan_root(self, tmp_path):
        workflow_dir = tmp_path / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)
        workflow = workflow_dir / "ci.yml"
        workflow.write_text("on: push\n", encoding="utf-8")
        assert find_audit_targets(workflow_dir) == [
            (workflow, FileKind.GITHUB_WORKFLOW)
        ]


class TestSizeLimit:
    def test_oversized_target_fails_closed(self, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_bytes(b"x" * 1_048_577)
        with pytest.raises(ScanInputError, match="exceeds"):
            find_audit_targets(tmp_path)


class TestTraversalSafety:
    def test_walk_error_fails_closed(self, tmp_path, monkeypatch):
        def failing_walk(*args, onerror=None, **kwargs):
            assert onerror is not None
            onerror(PermissionError("denied"))
            yield  # pragma: no cover

        monkeypatch.setattr("pipeline_audit.core.finder.os.walk", failing_walk)
        with pytest.raises(ScanInputError, match="Cannot traverse scan tree"):
            find_audit_targets(tmp_path)

    @pytest.mark.parametrize("is_directory", [False, True])
    def test_symlink_fails_closed(self, tmp_path, is_directory):
        root = tmp_path / "repo"
        root.mkdir()
        if is_directory:
            target = tmp_path / "external"
            target.mkdir()
            (target / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            link = root / "service"
        else:
            target = tmp_path / "external.Dockerfile"
            target.write_text("FROM scratch\n", encoding="utf-8")
            link = root / "Dockerfile"
        try:
            os.symlink(target, link, target_is_directory=is_directory)
        except OSError as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with pytest.raises(ScanInputError, match="Symlinks are not supported"):
            find_audit_targets(root)


# ─── excluded directory names ───────────────────────────────────────────────


class TestExcludedDirs:
    @pytest.mark.parametrize("dirname", ["test", "tests", "__tests__"])
    def test_test_dirs_excluded(self, tmp_path, dirname):
        d = tmp_path / dirname
        d.mkdir()
        (d / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        targets = find_audit_targets(tmp_path)
        assert not any(p.name == "Dockerfile" for p, _ in targets)

    def test_node_modules_excluded(self, tmp_path):
        d = tmp_path / "node_modules"
        d.mkdir()
        (d / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        targets = find_audit_targets(tmp_path)
        assert not any(p.name == "Dockerfile" for p, _ in targets)

    def test_non_test_dir_not_excluded(self, tmp_path):
        d = tmp_path / "dockerfiles"
        d.mkdir()
        (d / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        targets = find_audit_targets(tmp_path)
        assert any(p.name == "Dockerfile" for p, _ in targets)


# ─── directory error ────────────────────────────────────────────────────────


class TestErrors:
    def test_nonexistent_directory_raises(self, tmp_path):
        nonexistent = tmp_path / "nope"
        with pytest.raises(NotADirectoryError):
            find_audit_targets(nonexistent)
