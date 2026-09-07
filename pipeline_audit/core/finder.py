from __future__ import annotations

from enum import Enum
import os
from pathlib import Path
import stat
import subprocess

import pathspec

from pipeline_audit.core.exceptions import ScanInputError


class FileKind(str, Enum):
    DOCKERFILE = "dockerfile"
    GITHUB_WORKFLOW = "github_workflow"


WORKFLOW_SUFFIXES = {".yml", ".yaml"}
WORKFLOW_DIR_PARTS = {
    (".github", "workflows"),
    (".gitea", "workflows"),
    (".gitlab", "workflows"),
}
DOCKERFILE_NAMES = {"dockerfile"}
MAX_FILE_BYTES = 1_048_576  # 1 MiB cap to avoid giant generated files

# Directory names that are never scanned — test fixtures, vendored code, caches.
# Checked against any path component in the relative path from scan root.
EXCLUDED_DIR_NAMES = {
    "node_modules",
    "test",
    "tests",
    "__tests__",
}


def _looks_like_dockerfile(path: Path) -> bool:
    name = path.name.lower()
    if name in DOCKERFILE_NAMES:
        return True
    if name.startswith("dockerfile.") or name.endswith(".dockerfile") or ".dockerfile." in name:
        return True
    return False


def _is_workflow_file(path: Path) -> bool:
    return path.suffix.lower() in WORKFLOW_SUFFIXES


def _workflow_dir_match(path: Path) -> bool:
    parts = tuple(part.lower() for part in path.parent.parts)
    for index in range(len(parts) - 1):
        if parts[index : index + 2] in WORKFLOW_DIR_PARTS:
            return True
    return False


def _extend_gitignore_specs(
    directory: Path,
    inherited: list[tuple[Path, pathspec.GitIgnoreSpec]],
) -> list[tuple[Path, pathspec.GitIgnoreSpec]]:
    ignore_file = directory / ".gitignore"
    if not ignore_file.is_file():
        return inherited
    try:
        lines = ignore_file.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ScanInputError(f"Cannot read ignore file {ignore_file}: {exc}") from exc
    return [*inherited, (directory, pathspec.GitIgnoreSpec.from_lines(lines))]


def _is_ignored_nested(
    path: Path,
    specs: list[tuple[Path, pathspec.GitIgnoreSpec]],
    *,
    is_dir: bool = False,
) -> bool:
    ignored = False
    for base, spec in specs:
        try:
            candidate = path.relative_to(base).as_posix()
        except ValueError:
            continue
        if is_dir:
            candidate += "/"
        result = spec.check_file(candidate)
        if result.include is not None:
            ignored = bool(result.include)
    return ignored


def _raise_walk_error(exc: OSError) -> None:
    raise ScanInputError(f"Cannot traverse scan tree: {exc}") from exc


def _reject_symlink(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise ScanInputError(f"Cannot inspect path {path}: {exc}") from exc
    if stat.S_ISLNK(mode):
        raise ScanInputError(f"Symlinks are not supported in scan trees: {path}")


def _tracked_security_paths(root: Path) -> set[Path]:
    """Return tracked Dockerfiles/workflows beneath *root*, when it is in Git.

    A tracked security configuration is part of the reviewed source and must
    not disappear merely because a later `.gitignore` pattern matches it.
    Non-repositories retain ordinary `.gitignore` behavior.
    """
    try:
        top_level = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if top_level.returncode != 0:
        return set()

    repo_root = Path(top_level.stdout.decode("utf-8", errors="strict").strip())
    try:
        listing = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "-z", "--full-name"],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanInputError(f"Cannot inspect tracked files: {exc}") from exc
    if listing.returncode != 0:
        raise ScanInputError("Cannot inspect tracked files with Git")

    tracked: set[Path] = set()
    for item in listing.stdout.split(b"\0"):
        if not item:
            continue
        try:
            relative = Path(item.decode("utf-8", errors="strict"))
        except UnicodeDecodeError as exc:
            raise ScanInputError("Git returned a non-UTF-8 tracked path") from exc
        path = repo_root / relative
        try:
            path.relative_to(root)
        except ValueError:
            continue
        if _looks_like_dockerfile(path) or (
            _is_workflow_file(path) and _workflow_dir_match(path)
        ):
            tracked.add(path)
    return tracked


def find_audit_targets(root: Path) -> list[tuple[Path, FileKind]]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    targets: list[tuple[Path, FileKind]] = []
    specs_by_dir: dict[Path, list[tuple[Path, pathspec.GitIgnoreSpec]]] = {}
    tracked_targets = _tracked_security_paths(root)
    tracked_ancestors = {
        ancestor
        for target in tracked_targets
        for ancestor in target.parents
        if ancestor == root or root in ancestor.parents
    }

    for current_str, dirnames, filenames in os.walk(
        root,
        topdown=True,
        onerror=_raise_walk_error,
        followlinks=False,
    ):
        current = Path(current_str)
        inherited = specs_by_dir.get(current.parent, []) if current != root else []
        specs = _extend_gitignore_specs(current, inherited)
        specs_by_dir[current] = specs

        kept_dirs: list[str] = []
        for dirname in dirnames:
            candidate = current / dirname
            _reject_symlink(candidate)
            if dirname.lower() in EXCLUDED_DIR_NAMES:
                continue
            if (
                candidate not in tracked_ancestors
                and _is_ignored_nested(candidate, specs, is_dir=True)
            ):
                continue
            kept_dirs.append(dirname)
            specs_by_dir[candidate] = specs
        dirnames[:] = kept_dirs

        for filename in filenames:
            path = current / filename
            _reject_symlink(path)
            if path not in tracked_targets and _is_ignored_nested(path, specs):
                continue

            kind: FileKind | None = None
            if _is_workflow_file(path) and _workflow_dir_match(path):
                kind = FileKind.GITHUB_WORKFLOW
            elif _looks_like_dockerfile(path):
                kind = FileKind.DOCKERFILE
            if kind is None:
                continue

            try:
                size = path.stat().st_size
            except OSError as exc:
                raise ScanInputError(f"Cannot inspect scan target {path}: {exc}") from exc
            if size > MAX_FILE_BYTES:
                raise ScanInputError(
                    f"Scan target exceeds {MAX_FILE_BYTES} byte limit: {path} ({size} bytes)"
                )
            targets.append((path, kind))

    targets.sort(key=lambda t: str(t[0]))
    return targets
