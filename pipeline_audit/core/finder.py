from __future__ import annotations

from enum import Enum
from pathlib import Path

import pathspec


class FileKind(str, Enum):
    DOCKERFILE = "dockerfile"
    GITHUB_WORKFLOW = "github_workflow"


WORKFLOW_SUFFIXES = {".yml", ".yaml"}
WORKFLOW_DIR_GLOBS = [".github/workflows", ".gitea/workflows", ".gitlab/workflows"]
DOCKERFILE_NAMES = {"dockerfile"}
MAX_FILE_BYTES = 1_048_576  # 1 MiB cap to avoid giant generated files


def _load_gitignore(root: Path) -> pathspec.PathSpec | None:
    gi = root / ".gitignore"
    if not gi.is_file():
        return None
    try:
        lines = gi.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    return pathspec.PathSpec.from_lines("gitignore", lines)


def _is_ignored(rel: Path, spec: pathspec.PathSpec | None) -> bool:
    if spec is None:
        return False
    posix = rel.as_posix()
    if spec.match_file(posix):
        return True
    parts = rel.parts
    for i in range(1, len(parts)):
        if spec.match_file("/".join(parts[:i]) + "/"):
            return True
    return False


def _looks_like_dockerfile(path: Path) -> bool:
    name = path.name.lower()
    if name in DOCKERFILE_NAMES:
        return True
    if name.startswith("dockerfile.") or name.endswith(".dockerfile") or ".dockerfile." in name:
        return True
    return False


def _is_workflow_file(path: Path) -> bool:
    return path.suffix.lower() in WORKFLOW_SUFFIXES


def _workflow_dir_match(rel: Path) -> bool:
    posix = rel.as_posix()
    for g in WORKFLOW_DIR_GLOBS:
        if posix.startswith(g + "/"):
            return True
    return False


def find_audit_targets(root: Path) -> list[tuple[Path, FileKind]]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    spec = _load_gitignore(root)
    targets: list[tuple[Path, FileKind]] = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue

        if _is_ignored(rel, spec):
            continue

        if _is_workflow_file(path) and _workflow_dir_match(rel):
            targets.append((path, FileKind.GITHUB_WORKFLOW))
            continue

        if _looks_like_dockerfile(path):
            rel_parts_lower = [p.lower() for p in rel.parts[:-1]]
            if "node_modules" in rel_parts_lower:
                continue
            targets.append((path, FileKind.DOCKERFILE))

    targets.sort(key=lambda t: str(t[0]))
    return targets