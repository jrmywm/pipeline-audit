from __future__ import annotations

from pathlib import Path
from typing import Any

from pipeline_audit.core.finder import FileKind, find_audit_targets
from pipeline_audit.core.parser import (
    ParsedDockerfile,
    ParsedWorkflow,
    parse_dockerfile,
    parse_workflow,
)
from pipeline_audit.core.rule_base import Finding, RuleHandler
from pipeline_audit.core.rule_loader import Rule as RuleSpec, load_merged_ruleset
from pipeline_audit.core.docker_rule import DockerStructuralRule
from pipeline_audit.core.workflow_rule import WorkflowStructuralRule


# Registry: maps (target, type) -> RuleHandler instance
# Handlers are stateless; one instance per (target, type) key is fine.
_REGISTRY: dict[tuple[str, str], RuleHandler] = {
    ("dockerfile", "structural"): DockerStructuralRule(),
    ("github_workflow", "structural"): WorkflowStructuralRule(),
    # dockerfile regex, github_workflow regex -> Stage 7+
}


def get_handler(spec: RuleSpec) -> RuleHandler | None:
    return _REGISTRY.get((spec.target, spec.type))


def _register(target: str, rule_type: str, handler: RuleHandler) -> None:
    _REGISTRY[(target, rule_type)] = handler


def scan_path(
    root: Path,
    *,
    ruleset_path: Path | None = None,
    progress_cb: Any = None,
) -> list[Finding]:
    root = Path(root).resolve()
    rules = [r for r in load_merged_ruleset(ruleset_path) if r.enabled]
    targets = find_audit_targets(root)

    findings: list[Finding] = []
    for file_path, kind in targets:
        try:
            raw_text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        dockerfile: ParsedDockerfile | None = None
        workflow: ParsedWorkflow | None = None
        if kind == FileKind.DOCKERFILE:
            dockerfile = parse_dockerfile(raw_text)
        elif kind == FileKind.GITHUB_WORKFLOW:
            workflow = parse_workflow(raw_text)

        for spec in rules:
            if spec.target != kind.value:
                continue
            handler = get_handler(spec)
            if handler is None:
                continue
            result = handler.match(
                spec,
                file=file_path,
                dockerfile=dockerfile,
                workflow=workflow,
                raw_text=raw_text,
            )
            findings.extend(result)

        if progress_cb is not None:
            progress_cb(file_path, len(findings))

    findings.sort(
        key=lambda f: (str(f.location.file), -int(f.severity), f.location.line or 0)
    )
    return findings


__all__ = ["scan_path", "get_handler", "_register"]