from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pipeline_audit.core.location import Location
from pipeline_audit.core.parser import ParsedWorkflow
from pipeline_audit.core.rule_base import Finding, RuleHandler
from pipeline_audit.core.rule_loader import Rule as RuleSpec

class WorkflowRegexRule(RuleHandler):
    """Handles `type: regex` rules targeting GitHub Actions workflows.

    Configuration via `match.regex`:
      - pattern (required): compiled regex applied to step scoped values.
      - scope_keys (required): list of step-level keys whose scalar string
        values are scanned (e.g. `run`, `script`).
      - exclude_keys (optional): keys whose values are never scanned, even
        if they also appear in `scope_keys` or mean the same content. The
        canonical defence here is `env:` — passing secrets through `env`
        is the recommended pattern, not an interpolation into `run`.
    """

    def match(
        self,
        spec: RuleSpec,
        *,
        file: Path,
        dockerfile=None,
        workflow: ParsedWorkflow | None = None,
        raw_text: str = "",
    ) -> list[Finding]:
        if workflow is None:
            return []

        regex_cfg = spec.match.get("regex", {})
        pattern_src = regex_cfg.get("pattern")
        if not pattern_src:
            return []

        try:
            pattern = re.compile(pattern_src)
        except re.error:
            return []

        scope_keys = set(regex_cfg.get("scope_keys", []))
        exclude_keys = set(regex_cfg.get("exclude_keys", []))
        # Defence in depth: never let a misconfigured rule scan excluded keys.
        scope_keys -= exclude_keys
        if not scope_keys:
            return []

        findings: list[Finding] = []
        jobs = workflow.data.get("jobs", {})
        if not isinstance(jobs, dict):
            return findings

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            for idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                self._scan_mapping(
                    spec,
                    file=file,
                    wf=workflow,
                    node=step,
                    path=("jobs", job_name, "steps", idx),
                    scope_keys=scope_keys,
                    exclude_keys=exclude_keys,
                    pattern=pattern,
                    findings=findings,
                )
        return findings

    def _scan_mapping(
        self,
        spec: RuleSpec,
        *,
        file: Path,
        wf: ParsedWorkflow,
        node: Any,
        path: tuple,
        scope_keys: set[str],
        exclude_keys: set[str],
        pattern: re.Pattern,
        findings: list[Finding],
    ) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                child_path = path + (key,)
                if key in exclude_keys:
                    continue
                if key in scope_keys:
                    self._scan_value(
                        spec,
                        file=file,
                        wf=wf,
                        path=child_path,
                        value=value,
                        pattern=pattern,
                        findings=findings,
                    )
                else:
                    self._scan_mapping(
                        spec,
                        file=file,
                        wf=wf,
                        node=value,
                        path=child_path,
                        scope_keys=scope_keys,
                        exclude_keys=exclude_keys,
                        pattern=pattern,
                        findings=findings,
                    )
        elif isinstance(node, list):
            for index, value in enumerate(node):
                self._scan_mapping(
                    spec,
                    file=file,
                    wf=wf,
                    node=value,
                    path=path + (index,),
                    scope_keys=scope_keys,
                    exclude_keys=exclude_keys,
                    pattern=pattern,
                    findings=findings,
                )

    def _scan_value(
        self,
        spec: RuleSpec,
        *,
        file: Path,
        wf: ParsedWorkflow,
        path: tuple,
        value: Any,
        pattern: re.Pattern,
        findings: list[Finding],
    ) -> None:
        if not isinstance(value, str):
            for sub_index, sub in enumerate(value if isinstance(value, list) else []):
                self._scan_value(
                    spec,
                    file=file,
                    wf=wf,
                    path=path + (sub_index,),
                    value=sub,
                    pattern=pattern,
                    findings=findings,
                )
            return

        base_line = wf.line_of(*path)

        # Block scalars (`|` / `>`) start the value on the line *after*
        # the key line.
        if base_line is not None and self._is_block_scalar(wf, base_line):
            base_line += 1

        # Count newlines in the value to resolve multi-line matches.
        for m in pattern.finditer(value):
            offset = value.count("\n", 0, m.start())
            line = (base_line or 1) + offset
            findings.append(
                Finding(
                    rule_id=spec.id,
                    title=spec.title,
                    severity=spec.severity,
                    target=spec.target,
                    location=Location(
                        file=file, line=line, snippet=m.group(0)
                    ),
                    remediation=spec.remediation,
                    references=list(spec.references),
                )
            )

    def _is_block_scalar(self, wf: ParsedWorkflow, key_line: int) -> bool:
        if 1 <= key_line <= len(wf.raw_lines):
            line = wf.raw_lines[key_line - 1].rstrip()
            # The key line ends with a block scalar indicator (`|` or `>`).
            # We cheaply check for a trailing `:` followed by the indicator.
            return bool(re.search(r":\s*[|>][\+\-]?\s*$", line))
        return False

__all__ = ["WorkflowRegexRule"]
