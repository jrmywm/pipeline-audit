from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pipeline_audit.core.location import Location
from pipeline_audit.core.parser import ParsedWorkflow
from pipeline_audit.core.rule_base import Finding, RuleHandler
from pipeline_audit.core.rule_loader import Rule as RuleSpec

# Sibling-key indents / value patterns that mark the end of a block scalar's
# multi-line body. We use a simpler heuristic below instead.
_BLOCK_SCALAR_HINT = re.compile(r":\s*[|>][\+\-]?\s*$")


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
                for key, value in step.items():
                    if key not in scope_keys:
                        continue
                    self._scan_step_value(
                        spec,
                        file=file,
                        wf=workflow,
                        job=job_name,
                        idx=idx,
                        key=key,
                        value=value,
                        pattern=pattern,
                        findings=findings,
                    )
        return findings

    def _scan_step_value(
        self,
        spec: RuleSpec,
        *,
        file: Path,
        wf: ParsedWorkflow,
        job: str,
        idx: int,
        key: str,
        value: Any,
        pattern: re.Pattern,
        findings: list[Finding],
    ) -> None:
        if not isinstance(value, str):
            for sub in value if isinstance(value, list) else []:
                self._scan_step_value(
                    spec,
                    file=file,
                    wf=wf,
                    job=job,
                    idx=idx,
                    key=key,
                    value=sub,
                    pattern=pattern,
                    findings=findings,
                )
            return

        base_line = wf.line_of("jobs", job, "steps", idx, key)
        if base_line is None:
            base_line = self._fallback_line(wf, job, idx, key)

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

    def _fallback_line(
        self, wf: ParsedWorkflow, job: str, idx: int, key: str
    ) -> int | None:
        for path in (
            ("jobs", job, "steps", idx, key),
            ("jobs", job, "steps", idx),
        ):
            line = wf.line_of(*path)
            if line is not None:
                return line
        return None


__all__ = ["WorkflowRegexRule"]