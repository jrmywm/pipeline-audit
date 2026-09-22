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
        source_line_map = self._block_scalar_source_line_map(wf, base_line)

        # Block scalar values are decoded by YAML before we scan them.  In
        # particular, folded scalars turn many physical line breaks into
        # spaces, so counting newlines in ``value`` alone cannot recover the
        # source location.  The map retains the source line of each decoded
        # character.
        if source_line_map is not None:
            base_line = None

        # Count newlines in the value to resolve multi-line matches.
        for m in pattern.finditer(value):
            offset = value.count("\n", 0, m.start())
            line = (
                source_line_map[m.start()]
                if source_line_map is not None and m.start() < len(source_line_map)
                else (base_line or 1) + offset
            )
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

    def _block_scalar_source_line_map(
        self, wf: ParsedWorkflow, key_line: int | None
    ) -> list[int] | None:
        """Return decoded-character-to-source-line offsets for a block scalar.

        ``ParsedWorkflow`` intentionally keeps only the parsed data, its key
        locations, and the raw source lines.  This reconstructs enough YAML
        block-scalar semantics from those structures to locate regex matches:
        literal scalars preserve line breaks, while folded scalars fold ordinary
        line breaks but preserve those around blank or more-indented lines.
        """
        if key_line is None or not 1 <= key_line <= len(wf.raw_lines):
            return None

        header = self._parse_block_scalar_header(wf.raw_lines[key_line - 1])
        if header is None:
            return None
        style, explicit_indent, parent_indent = header

        content: list[tuple[str, int, int]] = []
        for index in range(key_line, len(wf.raw_lines)):
            raw_line = wf.raw_lines[index]
            stripped = raw_line.strip()
            indentation = len(raw_line) - len(raw_line.lstrip(" "))
            if stripped and indentation <= parent_indent:
                break
            content.append((raw_line, index + 1, indentation))

        non_blank_indents = [indent for raw, _, indent in content if raw.strip()]
        if not non_blank_indents:
            return []
        content_indent = (
            parent_indent + explicit_indent
            if explicit_indent is not None
            else min(non_blank_indents)
        )

        lines = [
            (raw[content_indent:] if len(raw) >= content_indent else "", line, indent)
            for raw, line, indent in content
        ]
        line_map: list[int] = []
        for index, (text, line, indentation) in enumerate(lines):
            line_map.extend([line] * len(text))
            if index == len(lines) - 1:
                continue

            next_text, _, next_indentation = lines[index + 1]
            if style == "|":
                separator = "\n"
            elif not text:
                # A run of N blank source lines becomes N newlines.  The
                # preceding non-blank-to-blank boundary contributes nothing.
                separator = "\n"
            elif not next_text:
                separator = ""
            elif indentation > content_indent or next_indentation > content_indent:
                separator = "\n"
            else:
                separator = " "
            line_map.extend([line] * len(separator))
        return line_map

    @staticmethod
    def _parse_block_scalar_header(
        line: str,
    ) -> tuple[str, int | None, int] | None:
        """Parse a mapping value header such as ``run: >2- # comment``."""
        match = re.match(
            r"^(?P<indent> *)(?:-\s+)?(?P<key>.*?)\s*:\s*(?P<style>[|>])"
            r"(?P<indicators>[1-9+\-]*)(?:\s*(?:#.*)?)?$",
            line,
        )
        if match is None:
            return None
        indicators = match.group("indicators")
        indentation = next((int(char) for char in indicators if char.isdigit()), None)
        return match.group("style"), indentation, match.start("key")

__all__ = ["WorkflowRegexRule"]
