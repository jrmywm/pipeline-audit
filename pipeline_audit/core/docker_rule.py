from __future__ import annotations

from pathlib import Path

from pipeline_audit.core.location import Location
from pipeline_audit.core.parser import ParsedDockerfile
from pipeline_audit.core.rule_base import Finding, RuleHandler
from pipeline_audit.core.rule_loader import Rule as RuleSpec
from pipeline_audit.core.severity import Severity


class DockerStructuralRule(RuleHandler):
    """Handles `type: structural` rules targeting Dockerfiles.

    Recognized `match.structural.kind` values:
      - missing_instruction: fires when no instruction with
        `match.structural.instruction` (case-insensitive) appears.
    """

    KIND_MISSING_INSTRUCTION = "missing_instruction"

    def match(
        self,
        spec: RuleSpec,
        *,
        file: Path,
        dockerfile: ParsedDockerfile | None = None,
        workflow=None,
        raw_text: str = "",
    ) -> list[Finding]:
        if dockerfile is None:
            return []

        kind = spec.match.get("structural", {}).get("kind")
        if kind == self.KIND_MISSING_INSTRUCTION:
            return self._missing_instruction(spec, file, dockerfile)
        return []

    def _missing_instruction(
        self, spec: RuleSpec, file: Path, df: ParsedDockerfile
    ) -> list[Finding]:
        target_instr = spec.match["structural"]["instruction"].upper()
        present = any(
            i.instruction_upper == target_instr and not i.is_directive
            for i in df.instructions
        )
        if present:
            return []

        last_line = max((i.end_line for i in df.instructions), default=1)
        snippet = None
        if df.raw_lines:
            snippet = df.raw_lines[0]

        return [
            Finding(
                rule_id=spec.id,
                title=spec.title,
                severity=spec.severity,
                target=spec.target,
                location=Location(file=file, line=1, end_line=last_line, snippet=snippet),
                remediation=spec.remediation,
                references=list(spec.references),
            )
        ]


__all__ = ["DockerStructuralRule"]