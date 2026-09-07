from __future__ import annotations

from pathlib import Path

from pipeline_audit.core.location import Location
from pipeline_audit.core.parser import ParsedDockerfile
from pipeline_audit.core.rule_base import Finding, RuleHandler
from pipeline_audit.core.rule_loader import Rule as RuleSpec


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
        instructions = [i for i in df.instructions if not i.is_directive]
        if target_instr == "USER":
            final_from = max(
                (idx for idx, inst in enumerate(instructions) if inst.instruction_upper == "FROM"),
                default=0,
            )
            final_stage = instructions[final_from:]
            users = [i for i in final_stage if i.instruction_upper == "USER"]
            present = bool(users and _is_non_root_user(users[-1].args))
            location_line = final_stage[0].line if final_stage else 1
        else:
            present = any(i.instruction_upper == target_instr for i in instructions)
            location_line = 1
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
                location=Location(
                    file=file,
                    line=location_line,
                    end_line=last_line,
                    snippet=snippet,
                ),
                remediation=spec.remediation,
                references=list(spec.references),
            )
        ]


def _is_non_root_user(args: str) -> bool:
    """Return whether a USER argument is statically known to be non-root."""
    value = args.strip().split(maxsplit=1)[0] if args.strip() else ""
    user = value.split(":", 1)[0].strip()
    if not user or "$" in user or "{" in user or "}" in user:
        return False
    if user.lower() == "root":
        return False
    if user.isdigit():
        return int(user) != 0
    return True


__all__ = ["DockerStructuralRule"]
