from __future__ import annotations

import re
from pathlib import Path

from pipeline_audit.core.location import Location
from pipeline_audit.core.parser import ParsedDockerfile
from pipeline_audit.core.rule_base import Finding, RuleHandler
from pipeline_audit.core.rule_loader import Rule as RuleSpec
from pipeline_audit.utils.entropy import shannon_entropy


# Dockerfile instructions that may assign environment variables and
# therefore carry hardcoded secrets in their values.
_ENV_INSTRUCTIONS = ("ENV", "ARG")

# Default capture group used when the rule spec omits `capture_group`.
_DEFAULT_CAPTURE_GROUP = 1


class DockerRegexRule(RuleHandler):
    """Handles `type: regex` rules targeting Dockerfiles.

    Recognized `match.regex` keys:
      - pattern (required): compiled regex. Must expose a capturing group
        (selected via `capture_group`) whose content is treated as the
        candidate secret value.
      - capture_group (default 1): index of the group containing the value.
      - exclude_names: list of ENV/ARG names (case-insensitive) that are
        never flagged even if they match the pattern (allowlist, e.g.
        `NODE_ENV`, `PATH`).
      - min_entropy (default 0.0): Shannon entropy floor (bits/char) on
        the captured value. Values below the floor are dropped.
    """

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

        regex_cfg = spec.match.get("regex", {})
        pattern_src = regex_cfg.get("pattern")
        if not pattern_src:
            return []

        try:
            pattern = re.compile(pattern_src, re.IGNORECASE | re.MULTILINE)
        except re.error:
            return []

        exclude_names = {n.upper() for n in regex_cfg.get("exclude_names", [])}
        min_entropy = float(regex_cfg.get("min_entropy", 0.0))
        capture_group = int(regex_cfg.get("capture_group", _DEFAULT_CAPTURE_GROUP))

        findings: list[Finding] = []
        for inst in dockerfile.instructions:
            if inst.is_directive:
                continue
            if inst.instruction_upper not in _ENV_INSTRUCTIONS:
                continue
            for m in pattern.finditer(inst.raw):
                self._evaluate_match(
                    spec,
                    file=file,
                    instruction=inst,
                    match=m,
                    capture_group=capture_group,
                    exclude_names=exclude_names,
                    min_entropy=min_entropy,
                    findings=findings,
                )
        return findings

    def _evaluate_match(
        self,
        spec: RuleSpec,
        *,
        file: Path,
        instruction,
        match,
        capture_group: int,
        exclude_names: set[str],
        min_entropy: float,
        findings: list[Finding],
    ) -> None:
        try:
            value = match.group(capture_group)
        except IndexError:
            # Capturing group index out of range for this compiled pattern
            return
        if value is None:
            return

        name = self._name_of(match, capture_group)
        if name.upper() in exclude_names:
            return

        if shannon_entropy(value) < min_entropy:
            return

        line = instruction.line + match.string[: match.start()].count("\n")
        snippet = self._snippet(instruction, name, value)

        findings.append(
            Finding(
                rule_id=spec.id,
                title=spec.title,
                severity=spec.severity,
                target=spec.target,
                location=Location(file=file, line=line, snippet=snippet),
                remediation=spec.remediation,
                references=list(spec.references),
            )
        )

    def _name_of(self, match: re.Match, capture_group: int) -> str:
        """Extract the ENV/ARG variable name from the regex match.

        Walks backwards from the start of the captured value, skipping the
        `[=\\s]+` separator that precedes the value, then collects the
        preceding run of non-whitespace characters as the name.
        """
        text = match.string
        search_pos = match.start(capture_group) - 1
        # Skip separator chars ([=\s]+ equivalent of trailing = or whitespace)
        while search_pos >= match.start() and text[search_pos] in "=\t\n\f\r ":
            search_pos -= 1
        name_end = search_pos + 1
        # Collect name token (everything until preceding whitespace)
        while search_pos >= match.start() and text[search_pos] not in " \t\n\f\r":
            search_pos -= 1
        return text[search_pos + 1 : name_end]

    def _snippet(self, instruction, name: str, value: str) -> str:
        # Prefer the first non-whitespace raw line of the instruction for
        # short single-line assignments; otherwise synthesize name=value.
        first_line = next(
            (ln.strip() for ln in instruction.raw.splitlines() if ln.strip()),
            "",
        )
        if first_line:
            return first_line
        return f"{instruction.instruction_upper} {name}={value}"


__all__ = ["DockerRegexRule"]