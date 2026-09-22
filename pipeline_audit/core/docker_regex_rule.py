from __future__ import annotations

import re
import shlex
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
        seen: set[tuple[int, str]] = set()
        for inst in dockerfile.instructions:
            if inst.is_directive:
                continue
            if inst.instruction_upper not in _ENV_INSTRUCTIONS:
                continue
            candidates = [(inst.raw, inst.line)]
            candidates.extend(_assignment_candidates(inst))
            for candidate, candidate_line in candidates:
                for m in pattern.finditer(candidate):
                    self._evaluate_match(
                        spec,
                        file=file,
                        instruction=inst,
                        match=m,
                        line=candidate_line,
                        capture_group=capture_group,
                        exclude_names=exclude_names,
                        min_entropy=min_entropy,
                        findings=findings,
                        seen=seen,
                    )
        return findings

    def _evaluate_match(
        self,
        spec: RuleSpec,
        *,
        file: Path,
        instruction,
        match,
        line: int,
        capture_group: int,
        exclude_names: set[str],
        min_entropy: float,
        findings: list[Finding],
        seen: set[tuple[int, str]],
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

        if _is_runtime_reference(value):
            return

        if shannon_entropy(value) < min_entropy:
            return

        line += match.string[: match.start()].count("\n")
        identity = (line, name.upper())
        if identity in seen:
            return
        seen.add(identity)
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
        return f"{instruction.instruction_upper} {name}=<redacted>"


def _assignment_candidates(instruction) -> list[tuple[str, int]]:
    """Split ENV/ARG assignments and retain each assignment's source line.

    Docker permits an ENV instruction to span lines.  Flattened ``args`` are
    convenient for matching, but lose the line on which later ``NAME=value``
    pairs occur.  Tokenizing the original instruction keeps the generated
    candidate independent while pointing a finding at the assignment itself.
    """
    raw_tokens = _assignment_tokens_with_lines(instruction)
    tokens: list[tuple[str, int]] = []
    for raw_token, line in raw_tokens:
        try:
            parsed = shlex.split(raw_token, posix=True)
        except ValueError:
            parsed = [raw_token]
        if parsed:
            # A shell token produces exactly one logical ENV token.  Keeping
            # this defensive loop makes malformed quotes fail closed but still
            # lets straightforward assignments be scanned.
            tokens.extend((token, line) for token in parsed)
    if not tokens:
        return []

    assignments: list[tuple[str, str, int]] = []
    for token, line in tokens:
        if "=" in token:
            name, value = token.split("=", 1)
            assignments.append((name, value, line))

    if not assignments and instruction.instruction_upper == "ENV" and len(tokens) >= 2:
        name, line = tokens[0]
        assignments.append((name, " ".join(token for token, _ in tokens[1:]), line))

    return [
        (f"{instruction.instruction_upper} {name}={value}", line)
        for name, value, line in assignments
    ]


def _assignment_tokens_with_lines(instruction) -> list[tuple[str, int]]:
    """Lex the original ENV/ARG text into tokens paired with their line."""
    lines = instruction.raw.splitlines()
    if not lines:
        return []

    first = re.match(r"\s*\S+(.*)$", lines[0])
    segments: list[tuple[str, int]] = [(first.group(1) if first else "", instruction.line)]
    segments.extend((line, instruction.line + index) for index, line in enumerate(lines[1:], 1))

    chars: list[tuple[str, int]] = []
    escape_char = getattr(instruction, "escape_char", "\\")
    for index, (segment, line) in enumerate(segments):
        trimmed = segment.rstrip()
        if _ends_with_escape(trimmed, escape_char):
            trimmed = trimmed[:-1]
        chars.extend((ch, line) for ch in trimmed)
        if index + 1 < len(segments):
            # Whitespace joins a Docker continuation without attributing the
            # next assignment to the preceding source line.
            chars.append((" ", segments[index + 1][1]))

    tokens: list[tuple[str, int]] = []
    token: list[str] = []
    token_line: int | None = None
    quote: str | None = None
    i = 0
    while i < len(chars):
        ch, line = chars[i]
        if quote is None and ch.isspace():
            if token:
                tokens.append(("".join(token), token_line or line))
                token = []
                token_line = None
            i += 1
            continue

        if token_line is None:
            token_line = line
        token.append(ch)
        if ch in {"'", '"'}:
            if quote is None:
                quote = ch
            elif quote == ch:
                quote = None
        elif ch == "\\" and quote != "'" and i + 1 < len(chars):
            # Preserve shell escapes and prevent an escaped space/quote from
            # ending or changing the current token.
            i += 1
            escaped, escaped_line = chars[i]
            token.append(escaped)
        i += 1

    if token:
        tokens.append(("".join(token), token_line or instruction.line))
    return tokens


def _ends_with_escape(text: str, escape_char: str) -> bool:
    if not text.endswith(escape_char):
        return False
    count = 0
    for ch in reversed(text):
        if ch != escape_char:
            break
        count += 1
    return count % 2 == 1


def _is_runtime_reference(value: str) -> bool:
    stripped = _normalized_value(value)
    return bool(
        re.fullmatch(
            r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})",
            stripped,
        )
        or re.fullmatch(r"\{\{\s*[A-Za-z_][A-Za-z0-9_]*\s*\}\}", stripped)
    )


def _normalized_value(value: str) -> str:
    stripped = value.strip()
    if (
        len(stripped) >= 2
        and stripped[0] == stripped[-1]
        and stripped[0] in {'"', "'"}
    ):
        return stripped[1:-1]
    return stripped


__all__ = ["DockerRegexRule"]
