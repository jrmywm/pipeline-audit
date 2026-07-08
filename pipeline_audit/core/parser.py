from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError


# ─── Dockerfile ───────────────────────────────────────────────────────────────

_DIRECTIVE_RE = re.compile(r"^\s*#\s*([a-zA-Z]+)\s*=\s*(.+?)\s*$")

# Instructions we recognize; others parsed but flagged as unknown
KNOWN_INSTRUCTIONS = {
    "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV", "ADD",
    "COPY", "ENTRYPOINT", "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD",
    "STOPSIGNAL", "HEALTHCHECK", "SHELL",
}


@dataclass(frozen=True)
class DockerInstruction:
    line: int
    end_line: int
    instruction: str
    args: str
    raw: str
    is_directive: bool = False

    @property
    def instruction_upper(self) -> str:
        return self.instruction.upper()

    @property
    def is_known(self) -> bool:
        return self.instruction_upper in KNOWN_INSTRUCTIONS


@dataclass
class ParsedDockerfile:
    instructions: list[DockerInstruction] = field(default_factory=list)
    raw_lines: list[str] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)


def parse_dockerfile(text: str) -> ParsedDockerfile:
    raw_lines = text.splitlines()
    instructions: list[DockerInstruction] = []
    errors: list[str] = []

    i = 0
    n = len(raw_lines)
    while i < n:
        line = raw_lines[i]
        lineno = i + 1

        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            m = _DIRECTIVE_RE.match(line)
            if m and lineno <= 5 and not instructions:
                instructions.append(
                    DockerInstruction(
                        line=lineno, end_line=lineno, instruction=m.group(1),
                        args=m.group(2), raw=line, is_directive=True,
                    )
                )
            i += 1
            continue

        first_token_match = re.match(r"\s*(\S+)", line)
        if not first_token_match:
            i += 1
            continue
        instruction = first_token_match.group(1)
        rest = line[first_token_match.end():]

        block_lines: list[str] = [line]
        end_line_no = lineno
        j = i

        # Handle line continuations with backslash
        while _ends_with_continuation(block_lines[-1]):
            j += 1
            if j >= n:
                errors.append(f"line {lineno}: unterminated line continuation")
                break
            block_lines.append(raw_lines[j])
            end_line_no = j + 1

        # Handle heredoc: instruction body or following lines `<<EOF` / `<<-EOF`
        joined = "".join(block_lines)
        heredoc_match = re.search(r"<<-?([A-Za-z_][A-Za-z0-9_]*)", joined)
        if heredoc_match:
            terminator = heredoc_match.group(1)
            while j + 1 < n:
                j += 1
                next_line = raw_lines[j]
                block_lines.append(next_line)
                end_line_no = j + 1
                if next_line.strip() == terminator:
                    break
            else:
                errors.append(f"line {lineno}: unterminated heredoc {terminator}")

        i = j + 1
        args = _strip_continuations([rest] + block_lines[1:])
        raw = "\n".join(block_lines)
        instructions.append(
            DockerInstruction(
                line=lineno, end_line=end_line_no, instruction=instruction,
                args=args, raw=raw,
            )
        )

    return ParsedDockerfile(
        instructions=instructions, raw_lines=raw_lines, parse_errors=errors,
    )


def _ends_with_continuation(line: str) -> bool:
    stripped = line.rstrip()
    if not stripped.endswith("\\"):
        return False
    backslashes = 0
    for ch in reversed(stripped):
        if ch == "\\":
            backslashes += 1
        else:
            break
    return backslashes % 2 == 1


def _strip_continuations(lines: list[str]) -> str:
    out: list[str] = []
    for ln in lines:
        s = ln.rstrip()
        if s.endswith("\\"):
            s = s[:-1]
        out.append(s.strip())
    return " ".join(p for p in out if p)


# ─── GitHub Actions workflow ────────────────────────────────────────────────


@dataclass
class ParsedWorkflow:
    data: dict[str, Any]
    line_map: dict[tuple, tuple[int, int]]
    raw_lines: list[str]
    parse_errors: list[str] = field(default_factory=list)

    def line_of(self, *path) -> int | None:
        entry = self.line_map.get(tuple(path))
        return entry[0] if entry else None


def parse_workflow(text: str) -> ParsedWorkflow:
    raw_lines = text.splitlines()
    line_map: dict[tuple, tuple[int, int]] = {}
    errors: list[str] = []

    yaml = YAML(typ="rt")
    try:
        doc = yaml.load(text)
    except YAMLError as exc:
        return ParsedWorkflow(
            data={}, line_map={}, raw_lines=raw_lines,
            parse_errors=[f"YAML parse error: {exc}"],
        )

    if doc is None:
        return ParsedWorkflow(
            data={}, line_map={}, raw_lines=raw_lines,
            parse_errors=["empty document"],
        )

    if not isinstance(doc, dict):
        return ParsedWorkflow(
            data={}, line_map={}, raw_lines=raw_lines,
            parse_errors=[f"workflow root must be a mapping, got {type(doc).__name__}"],
        )

    plain = _convert_with_lines(doc, (), line_map)
    if not isinstance(plain, dict):
        plain = {}

    return ParsedWorkflow(
        data=plain, line_map=line_map, raw_lines=raw_lines, parse_errors=errors,
    )


def _convert_with_lines(node: Any, path: tuple, line_map: dict[tuple, tuple[int, int]]) -> Any:
    from ruamel.yaml.comments import CommentedMap, CommentedSeq

    if isinstance(node, CommentedMap):
        result: dict[str, Any] = {}
        for key, value in node.items():
            key_path = path + (key,)
            lc = _safe_lc(node, key)
            if lc is not None:
                line_map[key_path] = (lc[0] + 1, lc[1] + 1)
            result[key] = _convert_with_lines(value, key_path, line_map)
        return result

    if isinstance(node, CommentedSeq):
        seq: list[Any] = []
        for idx, value in enumerate(node):
            idx_path = path + (idx,)
            lc = _safe_lc_seq(node, idx)
            if lc is not None:
                line_map[idx_path] = (lc[0] + 1, lc[1] + 1)
            seq.append(_convert_with_lines(value, idx_path, line_map))
        return seq

    if isinstance(node, str | int | float | bool) or node is None:
        lc = None
        return node

    # Fallback: stringify unexpected types
    return str(node)


def _safe_lc(node: Any, key: Any) -> tuple[int, int] | None:
    try:
        lc = node.lc.data.get(key)
        if lc is not None and len(lc) >= 2:
            return (lc[0], lc[1])
    except Exception:
        pass
    return None


def _safe_lc_seq(node: Any, idx: int) -> tuple[int, int] | None:
    try:
        lc = node.lc.data.get(idx)
        if lc is not None and len(lc) >= 2:
            return (lc[0], lc[1])
    except Exception:
        pass
    return None