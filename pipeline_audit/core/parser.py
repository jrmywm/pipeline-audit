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

MAX_WORKFLOW_NODES = 10_000
MAX_WORKFLOW_DEPTH = 100


class _WorkflowComplexityError(ValueError):
    pass


@dataclass(frozen=True)
class DockerInstruction:
    line: int
    end_line: int
    instruction: str
    args: str
    raw: str
    is_directive: bool = False
    escape_char: str = "\\"

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
    escape_char = "\\"
    saw_instruction = False
    while i < n:
        line = raw_lines[i]
        lineno = i + 1

        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            m = _DIRECTIVE_RE.match(line)
            if m and not saw_instruction:
                instructions.append(
                    DockerInstruction(
                        line=lineno, end_line=lineno, instruction=m.group(1),
                        args=m.group(2), raw=line, is_directive=True,
                    )
                )
                if m.group(1).lower() == "escape" and m.group(2) in {"\\", "`"}:
                    escape_char = m.group(2)
            i += 1
            continue

        first_token_match = re.match(r"\s*(\S+)", line)
        if not first_token_match:
            i += 1
            continue
        instruction = first_token_match.group(1)
        rest = line[first_token_match.end():]
        saw_instruction = True

        block_lines: list[str] = [line]
        end_line_no = lineno
        j = i

        # The escape parser directive controls Dockerfile continuations.
        while _ends_with_continuation(block_lines[-1], escape_char):
            j += 1
            if j >= n:
                errors.append(f"line {lineno}: unterminated line continuation")
                break
            block_lines.append(raw_lines[j])
            end_line_no = j + 1

        # Consume each heredoc body as part of its instruction.  In particular,
        # quoted delimiters (<<'EOF', <<\"EOF\") must not leave their bodies to
        # be mistaken for subsequent Dockerfile instructions.
        heredocs = _heredoc_delimiters("\n".join(block_lines))
        for terminator, allow_tabs in heredocs:
            terminated = False
            while j + 1 < n:
                j += 1
                next_line = raw_lines[j]
                block_lines.append(next_line)
                end_line_no = j + 1
                if _is_heredoc_terminator(next_line, terminator, allow_tabs):
                    terminated = True
                    break
            if not terminated:
                errors.append(f"line {lineno}: unterminated heredoc {terminator}")
                break

        i = j + 1
        args = _strip_continuations([rest] + block_lines[1:], escape_char)
        raw = "\n".join(block_lines)
        instructions.append(
            DockerInstruction(
                line=lineno, end_line=end_line_no, instruction=instruction,
                args=args, raw=raw, escape_char=escape_char,
            )
        )

    return ParsedDockerfile(
        instructions=instructions, raw_lines=raw_lines, parse_errors=errors,
    )


def _ends_with_continuation(line: str, escape_char: str = "\\") -> bool:
    stripped = line.rstrip()
    if not stripped.endswith(escape_char):
        return False
    escapes = 0
    for ch in reversed(stripped):
        if ch == escape_char:
            escapes += 1
        else:
            break
    return escapes % 2 == 1


def _strip_continuations(lines: list[str], escape_char: str = "\\") -> str:
    out: list[str] = []
    for ln in lines:
        s = ln.rstrip()
        if _ends_with_continuation(s, escape_char):
            s = s[:-1]
        out.append(s.strip())
    return " ".join(p for p in out if p)


def _heredoc_delimiters(text: str) -> list[tuple[str, bool]]:
    """Return Docker heredoc delimiters declared outside shell quotes.

    The Dockerfile frontend accepts both bare and quoted words after ``<<``.
    We intentionally keep this small lexer conservative: an apparent heredoc
    inside a shell string or a shell comment is ignored, while quoted words and
    ``<<-`` are retained so their body lines are never parsed as Docker syntax.
    """
    heredocs: list[tuple[str, bool]] = []
    quote: str | None = None
    i = 0
    start_of_word = True
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < len(text):
                i += 2
                continue
            if ch == quote:
                quote = None
            start_of_word = ch.isspace()
            i += 1
            continue

        if ch in {"'", '"'}:
            quote = ch
            start_of_word = False
            i += 1
            continue
        if ch == "#" and start_of_word:
            newline = text.find("\n", i)
            if newline == -1:
                break
            i = newline + 1
            start_of_word = True
            continue
        if text.startswith("<<", i):
            cursor = i + 2
            allow_tabs = cursor < len(text) and text[cursor] == "-"
            if allow_tabs:
                cursor += 1
            if cursor >= len(text):
                i += 2
                continue

            delimiter: str | None = None
            if text[cursor] in {"'", '"'}:
                delimiter_quote = text[cursor]
                end = text.find(delimiter_quote, cursor + 1)
                if end != -1 and end > cursor + 1:
                    delimiter = text[cursor + 1:end]
                    cursor = end + 1
            else:
                match = re.match(r"[A-Za-z_][A-Za-z0-9_.-]*", text[cursor:])
                if match:
                    delimiter = match.group(0)
                    cursor += len(delimiter)
            if delimiter is not None:
                heredocs.append((delimiter, allow_tabs))
                i = cursor
                start_of_word = False
                continue
        start_of_word = ch.isspace()
        i += 1
    return heredocs


def _is_heredoc_terminator(line: str, terminator: str, allow_tabs: bool) -> bool:
    if allow_tabs:
        line = line.lstrip("\t")
    return line == terminator


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
    except RecursionError as exc:
        return ParsedWorkflow(
            data={},
            line_map={},
            raw_lines=raw_lines,
            parse_errors=[f"workflow exceeds safe complexity limits: {exc}"],
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

    try:
        plain = _convert_with_lines(doc, (), line_map, [0])
    except (_WorkflowComplexityError, RecursionError) as exc:
        return ParsedWorkflow(
            data={},
            line_map={},
            raw_lines=raw_lines,
            parse_errors=[f"workflow exceeds safe complexity limits: {exc}"],
        )
    if not isinstance(plain, dict):
        plain = {}

    return ParsedWorkflow(
        data=plain, line_map=line_map, raw_lines=raw_lines, parse_errors=errors,
    )


def _convert_with_lines(
    node: Any,
    path: tuple,
    line_map: dict[tuple, tuple[int, int]],
    node_count: list[int],
    depth: int = 0,
) -> Any:
    from ruamel.yaml.comments import CommentedMap, CommentedSeq

    node_count[0] += 1
    if node_count[0] > MAX_WORKFLOW_NODES:
        raise _WorkflowComplexityError(
            f"expanded node count exceeds {MAX_WORKFLOW_NODES}"
        )
    if depth > MAX_WORKFLOW_DEPTH:
        raise _WorkflowComplexityError(
            f"nesting depth exceeds {MAX_WORKFLOW_DEPTH}"
        )

    if isinstance(node, CommentedMap):
        result: dict[str, Any] = {}
        for key, value in node.items():
            key_path = path + (key,)
            lc = _safe_lc(node, key)
            if lc is not None:
                line_map[key_path] = (lc[0] + 1, lc[1] + 1)
            result[key] = _convert_with_lines(
                value, key_path, line_map, node_count, depth + 1
            )
        return result

    if isinstance(node, CommentedSeq):
        seq: list[Any] = []
        for idx, value in enumerate(node):
            idx_path = path + (idx,)
            lc = _safe_lc_seq(node, idx)
            if lc is not None:
                line_map[idx_path] = (lc[0] + 1, lc[1] + 1)
            seq.append(
                _convert_with_lines(value, idx_path, line_map, node_count, depth + 1)
            )
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
