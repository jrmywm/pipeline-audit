from __future__ import annotations

import json
import math
import re
from re import _parser as _sre_parser
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import jsonschema
from ruamel.yaml import YAML

from pipeline_audit.core.exceptions import RulesetSyntaxError, RulesetValidationError
from pipeline_audit.core.severity import Severity


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    target: str
    type: str
    match: dict[str, Any]
    remediation: str
    references: list[str] = field(default_factory=list)
    enabled: bool = True


SCHEMA_RESOURCE = "schema.json"
DEFAULT_RULESET_RESOURCE = "default.yaml"
MAX_REGEX_PATTERN_LENGTH = 4096

_yaml = YAML(typ="safe")


def _load_schema() -> dict[str, Any]:
    with resources.files("pipeline_audit.rulesets").joinpath(SCHEMA_RESOURCE).open("r", encoding="utf-8") as f:
        return json.load(f)


def _read_yaml_file(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = _yaml.load(f)
    except FileNotFoundError:
        raise RulesetSyntaxError(f"Ruleset file not found: {path}")
    except Exception as exc:
        raise RulesetSyntaxError(f"Failed to parse YAML {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise RulesetSyntaxError(f"Ruleset root must be a mapping; got {type(data).__name__} in {path}")
    return data


def _validate(data: dict[str, Any]) -> None:
    schema = _load_schema()
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        msgs = []
        for e in errors[:5]:
            loc = ".".join(str(p) for p in e.absolute_path) or "<root>"
            msgs.append(f"  {loc}: {e.message}")
        if len(errors) > 5:
            msgs.append(f"  ... and {len(errors) - 5} more error(s)")
        raise RulesetValidationError(f"Ruleset schema validation failed ({len(errors)} error(s)):\n" + "\n".join(msgs))
    _validate_semantics(data)


def _validate_semantics(data: dict[str, Any]) -> None:
    seen: set[str] = set()
    for rule in data.get("rules", []):
        rule_id = rule["id"]
        if rule_id in seen:
            raise RulesetValidationError(f"Duplicate rule id: {rule_id}")
        seen.add(rule_id)

        rule_type = rule["type"]
        target = rule["target"]
        match = rule["match"]
        if rule_type == "structural":
            structural = match.get("structural")
            if not isinstance(structural, dict):
                raise RulesetValidationError(f"{rule_id}: match.structural must be a mapping")
            kind = structural.get("kind")
            supported = {
                "dockerfile": {"missing_instruction"},
                "github_workflow": {
                    "uses_unpinned",
                    "permissions_write_all",
                    "privileged_pr_checkout_execution",
                    "workflow_run_artifact_execution",
                },
            }
            if kind not in supported[target]:
                raise RulesetValidationError(
                    f"{rule_id}: unsupported structural kind {kind!r} for {target}"
                )
            if kind == "missing_instruction" and not structural.get("instruction"):
                raise RulesetValidationError(
                    f"{rule_id}: missing_instruction requires an instruction"
                )
            sha_pattern = structural.get("sha_pattern")
            if sha_pattern is not None:
                _compile_pattern(rule_id, sha_pattern)
        elif rule_type == "regex":
            regex = match.get("regex")
            if not isinstance(regex, dict):
                raise RulesetValidationError(f"{rule_id}: match.regex must be a mapping")
            pattern = _compile_pattern(rule_id, regex.get("pattern"))
            if target == "dockerfile":
                capture_group = regex.get("capture_group", 1)
                if (
                    isinstance(capture_group, bool)
                    or not isinstance(capture_group, int)
                    or capture_group < 1
                ):
                    raise RulesetValidationError(
                        f"{rule_id}: capture_group must be a positive integer"
                    )
                if capture_group > pattern.groups:
                    raise RulesetValidationError(
                        f"{rule_id}: capture_group {capture_group} exceeds the pattern's {pattern.groups} group(s)"
                    )
                _validate_string_list(rule_id, regex, "exclude_names")
                min_entropy = regex.get("min_entropy", 0.0)
                if (
                    isinstance(min_entropy, bool)
                    or not isinstance(min_entropy, (int, float))
                    or min_entropy < 0
                    or (
                        isinstance(min_entropy, float)
                        and not math.isfinite(min_entropy)
                    )
                ):
                    raise RulesetValidationError(
                        f"{rule_id}: min_entropy must be a finite non-negative number"
                    )
            else:
                _validate_string_list(rule_id, regex, "scope_keys", required=True)
                _validate_string_list(rule_id, regex, "exclude_keys")


def _validate_string_list(
    rule_id: str,
    config: dict[str, Any],
    field_name: str,
    *,
    required: bool = False,
) -> None:
    value = config.get(field_name)
    if value is None:
        if required:
            raise RulesetValidationError(f"{rule_id}: {field_name} is required")
        return
    if (
        not isinstance(value, list)
        or (required and not value)
        or any(not isinstance(item, str) or not item.strip() for item in value)
    ):
        qualifier = "a non-empty list" if required else "a list"
        raise RulesetValidationError(
            f"{rule_id}: {field_name} must be {qualifier} of non-empty strings"
        )


def _compile_pattern(rule_id: str, pattern: Any) -> re.Pattern:
    if not isinstance(pattern, str) or not pattern:
        raise RulesetValidationError(f"{rule_id}: regex pattern must be a non-empty string")
    if len(pattern) > MAX_REGEX_PATTERN_LENGTH:
        raise RulesetValidationError(
            f"{rule_id}: regex pattern exceeds the {MAX_REGEX_PATTERN_LENGTH}-character limit"
        )
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise RulesetValidationError(f"{rule_id}: invalid regex pattern: {exc}") from exc
    _validate_regex_safety(rule_id, pattern)
    return compiled


def _validate_regex_safety(rule_id: str, pattern: str) -> None:
    """Reject regex constructs that can make Python's backtracking engine unsafe.

    Ruleset expressions run over repository-controlled text.  The standard
    library ``re`` engine has no timeout, so a short malicious expression can
    otherwise consume unbounded CPU.  This deliberately conservative check
    blocks the established catastrophic forms while retaining normal matching
    features such as groups, character classes, anchors, and disjoint choices.
    """
    parsed = _sre_parser.parse(pattern, 0)
    reason = _unsafe_regex_reason(parsed.data)
    if reason:
        raise RulesetValidationError(f"{rule_id}: unsafe regex pattern: {reason}")


def _unsafe_regex_reason(tokens: list[tuple[Any, Any]]) -> str | None:
    """Return an explanation when a parsed pattern has ambiguous repetition."""
    repeat_ops = {
        _sre_parser.MAX_REPEAT,
        _sre_parser.MIN_REPEAT,
        getattr(_sre_parser, "POSSESSIVE_REPEAT", object()),
    }
    groupref_ops = {
        _sre_parser.GROUPREF,
        _sre_parser.GROUPREF_EXISTS,
        getattr(_sre_parser, "GROUPREF_IGNORE", object()),
        getattr(_sre_parser, "GROUPREF_LOC_IGNORE", object()),
        getattr(_sre_parser, "GROUPREF_UNI_IGNORE", object()),
    }

    previous_unbounded: tuple[set[int] | None, bool] | None = None
    for op, value in tokens:
        if op in groupref_ops:
            return "backreferences are not supported"

        nested = _unsafe_regex_reason(_child_tokens(op, value))
        if nested:
            return nested

        if op in repeat_ops:
            minimum, maximum, repeated = value
            repeated_tokens = list(repeated)
            if _contains_ambiguous_repeat(repeated_tokens, repeat_ops):
                return "nested repetition can cause catastrophic backtracking"
            if maximum == _sre_parser.MAXREPEAT:
                branch_reason = _ambiguous_branch_reason(repeated_tokens)
                if branch_reason:
                    return branch_reason
                first = _first_characters(repeated_tokens)
                if (
                    previous_unbounded
                    and previous_unbounded[1]
                    and minimum == 0
                    and _first_sets_overlap(previous_unbounded[0], first)
                ):
                    return "adjacent unbounded repetitions can match the same text"
                previous_unbounded = (first, minimum == 0)
                continue

        if not _can_match_empty([(op, value)]):
            previous_unbounded = None
    return None


def _child_tokens(op: Any, value: Any) -> list[tuple[Any, Any]]:
    """Extract nested subpatterns for recursive safety checks."""
    if op is _sre_parser.SUBPATTERN:
        return list(value[-1])
    if op in {_sre_parser.MAX_REPEAT, _sre_parser.MIN_REPEAT, getattr(_sre_parser, "POSSESSIVE_REPEAT", object())}:
        return list(value[2])
    if op is _sre_parser.BRANCH:
        return [token for branch in value[1] for token in branch]
    if op in {_sre_parser.ASSERT, _sre_parser.ASSERT_NOT}:
        return list(value[1])
    return []


def _contains_ambiguous_repeat(tokens: list[tuple[Any, Any]], repeat_ops: set[Any]) -> bool:
    for op, value in tokens:
        if op in repeat_ops:
            minimum, maximum, _ = value
            if minimum != maximum:
                return True
        if _contains_ambiguous_repeat(_child_tokens(op, value), repeat_ops):
            return True
    return False


def _ambiguous_branch_reason(tokens: list[tuple[Any, Any]]) -> str | None:
    """Detect alternatives that a repeated group could partition ambiguously."""
    for op, value in tokens:
        if op is _sre_parser.BRANCH:
            branches = [list(branch) for branch in value[1]]
            if any(_can_match_empty(branch) for branch in branches):
                return "a repeated alternation contains an empty alternative"
            literal_branches = [_literal_sequence(branch) for branch in branches]
            if all(branch is not None for branch in literal_branches):
                for index, branch in enumerate(literal_branches):
                    if any(
                        branch.startswith(other) or other.startswith(branch)
                        for other in literal_branches[index + 1 :]
                    ):
                        return "a repeated alternation has overlapping alternatives"
            else:
                first_sets = [_first_characters(branch) for branch in branches]
                for index, first in enumerate(first_sets):
                    if any(_first_sets_overlap(first, other) for other in first_sets[index + 1 :]):
                        return "a repeated alternation has overlapping alternatives"
        child_reason = _ambiguous_branch_reason(_child_tokens(op, value))
        if child_reason:
            return child_reason
    return None


def _can_match_empty(tokens: list[tuple[Any, Any]]) -> bool:
    for op, value in tokens:
        if op in {_sre_parser.LITERAL, _sre_parser.NOT_LITERAL, _sre_parser.IN, _sre_parser.ANY, _sre_parser.CATEGORY}:
            return False
        if op is _sre_parser.SUBPATTERN and not _can_match_empty(list(value[-1])):
            return False
        if op in {_sre_parser.MAX_REPEAT, _sre_parser.MIN_REPEAT, getattr(_sre_parser, "POSSESSIVE_REPEAT", object())}:
            minimum, _, repeated = value
            if minimum and not _can_match_empty(list(repeated)):
                return False
        if op is _sre_parser.BRANCH and not any(_can_match_empty(list(branch)) for branch in value[1]):
            return False
    return True


def _literal_sequence(tokens: list[tuple[Any, Any]]) -> str | None:
    """Return a branch's fixed literal text, or None when it varies by input."""
    characters: list[str] = []
    for op, value in tokens:
        if op is _sre_parser.LITERAL:
            characters.append(chr(value))
        elif op is _sre_parser.SUBPATTERN:
            nested = _literal_sequence(list(value[-1]))
            if nested is None:
                return None
            characters.append(nested)
        elif op not in {_sre_parser.AT, _sre_parser.ASSERT, _sre_parser.ASSERT_NOT}:
            return None
    return "".join(characters)


def _first_characters(tokens: list[tuple[Any, Any]]) -> set[int] | None:
    """Return literal first characters, or None when the set is not finite."""
    result: set[int] = set()
    for op, value in tokens:
        if op is _sre_parser.LITERAL:
            result.add(value)
            return result
        if op is _sre_parser.IN:
            literals = {item for inner_op, item in value if inner_op is _sre_parser.LITERAL}
            if len(literals) != len(value):
                return None
            return result | literals
        if op in {_sre_parser.NOT_LITERAL, _sre_parser.ANY, _sre_parser.CATEGORY}:
            return None
        if op is _sre_parser.SUBPATTERN:
            first = _first_characters(list(value[-1]))
            if first is None:
                return None
            result.update(first)
            if not _can_match_empty(list(value[-1])):
                return result
            continue
        if op is _sre_parser.BRANCH:
            branch_firsts = [_first_characters(list(branch)) for branch in value[1]]
            if any(first is None for first in branch_firsts):
                return None
            for first in branch_firsts:
                result.update(first or set())
            if not any(_can_match_empty(list(branch)) for branch in value[1]):
                return result
            continue
        if op in {_sre_parser.MAX_REPEAT, _sre_parser.MIN_REPEAT, getattr(_sre_parser, "POSSESSIVE_REPEAT", object())}:
            minimum, _, repeated = value
            first = _first_characters(list(repeated))
            if first is None:
                return None
            result.update(first)
            if minimum:
                return result
    return result


def _first_sets_overlap(left: set[int] | None, right: set[int] | None) -> bool:
    """Unknown character classes are treated as overlapping for safety."""
    return left is None or right is None or bool(left & right)


def _rule_from_dict(r: dict[str, Any]) -> Rule:
    return Rule(
        id=r["id"],
        title=r["title"],
        severity=Severity.from_string(r["severity"]),
        target=r["target"],
        type=r["type"],
        match=r["match"],
        remediation=r["remediation"].strip(),
        references=list(r.get("references", [])),
        enabled=r.get("enabled", True),
    )


def load_ruleset_data(path: Path | None = None) -> dict[str, Any]:
    if path is None:
        with resources.files("pipeline_audit.rulesets").joinpath(DEFAULT_RULESET_RESOURCE).open("r", encoding="utf-8") as f:
            return _yaml.load(f)
    return _read_yaml_file(Path(path))


def load_ruleset(path: Path | None = None) -> list[Rule]:
    data = load_ruleset_data(path)
    _validate(data)
    rules_raw = data.get("rules", [])
    return [_rule_from_dict(r) for r in rules_raw]


def load_merged_ruleset(user_path: Path | None = None) -> list[Rule]:
    if user_path is None:
        return load_ruleset(None)

    default = load_ruleset_data(None)
    user = load_ruleset_data(user_path)
    _validate(user)

    by_id: dict[str, dict[str, Any]] = {}
    for r in default.get("rules", []):
        by_id[r["id"]] = r
    for r in user.get("rules", []):
        by_id[r["id"]] = r

    merged = {"version": user.get("version", default.get("version")), "metadata": {**default.get("metadata", {}), **user.get("metadata", {})}, "rules": list(by_id.values())}
    _validate(merged)
    return [_rule_from_dict(r) for r in merged["rules"]]
