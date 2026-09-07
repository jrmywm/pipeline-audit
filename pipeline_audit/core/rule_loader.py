from __future__ import annotations

import json
import math
import re
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
                "github_workflow": {"uses_unpinned"},
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
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise RulesetValidationError(f"{rule_id}: invalid regex pattern: {exc}") from exc


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
