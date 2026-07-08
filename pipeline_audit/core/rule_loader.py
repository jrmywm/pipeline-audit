from __future__ import annotations

import json
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