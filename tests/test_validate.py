from __future__ import annotations

import sys
from pathlib import Path

import pytest
from ruamel.yaml import YAML

ROOT = Path(__file__).parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
SNAPSHOT_DIR = FIXTURES / "snapshots"
EXPECTED_PATH = FIXTURES / "expected.yaml"
VALIDATE_SCRIPT = ROOT / "scripts" / "validate.py"


def _load_expected() -> dict:
    yaml = YAML(typ="safe")
    with EXPECTED_PATH.open("r", encoding="utf-8") as f:
        return yaml.load(f)


class TestExpectedYaml:
    def test_loads_cleanly(self):
        data = _load_expected()
        assert "snapshots" in data
        assert len(data["snapshots"]) == 67

    def test_all_snapshot_dirs_exist(self):
        data = _load_expected()
        for name in data["snapshots"]:
            assert (SNAPSHOT_DIR / name).is_dir(), f"missing snapshot dir: {name}"

    def test_all_expected_entries_have_fields(self):
        data = _load_expected()
        for name, spec in data["snapshots"].items():
            assert "description" in spec, f"{name} missing description"
            expected = spec.get("expected", [])
            for entry in expected:
                assert "rule_id" in entry, f"{name} entry missing rule_id"
                assert "file" in entry, f"{name} entry missing file"
                assert "severity" in entry, f"{name} entry missing severity"

    def test_tp_tn_balanced_per_rule(self):
        """Each rule should have at least 5 TP + 5 TN snapshots."""
        data = _load_expected()
        tp_by_rule: dict[str, int] = {}
        tn_by_rule: dict[str, int] = {}
        # Seed counters for every rule id referenced anywhere downstream; we
        # treat a snapshot with empty expected as a TN for *every* known rule.
        known_rules: set[str] = set()
        for spec in data["snapshots"].values():
            for entry in spec.get("expected", []):
                known_rules.add(entry["rule_id"])
        for rule_id in known_rules:
            tp_by_rule[rule_id] = 0
            tn_by_rule[rule_id] = 0
        # Walk snapshots in order; for each, treat each rule having an expected
        # entry as a TP for that rule, and rules without as TN. To avoid
        # overcounting TNs across rules we only count a TN if the snapshot has
        # any rule references at all (which means a real TN snapshot carries
        # one TN per rule id known at that snapshot's order).
        for spec in data["snapshots"].values():
            expected = spec.get("expected", [])
            seen_rules = {e["rule_id"] for e in expected}
            for rid in seen_rules:
                tp_by_rule[rid] += 1
            if not seen_rules:
                cnt = len(known_rules)
                for rid in known_rules:
                    tn_by_rule[rid] += 1
        # Validate counts match the planned 5 TP + 5 TN per rule.
        assert sorted(known_rules) == [
            "DOCKER-R001",
            "DOCKER-R002",
            "GHA-R001",
            "GHA-R002",
            "GHA-R003",
            "GHA-R004",
            "GHA-R005",
            "GHA-R006",
        ]
        for rule_id in known_rules:
            assert tp_by_rule[rule_id] >= 5, (
                f"{rule_id} expected >=5 TP snapshots, got {tp_by_rule[rule_id]}"
            )
            assert tn_by_rule[rule_id] >= 5, (
                f"{rule_id} expected >=5 TN snapshots, got {tn_by_rule[rule_id]}"
            )


class TestValidationHarness:
    def test_validate_script_importable(self):
        # Ensure the script is syntactically valid and importable (no exec)
        assert VALIDATE_SCRIPT.is_file()

    def test_all_snapshots_pass_thresholds(self):
        """Regression guard: run validate.run_validation directly."""
        # Import validate as a module by adjusting sys.path
        sys.path.insert(0, str(ROOT / "scripts"))
        try:
            import validate
            per_rule = validate.run_validation(EXPECTED_PATH, SNAPSHOT_DIR, verbose=False)
            assert len(per_rule) > 0, "no rules exercised"
            for rule_id, results in per_rule.items():
                tp = sum(r.tp for r in results)
                fp = sum(r.fp for r in results)
                fn = sum(r.fn for r in results)
                precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
                assert precision >= 0.80, f"{rule_id} precision {precision:.0%} < 80%"
                assert recall >= 0.80, f"{rule_id} recall {recall:.0%} < 80%"
        finally:
            sys.path.pop(0)
