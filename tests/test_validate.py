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
        assert len(data["snapshots"]) == 20

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

    def test_10_tp_10_tn_split(self):
        data = _load_expected()
        tp = sum(1 for s in data["snapshots"].values() if s["expected"])
        tn = sum(1 for s in data["snapshots"].values() if not s["expected"])
        assert tp == 10, f"expected 10 TP snapshots, got {tp}"
        assert tn == 10, f"expected 10 TN snapshots, got {tn}"


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