from __future__ import annotations

from pathlib import Path

import pytest

from scripts.validate import run_validation


def test_validation_rejects_missing_positive_rule_coverage(tmp_path: Path):
    expected = tmp_path / "expected.yaml"
    expected.write_text("snapshots:\n  empty: {}\n", encoding="utf-8")
    (tmp_path / "snapshots" / "empty").mkdir(parents=True)

    with pytest.raises(ValueError, match="no positive fixture coverage"):
        run_validation(expected, tmp_path / "snapshots")
