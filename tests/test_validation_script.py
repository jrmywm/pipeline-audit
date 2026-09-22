from __future__ import annotations

from pathlib import Path

import pytest

from scripts import validate
from scripts.validate import run_validation


def test_validation_rejects_missing_positive_rule_coverage(tmp_path: Path):
    expected = tmp_path / "expected.yaml"
    expected.write_text("snapshots:\n  empty: {}\n", encoding="utf-8")
    (tmp_path / "snapshots" / "empty").mkdir(parents=True)

    with pytest.raises(ValueError, match="no positive fixture coverage"):
        run_validation(expected, tmp_path / "snapshots")


@pytest.mark.parametrize(
    "contents",
    [
        "snapshots: [\n",
        "- not-a-mapping\n",
        "snapshots: []\n",
    ],
)
def test_main_returns_harness_error_for_malformed_expected_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, contents: str
):
    expected = tmp_path / "expected.yaml"
    expected.write_text(contents, encoding="utf-8")
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    monkeypatch.setattr(
        "sys.argv",
        ["validate.py", "--expected", str(expected), "--snapshots", str(snapshots)],
    )

    assert validate.main() == 2
