#!/usr/bin/env python
"""
scripts/validate.py — Precision/recall validation harness for pipeline-audit.

Runs scan_path against every snapshot fixture and compares actual findings
to the ground truth in tests/fixtures/expected.yaml. Reports per-rule
precision, recall, and any mismatches.

Usage:
    python scripts/validate.py [--expected tests/fixtures/expected.yaml]
                                [--snapshots tests/fixtures/snapshots]
                                [--verbose]

Exit codes:
    0  all rules ≥ 80% precision AND ≥ 80% recall
    1  at least one rule below threshold
    2  harness error (e.g. cannot load expected.yaml)

Designed for dev use; not user-facing.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from pipeline_audit.core.engine import scan_path
from pipeline_audit.core.rule_loader import load_ruleset


SNAPSHOT_ROOT = Path(__file__).parent.parent / "tests" / "fixtures" / "snapshots"
DEFAULT_EXPECTED = Path(__file__).parent.parent / "tests" / "fixtures" / "expected.yaml"
PRECISION_THRESHOLD = 0.80
RECALL_THRESHOLD = 0.80


@dataclass
class MatchResult:
    snapshot: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    fp_details: list[str] = field(default_factory=list)
    fn_details: list[str] = field(default_factory=list)


def _load_expected(path: Path) -> dict[str, dict]:
    yaml = YAML(typ="safe")
    with path.open("r", encoding="utf-8") as f:
        data = yaml.load(f)
    return {name: snap for name, snap in data.get("snapshots", {}).items()}


def _normalize_findings(findings, snapshot_dir: Path) -> list[tuple[str, str, str]]:
    """Return list of (rule_id, file_basename, severity_label) tuples."""
    result = []
    for f in findings:
        result.append((f.rule_id, f.file.name, f.severity.label))
    return sorted(result)


def _expected_tuples(snapshot_data: dict) -> list[tuple[str, str, str]]:
    """Extract (rule_id, file_basename, severity) from expected entries."""
    expected = snapshot_data.get("expected", [])
    return sorted((e["rule_id"], e["file"], e["severity"]) for e in expected)


def _count_matches(
    expected_list: list[tuple],
    actual_list: list[tuple],
    snapshot: str,
) -> MatchResult:
    """Match expected vs actual using multiset semantics (sorted tuples)."""
    result = MatchResult(snapshot=snapshot)
    exp_copy = list(expected_list)
    act_copy = list(actual_list)

    for item in actual_list:
        if item in exp_copy:
            exp_copy.remove(item)
            result.tp += 1
        else:
            result.fp += 1
            result.fp_details.append(str(item))

    for item in exp_copy:
        result.fn += 1
        result.fn_details.append(str(item))

    return result


def run_validation(
    expected_path: Path, snapshots_dir: Path, verbose: bool = False
) -> dict[str, list[MatchResult]]:
    expected_data = _load_expected(expected_path)

    bundled_rule_ids = {rule.id for rule in load_ruleset() if rule.enabled}
    expected_rule_ids = {
        entry["rule_id"]
        for snapshot in expected_data.values()
        for entry in snapshot.get("expected", [])
    }
    missing_coverage = bundled_rule_ids - expected_rule_ids
    if missing_coverage:
        missing = ", ".join(sorted(missing_coverage))
        raise ValueError(f"Bundled rule(s) have no positive fixture coverage: {missing}")

    # Per-rule aggregation
    per_rule: dict[str, list[MatchResult]] = {
        rule_id: [] for rule_id in sorted(bundled_rule_ids)
    }
    for snapshot_name in sorted(expected_data.keys()):
        snapshot_dir = snapshots_dir / snapshot_name
        if not snapshot_dir.is_dir():
            raise FileNotFoundError(f"Snapshot directory not found: {snapshot_name}")

        snapshot_spec = expected_data[snapshot_name]
        expected_tuples = _expected_tuples(snapshot_spec)
        actual_findings = scan_path(snapshot_dir)
        actual_tuples = _normalize_findings(actual_findings, snapshot_dir)
        rule_ids = bundled_rule_ids | {
            t[0] for t in expected_tuples
        } | {t[0] for t in actual_tuples}
        matches: list[MatchResult] = []
        for rule_id in rule_ids:
            match = _count_matches(
                [item for item in expected_tuples if item[0] == rule_id],
                [item for item in actual_tuples if item[0] == rule_id],
                snapshot_name,
            )
            per_rule[rule_id].append(match)
            matches.append(match)

        status = "OK"
        if any(match.fp or match.fn for match in matches):
            status = "MISMATCH"
        if verbose or status == "MISMATCH":
            tp = sum(match.tp for match in matches)
            fp = sum(match.fp for match in matches)
            fn = sum(match.fn for match in matches)
            print(
                f"  [{status:8s}] {snapshot_name}: "
                f"TP={tp} FP={fp} FN={fn}"
            )
            for match in matches:
                for d in match.fp_details:
                    print(f"            FP: {d}")
                for d in match.fn_details:
                    print(f"            FN: {d}")

    return per_rule


def report(per_rule: dict[str, list[MatchResult]]) -> bool:
    print()
    print("=" * 70)
    print(f"{'Rule':<16} {'TP':>4} {'FP':>4} {'FN':>4} {'Precision':>10} {'Recall':>10}  Status")
    print("-" * 70)
    all_pass = True
    for rule_id, results in sorted(per_rule.items()):
        tp = sum(r.tp for r in results)
        fp = sum(r.fp for r in results)
        fn = sum(r.fn for r in results)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        status = "PASS"
        if precision < PRECISION_THRESHOLD:
            status = "FAIL(prec)"
            all_pass = False
        if recall < RECALL_THRESHOLD:
            status = "FAIL(rec)"
            all_pass = False
        print(
            f"{rule_id:<16} {tp:>4} {fp:>4} {fn:>4} "
            f"{precision:>10.1%} {recall:>10.1%}  {status}"
        )
    print("=" * 70)
    if all_pass:
        print("All rules pass precision + recall thresholds (>= 80%).")
    else:
        print("Some rules below threshold - tune rule or fix expected.yaml.")
    return all_pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate pipeline-audit precision/recall against snapshots"
    )
    parser.add_argument("--expected", type=Path, default=DEFAULT_EXPECTED)
    parser.add_argument("--snapshots", type=Path, default=SNAPSHOT_ROOT)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if not args.expected.is_file():
        print(f"Expected file not found: {args.expected}", file=sys.stderr)
        return 2
    if not args.snapshots.is_dir():
        print(f"Snapshots dir not found: {args.snapshots}", file=sys.stderr)
        return 2

    print(f"Validating against {args.snapshots}")
    print(f"Ground truth: {args.expected}")
    print()
    try:
        per_rule = run_validation(args.expected, args.snapshots, verbose=args.verbose)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Validation error: {exc}", file=sys.stderr)
        return 2
    ok = report(per_rule)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
