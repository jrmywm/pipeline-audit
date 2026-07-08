# Pipeline-Audit — Project Plan & Context

> **For AI assistants resuming this project:** read this file first. It contains
> all locked decisions, roadmap, and current status. Do not re-derive scope.

## What this is

A local CLI static-analysis tool that audits CI/CD configs (`.github/workflows/*.yml`
and Dockerfiles) for security misconfigurations. Rules are externalized in YAML.
Aggregates findings by file + severity → `audit_report.md` (plus JSON/SARIF).

## Status

**Stage 1 — ruleset loader — COMPLETE**

## Tech stack (locked)

- Python 3.11+
- Click (CLI), rich (terminal + MD rendering)
- ruamel.yaml (round-trip parsing preserves line numbers)
- jsonschema (validate ruleset at load time)
- pathspec (honor .gitignore during traversal)
- pytest (testing)
- Build backend: hatchling
- License: MIT

## Locked decisions

- Ruleset format: YAML (`pipeline_audit/rulesets/default.yaml`) validated by
  `pipeline_audit/rulesets/schema.json`. User `--ruleset` merges over default.
- Ground-truth labeling: AI drafts `tests/fixtures/expected.yaml`, user vetoes
  (Option B). Validation via `scripts/validate.py` against snapshots.
- Entropy threshold for secret detection: hardcoded `3.5` Shannon (Shannon on
  the value after `=` in ENV/ARG). Promote to tunable when first real FP dispute
  arises, or when multi-file context rules land, or when SARIF upload makes
  noise org-visible.
- Validation approach: snapshot fixtures (20 anonymized snippets), not live
  clones.
- Output formats: MD + JSON + SARIF from v1 (--format repeatable flag).
- Deferred to v1.1: GHA-R003 (pull_request_target) trigger+checkout rule.

## Ruleset scope (v1)

- DOCKER-R001  High      No USER instruction (runs as root)
- DOCKER-R002  Critical  Hardcoded secret in ENV/ARG (regex+entropy+allowlist)
- GHA-R001     Medium    Unpinned action (tag or branch, not 40-hex SHA)
- GHA-R002     High      `${{ secrets.* }}` interpolated into run/script body

## Build order

- [x] **Stage 0** — Skeleton: pyproject.toml, package tree, cli stub, PLAN.md,
      LICENSE, README.md. Gate: `pipx install -e .` + `pipeline-audit --help`
      works; `pytest` runs 0/0.
- [x] **Stage 1** — Ruleset loader + JSON Schema + `default.yaml` (all 4 rules
      present, real match configs). Gate: 17 tests pass; schema validation +
      merge + error paths all tested.
- [ ] **Stage 2** — Finder (pathspec-aware) + parsers (Dockerfile line-tuples,
      Workflow ruamel+line-map). Gate: fixture parse tests pass.
- [ ] **Stage 3** — Rule ABC + DockerStructuralRule (DOCKER-R001) + engine
      wiring. Gate: scan bad fixture → 1 High; good fixture → 0.
- [ ] **Stage 4** — WorkflowStructuralRule (GHA-R001). Gate: scan `@v4` → 1
      Medium; `@<40hex>` → 0; `@main` → 1.
- [ ] **Stage 5** — Reporter (MD) + `scan` command end-to-end. Gate: eyeball
      `audit_report.md` on bad fixture.
- [ ] **Stage 5b** — JSON + SARIF emitters; `--format` multi-flag. Gate: SARIF
      validates against schema; upload to throwaway repo Code Scanning succeeds.
- [ ] **Stage 6** — Snapshot fixtures (20 snippets) + `expected.yaml` (AI draft,
      user veto) + `scripts/validate.py`. Gate: ≥80% precision per rule.
- [ ] **Stage 7** — Add DOCKER-R002 (entropy+allowlist) and GHA-R002 (run-only
      context filter). Gate: re-validate ≥80% precision.
- [ ] **Stage 8** — Portfolio polish: README samples, example report, CI
      self-audit workflow, MIT license text finalized. Gate: fresh install +
      `scan .` clean on own repo.

## Validation repositories (snapshot sources)

1. Local fixture (`tests/fixtures/repo_bad/`) — known-bad, all rules fire
2. `github/super-linter` — known-good, should yield ~0 (hard FP gate)
3. `microsoft/vscode` — high volume, diverse actions
4. `nodejs/node`, `python/cpython`, `rust-lang/rust` — ecosystem diversity
5. `homebrew/homebrew-core`, `ansible/ansible` — adversarial for GHA-R002
6. A real PR diff (for future --diff mode)

## Pass gates for v1 tag

1. Hard gate: 0 findings on super-linter snapshot.
2. Soft gate: ≥80% precision per rule on snapshots (manual sample of 10/rule).
3. Demonstrability: ≥5 defensible findings on at least one real snapshot.
4. Regression: pytest covers ≥1 TP + ≥1 TN per rule.

## Open items / future

- v1.1: GHA-R003 (pull_request_target) rule
- v1.2: `--diff` mode (scan only changed files vs base ref)
- v1.2: `.pipeline-audit-ignore` suppression file (rationale-required)
- v2: tunable entropy threshold
- v2: structural dockerfile AST parser (replaces hand-rolled)