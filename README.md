# pipeline-audit

Headless DevSecOps **pipeline audit** — a lightweight SAST scanner for CI/CD
configurations. Detects common misconfigurations in GitHub Actions workflows
(`.github/workflows/*.yml`) and Dockerfiles, with an externalized YAML ruleset
so new signatures ship without code changes.

## Quickstart

```bash
pipx install pipeline-audit
pipeline-audit scan ./my-repo
```

Outputs `audit_report.md` by default. Use `--format json` or `--format sarif`
for CI ingestion.

See [PLAN.md](./PLAN.md) for full architecture and roadmap.

## Status

Pre-alpha. See [PLAN.md](./PLAN.md).