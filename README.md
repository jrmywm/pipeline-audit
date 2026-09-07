# pipeline-audit

Headless DevSecOps **pipeline audit** — a lightweight SAST scanner for CI/CD
configurations. Detects common misconfigurations in GitHub Actions workflows
(`.github/workflows/*.yml`) and Dockerfiles, with externalized YAML configuration
for supported structural checks and regex signatures.

## Features

- **Externalized YAML ruleset** — add regex signatures or tune supported rules
- **4 built-in rules** covering root containers, hardcoded secrets, unpinned
  actions, and secret interpolation in run blocks
- **Three output formats** — Markdown (human review), JSON (CI ingestion),
  SARIF 2.1.0 (GitHub Code Scanning)
- **Nested `.gitignore`-aware traversal** — skips ignored paths throughout the tree, while still scanning tracked security configurations
- **Runtime-reference suppression + allowlist** for secret detection, with an
  optional Shannon entropy threshold
- **Exit-code policy** (`--fail-on`) for CI gating

## Rules

| Rule ID | Severity | Target | What it detects |
|---------|----------|--------|-----------------|
| `DOCKER-R001` | High | Dockerfile | Final stage lacks a statically non-root `USER` |
| `DOCKER-R002` | Critical | Dockerfile | Hardcoded secret in `ENV`/`ARG` (regex + allowlist + optional entropy threshold) |
| `GHA-R001` | Medium | Workflow | Unpinned action (tag/branch ref instead of 40-hex SHA) |
| `GHA-R002` | High | Workflow | `${{ secrets.* }}` interpolated into `run` or nested `script` bodies |

## Quickstart

```bash
pipx install pipeline-audit
pipeline-audit scan ./my-repo
```

Outputs `audit_report.md` by default.

## Usage

```bash
# Scan a repo, write Markdown report
pipeline-audit scan ./my-repo

# Emit JSON + SARIF alongside Markdown
pipeline-audit scan ./my-repo --format md --format json --format sarif

# Fail CI on any High or Critical finding
pipeline-audit scan ./my-repo --fail-on High

# Merge a custom ruleset on top of the bundled default
pipeline-audit scan ./my-repo --ruleset my-rules.yaml
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | `audit_report.md` | Output report path (stem for multi-format) |
| `--format` | `md` | Output format(s): `md`, `json`, `sarif` (repeatable) |
| `--ruleset` | bundled default | Merge custom ruleset YAML over default |
| `--fail-on` | _none_ | Exit non-zero if any finding ≥ severity |

## CI integration

Drop this into `.github/workflows/audit.yml` to self-audit on every push:

```yaml
name: audit
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  self-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pin-to-sha>
      - uses: actions/setup-python@<pin-to-sha>
        with:
          python-version: '3.11'
      - run: pip install pipeline-audit
      - run: pipeline-audit scan . --format sarif --fail-on Medium
      - uses: github/codeql-action/upload-sarif@<pin-to-sha>
        if: ${{ always() && hashFiles('audit_report.sarif') != '' && (github.event_name == 'push' || (github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.user.login != 'dependabot[bot]')) }}
        with:
          sarif_file: audit_report.sarif
```

See this repo's own [`audit.yml`](./.github/workflows/audit.yml) for a
fully-pinned working example.

## Example report

A sample report from a known-bad fixture repo is at
[`samples/example_report.md`](./samples/example_report.md) — 7 findings across
all 4 rules.

## Status

v1.0.0.

## License

MIT — see [LICENSE](./LICENSE).
