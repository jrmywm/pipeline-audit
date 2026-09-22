# Pipeline Audit Report

_Generated: 2026-09-22 08:34:44 UTC_

## Summary

| Severity | Count |
|----------|-------|
| :red_circle: Critical | 1 |
| :orange_circle: High | 4 |
| :yellow_circle: Medium | 2 |
| :green_circle: Low | 0 |
| **Total** | **7** |

## Findings by File

### `.github/workflows/bad.yml`

_4 finding(s): :orange_circle: High: 2, :yellow_circle: Medium: 2_

| Severity | Rule | Line | Snippet |
|----------|------|------|---------|
| :orange_circle: High | `GHA-R002` | 12 | `${{ secrets.DEPLOY_TOKEN }}` |
| :orange_circle: High | `GHA-R002` | 13 | `${{ secrets.DEPLOY_TOKEN }}` |
| :yellow_circle: Medium | `GHA-R001` | 9 | `uses: actions/checkout@v4` |
| :yellow_circle: Medium | `GHA-R001` | 22 | `uses: actions/checkout@main` |

### `Dockerfile`

_2 finding(s): :red_circle: Critical: 1, :orange_circle: High: 1_

| Severity | Rule | Line | Snippet |
|----------|------|------|---------|
| :red_circle: Critical | `DOCKER-R002` | 5 | `ENV API_KEY=<redacted>` |
| :orange_circle: High | `DOCKER-R001` | 2 | `# syntax=docker/dockerfile:1.6` |

### `vendor/Dockerfile`

_1 finding(s): :orange_circle: High: 1_

| Severity | Rule | Line | Snippet |
|----------|------|------|---------|
| :orange_circle: High | `DOCKER-R001` | 1 | `FROM scratch` |

## Details

### :orange_circle: GHA-R002 &mdash; GitHub secret interpolated into executable script

- **File:** `.github/workflows/bad.yml:12`
- **Severity:** High
- **Rule ID:** GHA-R002
- **Snippet:** `${{ secrets.DEPLOY_TOKEN }}`
- **Remediation:** Pass secrets to the step via the `env:` mapping and reference them as `$VAR_NAME` inside the bash script. Never interpolate `${{ secrets.* }}` directly into a run block.
- **References:** <https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets-securely>

### :orange_circle: GHA-R002 &mdash; GitHub secret interpolated into executable script

- **File:** `.github/workflows/bad.yml:13`
- **Severity:** High
- **Rule ID:** GHA-R002
- **Snippet:** `${{ secrets.DEPLOY_TOKEN }}`
- **Remediation:** Pass secrets to the step via the `env:` mapping and reference them as `$VAR_NAME` inside the bash script. Never interpolate `${{ secrets.* }}` directly into a run block.
- **References:** <https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets-securely>

### :yellow_circle: GHA-R001 &mdash; Unpinned GitHub Action (uses tag or branch instead of SHA)

- **File:** `.github/workflows/bad.yml:9`
- **Severity:** Medium
- **Rule ID:** GHA-R001
- **Snippet:** `uses: actions/checkout@v4`
- **Remediation:** Pin the action to a full 40-character commit SHA instead of a tag or branch reference, e.g. `uses: actions/checkout@<40-hex-sha>`.
- **References:** <https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions>

### :yellow_circle: GHA-R001 &mdash; Unpinned GitHub Action (uses tag or branch instead of SHA)

- **File:** `.github/workflows/bad.yml:22`
- **Severity:** Medium
- **Rule ID:** GHA-R001
- **Snippet:** `uses: actions/checkout@main`
- **Remediation:** Pin the action to a full 40-character commit SHA instead of a tag or branch reference, e.g. `uses: actions/checkout@<40-hex-sha>`.
- **References:** <https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions>

### :red_circle: DOCKER-R002 &mdash; Hardcoded secret in ENV or ARG instruction

- **File:** `Dockerfile:5`
- **Severity:** Critical
- **Rule ID:** DOCKER-R002
- **Snippet:** `ENV API_KEY=<redacted>`
- **Remediation:** Move secrets out of the image layer. Inject at runtime via Vault, GitHub secrets, docker secrets, or SOPS-encrypted files.
- **References:** <https://docs.github.com/en/actions/security-guides/encrypted-secrets>

### :orange_circle: DOCKER-R001 &mdash; Final container stage may run as root

- **File:** `Dockerfile:2`
- **Severity:** High
- **Rule ID:** DOCKER-R001
- **Snippet:** `# syntax=docker/dockerfile:1.6`
- **Remediation:** Add a USER instruction near the end of the Dockerfile to specify a non-root user, e.g. `USER 1001` or `USER appuser`.
- **References:** <https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user>

### :orange_circle: DOCKER-R001 &mdash; Final container stage may run as root

- **File:** `vendor/Dockerfile:1`
- **Severity:** High
- **Rule ID:** DOCKER-R001
- **Snippet:** `FROM scratch`
- **Remediation:** Add a USER instruction near the end of the Dockerfile to specify a non-root user, e.g. `USER 1001` or `USER appuser`.
- **References:** <https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user>
