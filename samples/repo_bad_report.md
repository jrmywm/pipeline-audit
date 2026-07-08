# Pipeline Audit Report

_Generated: 2026-07-08 15:41:34 UTC_

## Summary

| Severity | Count |
|----------|-------|
| :red_circle: Critical | 0 |
| :orange_circle: High | 2 |
| :yellow_circle: Medium | 2 |
| :green_circle: Low | 0 |
| **Total** | **4** |

## Findings by File

### `.github/workflows/bad.yml`

_2 finding(s): :yellow_circle: Medium: 2_

| Severity | Rule | Line | Snippet |
|----------|------|------|---------|
| :yellow_circle: Medium | `GHA-R001` | 9 | `uses: actions/checkout@v4` |
| :yellow_circle: Medium | `GHA-R001` | 22 | `uses: actions/checkout@main` |

### `Dockerfile`

_1 finding(s): :orange_circle: High: 1_

| Severity | Rule | Line | Snippet |
|----------|------|------|---------|
| :orange_circle: High | `DOCKER-R001` | 1 | `# syntax=docker/dockerfile:1.6` |

### `vendor/Dockerfile`

_1 finding(s): :orange_circle: High: 1_

| Severity | Rule | Line | Snippet |
|----------|------|------|---------|
| :orange_circle: High | `DOCKER-R001` | 1 | `FROM scratch` |

## Details

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

### :orange_circle: DOCKER-R001 &mdash; Container runs as root (no USER directive)

- **File:** `Dockerfile:1`
- **Severity:** High
- **Rule ID:** DOCKER-R001
- **Snippet:** `# syntax=docker/dockerfile:1.6`
- **Remediation:** Add a USER instruction near the end of the Dockerfile to specify a non-root user, e.g. `USER 1001` or `USER appuser`.
- **References:** <https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user>

### :orange_circle: DOCKER-R001 &mdash; Container runs as root (no USER directive)

- **File:** `vendor/Dockerfile:1`
- **Severity:** High
- **Rule ID:** DOCKER-R001
- **Snippet:** `FROM scratch`
- **Remediation:** Add a USER instruction near the end of the Dockerfile to specify a non-root user, e.g. `USER 1001` or `USER appuser`.
- **References:** <https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user>
