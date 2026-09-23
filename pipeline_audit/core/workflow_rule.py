from __future__ import annotations

import re
from pathlib import Path

from pipeline_audit.core.location import Location
from pipeline_audit.core.parser import ParsedWorkflow
from pipeline_audit.core.rule_base import Finding, RuleHandler
from pipeline_audit.core.rule_loader import Rule as RuleSpec


class WorkflowStructuralRule(RuleHandler):
    """Handles `type: structural` rules targeting GitHub Actions workflows.

    Recognized `match.structural.kind` values:
      - uses_unpinned: fires on every `uses:` value that does NOT match the
        `sha_pattern` regex in the ruleset (defaults to a 40-char hex SHA).
        Tags (e.g. `@v4`) and branches (e.g. `@main`) trigger findings;
        full commit SHAs pass.
      - permissions_write_all: fires on explicit workflow-level or job-level
        scalar `permissions: write-all` declarations.
      - privileged_pr_checkout_execution: detects execution of an untrusted
        pull request head after checking it out in a pull_request_target job.
      - workflow_run_artifact_execution: detects execution of downloaded
        artifacts in workflow_run workflows.
    """

    KIND_USES_UNPINNED = "uses_unpinned"
    KIND_PERMISSIONS_WRITE_ALL = "permissions_write_all"
    KIND_PRIVILEGED_PR_CHECKOUT_EXECUTION = "privileged_pr_checkout_execution"
    KIND_WORKFLOW_RUN_ARTIFACT_EXECUTION = "workflow_run_artifact_execution"
    DEFAULT_SHA_PATTERN = r"^[0-9a-f]{40}$"

    def match(
        self,
        spec: RuleSpec,
        *,
        file: Path,
        dockerfile=None,
        workflow: ParsedWorkflow | None = None,
        raw_text: str = "",
    ) -> list[Finding]:
        if workflow is None:
            return []

        kind = spec.match.get("structural", {}).get("kind")
        if kind == self.KIND_USES_UNPINNED:
            return self._uses_unpinned(spec, file, workflow)
        if kind == self.KIND_PERMISSIONS_WRITE_ALL:
            return self._permissions_write_all(spec, file, workflow)
        if kind == self.KIND_PRIVILEGED_PR_CHECKOUT_EXECUTION:
            return self._privileged_pr_checkout_execution(spec, file, workflow)
        if kind == self.KIND_WORKFLOW_RUN_ARTIFACT_EXECUTION:
            return self._workflow_run_artifact_execution(spec, file, workflow)
        return []

    def _privileged_pr_checkout_execution(
        self, spec: RuleSpec, file: Path, wf: ParsedWorkflow
    ) -> list[Finding]:
        if not _has_pull_request_target(wf.data.get("on")):
            return []
        jobs = wf.data.get("jobs", {})
        if not isinstance(jobs, dict):
            return []

        findings: list[Finding] = []
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            for idx, step in enumerate(steps):
                if not isinstance(step, dict) or not _is_checkout(step.get("uses")):
                    continue
                risky_path, snippet = _untrusted_checkout_input(step.get("with"))
                if risky_path is None:
                    continue
                if not _has_later_execution_sink(steps, idx):
                    continue
                findings.append(
                    Finding(
                        rule_id=spec.id,
                        title=spec.title,
                        severity=spec.severity,
                        target=spec.target,
                        location=Location(
                            file=file,
                            line=wf.line_of("jobs", job_name, "steps", idx, "with", risky_path),
                            snippet=snippet,
                        ),
                        remediation=spec.remediation,
                        references=list(spec.references),
                    )
                )
        return findings

    def _workflow_run_artifact_execution(
        self, spec: RuleSpec, file: Path, wf: ParsedWorkflow
    ) -> list[Finding]:
        if not _has_workflow_run(wf.data.get("on")):
            return []
        jobs = wf.data.get("jobs", {})
        if not isinstance(jobs, dict):
            return []

        findings: list[Finding] = []
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            downloads: list[tuple[int, str]] = []
            for idx, step in enumerate(steps):
                if not isinstance(step, dict) or not _is_download_artifact(step.get("uses")):
                    continue
                values = step.get("with")
                if not isinstance(values, dict):
                    continue
                run_id = values.get("run-id")
                github_token = values.get("github-token")
                path = _simple_relative_artifact_path(values.get("path"))
                if (
                    path is not None
                    and _is_workflow_run_id(run_id)
                    and isinstance(github_token, str)
                    and bool(github_token.strip())
                ):
                    downloads.append((idx, path))

            for idx, step in enumerate(steps):
                if not isinstance(step, dict) or not isinstance(step.get("run"), str):
                    continue
                if not any(
                    download_idx < idx and _executes_artifact_path(step["run"], artifact_path)
                    for download_idx, artifact_path in downloads
                ):
                    continue
                findings.append(
                    Finding(
                        rule_id=spec.id,
                        title=spec.title,
                        severity=spec.severity,
                        target=spec.target,
                        location=Location(
                            file=file,
                            line=wf.line_of("jobs", job_name, "steps", idx, "run"),
                            snippet="run: executes a file from the downloaded artifact",
                        ),
                        remediation=spec.remediation,
                        references=list(spec.references),
                    )
                )
        return findings

    def _permissions_write_all(
        self, spec: RuleSpec, file: Path, wf: ParsedWorkflow
    ) -> list[Finding]:
        """Find explicit broad permissions at supported workflow locations.

        GitHub Actions permits ``permissions`` at the workflow root and on
        individual jobs.  Looking only at those paths avoids treating text in
        steps, environment variables, or arbitrary mappings as declarations.
        Each explicit declaration is reported independently; permission
        inheritance is left to GitHub's semantics rather than inferred here.
        """
        findings: list[Finding] = []

        def check(value, path: tuple) -> None:
            if not isinstance(value, str) or value.casefold() != "write-all":
                return
            findings.append(
                Finding(
                    rule_id=spec.id,
                    title=spec.title,
                    severity=spec.severity,
                    target=spec.target,
                    location=Location(
                        file=file,
                        line=wf.line_of(*path),
                        snippet=f"permissions: {value}",
                    ),
                    remediation=spec.remediation,
                    references=list(spec.references),
                )
            )

        check(wf.data.get("permissions"), ("permissions",))

        jobs = wf.data.get("jobs", {})
        if not isinstance(jobs, dict):
            return findings
        for job_name, job in jobs.items():
            if isinstance(job, dict):
                check(job.get("permissions"), ("jobs", job_name, "permissions"))
        return findings

    def _uses_unpinned(
        self, spec: RuleSpec, file: Path, wf: ParsedWorkflow
    ) -> list[Finding]:
        sha_pattern_src = spec.match.get("structural", {}).get(
            "sha_pattern", self.DEFAULT_SHA_PATTERN
        )
        sha_re = re.compile(sha_pattern_src)

        findings: list[Finding] = []
        jobs = wf.data.get("jobs", {})
        if not isinstance(jobs, dict):
            return findings

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            job_uses = job.get("uses")
            if isinstance(job_uses, str):
                self._check_uses(
                    spec,
                    file=file,
                    wf=wf,
                    uses=job_uses,
                    path=("jobs", job_name, "uses"),
                    sha_re=sha_re,
                    findings=findings,
                )
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            for idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses")
                if not uses or not isinstance(uses, str):
                    continue
                self._check_uses(
                    spec,
                    file=file,
                    wf=wf,
                    uses=uses,
                    path=("jobs", job_name, "steps", idx, "uses"),
                    sha_re=sha_re,
                    findings=findings,
                )

        return findings

    def _check_uses(
        self,
        spec: RuleSpec,
        *,
        file: Path,
        wf: ParsedWorkflow,
        uses: str,
        path: tuple,
        sha_re: re.Pattern,
        findings: list[Finding],
    ) -> None:
        ref = _ref_from_uses(uses)
        if ref is None or sha_re.match(ref):
            return
        findings.append(
            Finding(
                rule_id=spec.id,
                title=spec.title,
                severity=spec.severity,
                target=spec.target,
                location=Location(
                    file=file,
                    line=wf.line_of(*path),
                    snippet=f"uses: {uses}",
                ),
                remediation=spec.remediation,
                references=list(spec.references),
            )
        )

def _ref_from_uses(uses: str) -> str | None:
    """Extract the @ref portion from an action reference.

    `actions/checkout@v4`      -> `v4`
    `actions/checkout@main`   -> `main`
    `actions/checkout@<sha>`  -> `<sha>`
    `actions/checkout`         -> None (no ref at all; flag)
    `./local-action`           -> None (local actions exempt)
    `docker://image:tag`       -> None (docker actions exempt)
    """
    if uses.startswith("./") or uses.startswith("docker://"):
        return None
    if "@" not in uses:
        return ""
    return uses.rsplit("@", 1)[-1]


def _has_pull_request_target(trigger) -> bool:
    if isinstance(trigger, str):
        return trigger.casefold() == "pull_request_target"
    if isinstance(trigger, list):
        return any(
            isinstance(item, str) and item.casefold() == "pull_request_target"
            for item in trigger
        )
    if isinstance(trigger, dict):
        return any(
            isinstance(event, str) and event.casefold() == "pull_request_target"
            for event in trigger
        )
    return False


def _has_workflow_run(trigger) -> bool:
    if isinstance(trigger, str):
        return trigger.casefold() == "workflow_run"
    if isinstance(trigger, list):
        return any(isinstance(item, str) and item.casefold() == "workflow_run" for item in trigger)
    if isinstance(trigger, dict):
        return any(isinstance(event, str) and event.casefold() == "workflow_run" for event in trigger)
    return False


def _is_workflow_run_id(value) -> bool:
    return isinstance(value, str) and re.sub(r"\s+", "", value).casefold() == (
        "${{github.event.workflow_run.id}}"
    )


def _is_download_artifact(uses) -> bool:
    if not isinstance(uses, str):
        return False
    return uses.split("@", 1)[0].casefold() == "actions/download-artifact"


def _simple_relative_artifact_path(value) -> str | None:
    if not isinstance(value, str) or not value or "${{" in value or "}}" in value:
        return None
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return None
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        return None
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        return None
    return "/".join(parts)


def _executes_artifact_path(run: str, artifact_path: str) -> bool:
    # Restrict matching to explicit, direct invocation forms. This deliberately
    # excludes shell variables, globs, redirections, and generic file reads.
    path = re.escape(artifact_path)
    file = r"[A-Za-z0-9_.-]+"
    patterns = (
        rf"(?:^|[;&|]\s*)(?:bash|sh|python|python3|node)\s+(?:\./)?{path}/{file}(?=\s|$)",
        rf"(?:^|[;&|]\s*)(?:source|\.)\s+(?:\./)?{path}/{file}(?=\s|$)",
        rf"(?:^|[;&|]\s*)\./{path}/{file}(?=\s|$)",
    )
    return any(re.search(pattern, run, flags=re.IGNORECASE | re.MULTILINE) for pattern in patterns)


def _is_checkout(uses) -> bool:
    if not isinstance(uses, str):
        return False
    action = uses.split("@", 1)[0]
    return action.casefold() == "actions/checkout"


def _untrusted_checkout_input(with_values) -> tuple[str | None, str | None]:
    if not isinstance(with_values, dict):
        return None, None
    ref = with_values.get("ref")
    if isinstance(ref, str):
        compact = re.sub(r"\s+", "", ref).casefold()
        if compact in {
            "${{github.event.pull_request.head.sha}}",
            "${{github.event.pull_request.head.ref}}",
        } or re.fullmatch(
            r"refs/pull/\$\{\{github\.event\.pull_request\.number\}\}/merge",
            compact,
        ):
            if "head.sha" in compact:
                return "ref", "with.ref: ${{ github.event.pull_request.head.sha }}"
            if "head.ref" in compact:
                return "ref", "with.ref: ${{ github.event.pull_request.head.ref }}"
            return "ref", "with.ref: refs/pull/${{ github.event.pull_request.number }}/merge"
    repository = with_values.get("repository")
    if isinstance(repository, str) and re.sub(r"\s+", "", repository).casefold() == (
        "${{github.event.pull_request.head.repo.full_name}}"
    ):
        return "repository", "with.repository: ${{ github.event.pull_request.head.repo.full_name }}"
    return None, None


def _has_later_execution_sink(steps: list, checkout_index: int) -> bool:
    for step in steps[checkout_index + 1:]:
        if not isinstance(step, dict):
            continue
        if isinstance(step.get("run"), str):
            return True
        uses = step.get("uses")
        if isinstance(uses, str) and uses.startswith("./"):
            return True
    return False


__all__ = ["WorkflowStructuralRule"]
