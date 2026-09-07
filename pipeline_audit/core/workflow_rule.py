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
    """

    KIND_USES_UNPINNED = "uses_unpinned"
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
        return []

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


__all__ = ["WorkflowStructuralRule"]
