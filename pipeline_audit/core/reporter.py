from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from pipeline_audit.core.rule_base import Finding
from pipeline_audit.core.severity import Severity


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
SEVERITY_EMOJI = {
    Severity.CRITICAL: ":red_circle:",
    Severity.HIGH: ":orange_circle:",
    Severity.MEDIUM: ":yellow_circle:",
    Severity.LOW: ":green_circle:",
}


def _summary_counts(findings: list[Finding]) -> Counter:
    counts: Counter = Counter()
    for f in findings:
        counts[f.severity] += 1
    return counts


def render_markdown(findings: list[Finding], *, root: Path | None = None) -> str:
    root = Path(root) if root is not None else None
    counts = _summary_counts(findings)
    total = len(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = []
    lines.append("# Pipeline Audit Report")
    lines.append("")
    lines.append(f"_Generated: {now}_")
    lines.append("")

    # ─── Summary ────────────────────────────────────────────────────────────
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in SEVERITY_ORDER:
        lines.append(f"| {SEVERITY_EMOJI[sev]} {sev.label} | {counts.get(sev, 0)} |")
    lines.append(f"| **Total** | **{total}** |")
    lines.append("")

    if total == 0:
        lines.append("No findings. The scanned paths appear clean.")
        lines.append("")
        return "\n".join(lines)

    # ─── Findings grouped by file ──────────────────────────────────────────
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        display = _display_path(f.file, root)
        by_file[display].append(f)

    lines.append("## Findings by File")
    lines.append("")

    for file_display in sorted(by_file.keys()):
        file_findings = by_file[file_display]
        file_findings.sort(
            key=lambda f: (-int(f.severity), f.location.line or 0)
        )
        lines.append(f"### `{file_display}`")
        lines.append("")
        lines.append(
            f"_{len(file_findings)} finding(s): "
            + ", ".join(
                f"{SEVERITY_EMOJI[s]} {s.label}: {sum(1 for f in file_findings if f.severity == s)}"
                for s in SEVERITY_ORDER
                if sum(1 for f in file_findings if f.severity == s) > 0
            )
            + "_"
        )
        lines.append("")

        lines.append("| Severity | Rule | Line | Snippet |")
        lines.append("|----------|------|------|---------|")
        for f in file_findings:
            line_cell = str(f.location.line) if f.location.line is not None else "-"
            snippet = (f.location.snippet or "").replace("`", "\\`").replace("|", "\\|")
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."
            lines.append(
                f"| {SEVERITY_EMOJI[f.severity]} {f.severity.label} | `{f.rule_id}` | {line_cell} | `{snippet}` |"
            )
        lines.append("")

    # ─── Details ────────────────────────────────────────────────────────────
    lines.append("## Details")
    lines.append("")
    for f in findings:
        display = _display_path(f.file, root)
        line_str = f":{f.location.line}" if f.location.line is not None else ""
        lines.append(f"### {SEVERITY_EMOJI[f.severity]} {f.rule_id} &mdash; {f.title}")
        lines.append("")
        lines.append(f"- **File:** `{display}{line_str}`")
        lines.append(f"- **Severity:** {f.severity.label}")
        lines.append(f"- **Rule ID:** {f.rule_id}")
        if f.location.snippet:
            esc = f.location.snippet.replace("`", "\\`")
            lines.append(f"- **Snippet:** `{esc}`")
        if f.remediation:
            lines.append(f"- **Remediation:** {f.remediation.strip()}")
        if f.references:
            refs = " ".join(f"<{r}>" for r in f.references)
            lines.append(f"- **References:** {refs}")
        lines.append("")

    return "\n".join(lines)


def _display_path(file_path: Path, root: Path | None) -> str:
    if root is None:
        return Path(file_path).as_posix()
    try:
        rel = Path(file_path).relative_to(root)
        return rel.as_posix()
    except ValueError:
        return Path(file_path).as_posix()


__all__ = ["render_markdown"]