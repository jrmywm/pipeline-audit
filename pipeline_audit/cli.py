import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from pipeline_audit import __version__
from pipeline_audit.core.engine import scan_path
from pipeline_audit.core.reporter import render_markdown
from pipeline_audit.core.severity import Severity

console = Console()
err_console = Console(stderr=True)


@click.group()
@click.version_option(__version__, prog_name="pipeline-audit")
def main() -> None:
    """Headless DevSecOps pipeline audit - SAST for CI/CD configs."""


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--output", "-o", default="audit_report.md", show_default=True,
    help="Output report file (when --format=md).",
)
@click.option(
    "--format", "fmts", multiple=True, type=click.Choice(["md", "json", "sarif"]),
    default=("md",), show_default=True,
    help="Output format(s); may be repeated.",
)
@click.option(
    "--ruleset", "ruleset", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None,
    help="Override/merge ruleset YAML on top of bundled default.",
)
@click.option(
    "--fail-on", type=click.Choice(["Critical", "High", "Medium", "Low"]),
    default=None, help="Exit non-zero if any finding >= this severity.",
)
def scan(path: Path, output: str, fmts: tuple[str, ...], ruleset: Path | None, fail_on: str | None) -> None:
    """Scan PATH for DevSecOps misconfigurations in workflows + Dockerfiles."""
    root = Path(path).resolve()

    console.print(f"[bold]pipeline-audit[/bold] scanning [cyan]{root}[/cyan] ...")
    findings = scan_path(root, ruleset_path=ruleset)
    console.print(f"  found [bold]{len(findings)}[/bold] finding(s)")

    # Print a quick console summary table
    if findings:
        sev_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            sev_counts[f.severity.label] += 1
        table = Table(show_header=True, header_style="bold")
        table.add_column("Severity")
        table.add_column("Count", justify="right")
        for sev_label in ("Critical", "High", "Medium", "Low"):
            if sev_counts[sev_label] > 0:
                table.add_row(sev_label, str(sev_counts[sev_label]))
        console.print(table)

    # Emit requested formats
    wrote_outputs: list[str] = []
    for fmt in fmts:
        if fmt == "md":
            md = render_markdown(findings, root=root)
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(md, encoding="utf-8")
            wrote_outputs.append(str(out_path))
        elif fmt in ("json", "sarif"):
            err_console.print(
                f"[yellow]--format {fmt} not implemented yet (Stage 5b).[/yellow]"
            )

    for o in wrote_outputs:
        console.print(f"  report written to [cyan]{o}[/cyan]")

    # Exit-code policy
    if fail_on is not None:
        threshold = Severity.from_string(fail_on)
        if any(f.severity >= threshold for f in findings):
            err_console.print(
                f"[red]Failing: at least one finding >= {fail_on}.[/red]"
            )
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()