import sys
from pathlib import Path

import click
from rich.console import Console

from pipeline_audit import __version__

console = Console()
err_console = Console(stderr=True)


@click.group()
@click.version_option(__version__, prog_name="pipeline-audit")
def main() -> None:
    """Headless DevSecOps pipeline audit — SAST for CI/CD configs."""


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
    "--ruleset", type=click.Path(exists=True, dir_okay=False), default=None,
    help="Override/merge ruleset YAML on top of bundled default.",
)
@click.option(
    "--fail-on", type=click.Choice(["Critical", "High", "Medium", "Low"]),
    default=None, help="Exit non-zero if any finding >= this severity.",
)
def scan(path: Path, output: str, fmts: tuple[str, ...], ruleset: str | None, fail_on: str | None) -> None:
    """Scan PATH for DevSecOps misconfigurations in workflows + Dockerfiles."""
    err_console.print(
        "[yellow]pipeline-audit scan is not implemented yet.[/yellow] "
        "Stage 0 skeleton only - see PLAN.md for roadmap."
    )
    sys.exit(2)


if __name__ == "__main__":
    main()