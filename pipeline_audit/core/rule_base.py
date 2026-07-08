from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pipeline_audit.core.location import Location
from pipeline_audit.core.parser import ParsedDockerfile, ParsedWorkflow
from pipeline_audit.core.rule_loader import Rule as RuleSpec
from pipeline_audit.core.severity import Severity


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    target: str
    location: Location
    snippet: str | None = None
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    @property
    def file(self) -> Path:
        return self.location.file

    @property
    def line(self) -> int | None:
        return self.location.line


class RuleHandler(ABC):
    """Base class for rule executors. Subclasses implement `match`."""

    @abstractmethod
    def match(
        self,
        spec: RuleSpec,
        *,
        file: Path,
        dockerfile: ParsedDockerfile | None = None,
        workflow: ParsedWorkflow | None = None,
        raw_text: str = "",
    ) -> list[Finding]:
        """Return zero or more Findings for this rule against the given file."""
        raise NotImplementedError


__all__ = ["Finding", "RuleHandler"]