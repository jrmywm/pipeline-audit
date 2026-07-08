from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Location:
    file: Path
    line: int | None = None
    col: int | None = None
    end_line: int | None = None
    snippet: str | None = None

    def __str__(self) -> str:
        s = str(self.file)
        if self.line is not None:
            s += f":{self.line}"
            if self.col is not None:
                s += f":{self.col}"
            if self.end_line is not None and self.end_line != self.line:
                s += f"-{self.end_line}"
        return s

    @property
    def display(self) -> str:
        return str(self)