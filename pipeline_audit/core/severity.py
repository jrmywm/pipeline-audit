from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1

    @classmethod
    def from_string(cls, label: str) -> Severity:
        normalized = label.strip().capitalize()
        for member in cls:
            if member.label == normalized:
                return member
        raise ValueError(f"Unknown severity: {label!r}")

    @property
    def label(self) -> str:
        return self.name.capitalize()

    def __ge__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return int(self) >= int(other)
        if isinstance(other, str):
            return self >= Severity.from_string(other)
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return int(self) > int(other)
        if isinstance(other, str):
            return self > Severity.from_string(other)
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return int(self) <= int(other)
        if isinstance(other, str):
            return self <= Severity.from_string(other)
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return int(self) < int(other)
        if isinstance(other, str):
            return self < Severity.from_string(other)
        return NotImplemented

    def __str__(self) -> str:
        return self.label