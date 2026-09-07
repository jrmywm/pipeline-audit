from __future__ import annotations


class PipelineAuditError(Exception):
    pass


class RulesetValidationError(PipelineAuditError):
    pass


class RulesetSyntaxError(PipelineAuditError):
    pass


class ScanInputError(PipelineAuditError):
    """Raised when a scan target cannot be analyzed safely and completely."""

    pass
