from __future__ import annotations


class PipelineAuditError(Exception):
    pass


class RulesetValidationError(PipelineAuditError):
    pass


class RulesetSyntaxError(PipelineAuditError):
    pass