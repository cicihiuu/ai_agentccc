from __future__ import annotations

from typing import Any

from ai_security_agent.schemas import ModuleResult

from .backup_audit_extended.followup_context import (
    build_backup_audit_followup_context,
    build_sql_bypass_followup_context,
    build_sql_scan_followup_context,
    extract_followup_inputs,
    extract_high_risk_findings,
    extract_sql_bypass_assessments,
)


def build_summary_from_backup_result(result: ModuleResult | dict[str, Any]) -> dict[str, Any]:
    module_result = result if isinstance(result, ModuleResult) else ModuleResult.from_dict(result)
    return build_backup_audit_followup_context(module_result)


__all__ = [
    "build_backup_audit_followup_context",
    "build_sql_bypass_followup_context",
    "build_sql_scan_followup_context",
    "build_summary_from_backup_result",
    "extract_followup_inputs",
    "extract_high_risk_findings",
    "extract_sql_bypass_assessments",
]
