from __future__ import annotations

from ai_security_agent.schemas import ModuleResult

from .engine import run_backup_audit_extended as run_engine
from .followup_context import build_backup_audit_followup_context


def run(target: str, context: dict | None = None) -> ModuleResult:
    result = run_engine(target)
    followup_context = build_backup_audit_followup_context(result) if result.status == "ok" else {}
    logs = list(result.logs)
    if followup_context:
        logs.append("Generated skill-native followup_context for downstream modules.")
    return ModuleResult(
        module="backup_audit_extended",
        target=result.target,
        status=result.status,
        findings=list(result.findings),
        logs=logs,
        followup_context=followup_context,
        started_at=result.started_at,
        finished_at=result.finished_at,
        error=result.error,
    )


__all__ = [
    "run",
    "run_engine",
    "build_backup_audit_followup_context",
]
