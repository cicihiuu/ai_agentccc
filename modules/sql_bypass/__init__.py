from __future__ import annotations

from ai_security_agent.schemas import ModuleResult

from ai_security_agent.modules.common import is_local_or_lab_target, now_iso, target_scope_label
from ai_security_agent.integrations.sqlmap import run_sqlmap_command

from .adaptive_engine import SQLBypassAdaptiveEngine
from .evidence import build_findings, build_sql_bypass_followup_context


def run(target: str, context: dict | None = None) -> ModuleResult:
    started = now_iso()
    logs: list[str] = []
    context = context or {}

    if not is_local_or_lab_target(target):
        return ModuleResult(
            module="sql_bypass",
            target=target,
            status="skipped",
            findings=[],
            logs=["Target is outside the local/course-lab allowlist; SQL bypass assessment skipped."],
            started_at=started,
            finished_at=now_iso(),
            error="only localhost or course lab targets are allowed",
        )

    logs.append(f"Target scope: {target_scope_label(target)}")
    engine = SQLBypassAdaptiveEngine()
    candidates = engine.extract_sql_scan_candidates(context)
    if not candidates:
        return ModuleResult(
            module="sql_bypass",
            target=target,
            status="skipped",
            findings=[],
            logs=logs + ["No sql_scan followup_context candidates were available; sql_bypass requires upstream sql_scan output."],
            started_at=started,
            finished_at=now_iso(),
            error="sql_bypass requires sql_scan followup_context",
        )

    logs.append(f"Loaded SQL bypass candidates from sql_scan followup_context: {len(candidates)}")
    records = engine.run(candidates)
    _execute_sqlmap(records, context, logs)
    logs.append(f"Generated SQL bypass assessment records: {len(records)}")
    signal_count = sum(1 for record in records if record.has_assessment_signal)
    logs.append(f"Bypass-oriented assessment signals: {signal_count}")
    findings = build_findings(target, records)
    return ModuleResult(
        module="sql_bypass",
        target=target,
        status="ok",
        findings=findings,
        logs=logs,
        followup_context=build_sql_bypass_followup_context(records),
        started_at=started,
        finished_at=now_iso(),
    )


def _execute_sqlmap(records, context: dict | None, logs: list[str]) -> int:
    profile_config = dict((context or {}).get("profile_config", {})) if isinstance((context or {}).get("profile_config", {}), dict) else {}
    sqlmap_config = dict(profile_config.get("sqlmap", {})) if isinstance(profile_config.get("sqlmap", {}), dict) else {}
    if not sqlmap_config.get("enabled"):
        return 0
    binary = str(sqlmap_config.get("binary", "sqlmap")).strip() or "sqlmap"
    timeout_seconds = float(sqlmap_config.get("timeout_seconds", 45.0) or 45.0)
    safe_mode = bool(sqlmap_config.get("safe_mode", True))
    allow_dump = bool(sqlmap_config.get("allow_dump", False))
    executed = 0
    for record in records[:2]:
        command_info = record.sqlmap_command
        command = [str(item) for item in command_info.get("primary_command", []) if str(item).strip()]
        if not command:
            continue
        if command[0].lower() == "sqlmap":
            command = command[1:]
        if safe_mode and not allow_dump:
            command = [item for item in command if item not in {"--dump", "--dbs", "--tables"}]
        result = run_sqlmap_command(command, binary=binary, timeout_seconds=timeout_seconds)
        command_info["execution_result"] = {
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "parsed": dict(result.parsed),
            "stdout_excerpt": (result.stdout or "")[:1200],
            "stderr_excerpt": (result.stderr or "")[:800],
        }
        executed += 1
        logs.append(
            f"sqlmap executed for {record.candidate.parameter}: rc={result.returncode}, confirmed={bool(result.parsed.get('injection_confirmed', False))}"
        )
    return executed


__all__ = ["run"]
