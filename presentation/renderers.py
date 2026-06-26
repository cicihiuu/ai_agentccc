from __future__ import annotations

from typing import Any

from ai_security_agent.i18n import provider_env_help

from .i18n import to_user_label, to_user_message


def _planning_status(events: list[dict[str, Any]]) -> str:
    deferred = any(event.get("event_type") == "planning_deferred" for event in events)
    planning_done = any(event.get("event_type") == "llm_plan_enrichment_completed" for event in events)
    if deferred and not planning_done:
        return "等待首次执行时进行 LLM 规划增强"
    if planning_done:
        return "LLM 规划增强已完成"
    return "规则规划已创建"


def _execution_state_label(value: str) -> str:
    return {
        "ready": "可继续执行",
        "waiting_confirmation": "等待人工确认",
        "stalled": "暂无可执行步骤",
        "complete": "任务已完成",
    }.get(value, value)


def _provider_help(provider_name: str, provider_status: str) -> str:
    if provider_status not in {"missing_env", "fallback"}:
        return ""
    if provider_name == "deepseek":
        return provider_env_help("DEEPSEEK_API_KEY")
    if provider_name == "hunyuan":
        return provider_env_help("TOKENHUB_API_KEY")
    return ""


def build_ui_view_model(snapshot: dict[str, Any]) -> dict[str, Any]:
    raw_events = list(snapshot.get("events", []))
    raw_plan = snapshot.get("plan") or {}
    raw_steps = raw_plan.get("steps", []) if isinstance(raw_plan, dict) else []

    plan_steps: list[dict[str, Any]] = []
    for step in raw_steps:
        risk_level = str(step.get("risk_level", "low") or "low")
        reason = to_user_message(str(step.get("reason", "")), fallback="")
        plan_steps.append(
            {
                "step_id": str(step.get("step_id", "")),
                "module": str(step.get("module", "")),
                "skill": str(step.get("skill", "")),
                "status": str(step.get("status", "")),
                "status_label": to_user_label("status", str(step.get("status", ""))),
                "risk_level": risk_level,
                "risk_label": to_user_label("risk", risk_level),
                "reason": reason,
                "confirmed": bool(step.get("confirmed", False)),
            }
        )

    findings: list[dict[str, Any]] = []
    for finding in snapshot.get("findings", []):
        findings.append(
            {
                **finding,
                "severity_label": to_user_label("severity", str(finding.get("severity", ""))),
                "title_label": to_user_message(str(finding.get("title", ""))),
                "location_label": to_user_message(str(finding.get("location", "")), fallback="未记录"),
                "evidence_label": to_user_message(str(finding.get("evidence", "")), fallback="未记录"),
                "recommendation_label": to_user_message(str(finding.get("recommendation", "")), fallback="未提供建议"),
                "verified_label": "是" if finding.get("verified") else "否",
            }
        )

    advice_timeline: list[dict[str, Any]] = []
    for item in snapshot.get("advice_timeline", []):
        advice_timeline.append(
            {
                **item,
                "stage_label": to_user_label("stage", str(item.get("stage", ""))),
                "title_label": to_user_message(str(item.get("title", ""))),
                "content_label": to_user_message(str(item.get("content", ""))),
            }
        )

    events: list[dict[str, Any]] = []
    for event in raw_events:
        events.append(
            {
                **event,
                "stage_label": to_user_label("stage", str(event.get("stage", ""))),
                "event_type_label": to_user_label("event_type", str(event.get("event_type", ""))),
                "message_label": to_user_message(str(event.get("message", ""))),
            }
        )

    run_model_context = dict(snapshot.get("run_model_context", {}))
    requested_mode = str(run_model_context.get("requested_agent_mode", "rule_based") or "rule_based")
    effective_mode = str(run_model_context.get("effective_agent_mode", requested_mode) or requested_mode)
    provider_status = str(run_model_context.get("provider_status", "disabled") or "disabled")
    provider_name = str(run_model_context.get("provider_name", "")).strip()
    provider_message = to_user_message(str(run_model_context.get("provider_message", "")), fallback="")
    provider_help = _provider_help(provider_name, provider_status)

    planning_status_label = _planning_status(raw_events)
    execution_state = str(snapshot.get("execution_state", "stalled") or "stalled")
    execution_message = to_user_message(str(snapshot.get("execution_message", "")), fallback="")
    execution_state_label = _execution_state_label(execution_state)

    auto_modules: list[dict[str, str]] = []
    approval_modules: list[dict[str, str]] = []
    for step in plan_steps:
        item = {
            "module": step["module"],
            "risk_label": step["risk_label"],
            "status_label": step["status_label"],
            "reason": step["reason"] or ("等待人工确认" if step["risk_level"] == "high" else ""),
        }
        if step["risk_level"] == "high":
            approval_modules.append(item)
        else:
            auto_modules.append(item)

    status_cards = [
        {
            "title": "规划状态",
            "title_label": "规划状态",
            "level": "info",
            "content": planning_status_label,
            "content_label": planning_status_label,
        },
        {
            "title": "执行状态",
            "title_label": "执行状态",
            "level": "info",
            "content": execution_message or execution_state_label,
            "content_label": execution_message or execution_state_label,
        },
        {
            "title": "风险策略",
            "title_label": "风险策略",
            "level": "info",
            "content": "低/中风险模块默认自动执行；仅高风险主动探测步骤需要人工批准。",
            "content_label": "低/中风险模块默认自动执行；仅高风险主动探测步骤需要人工批准。",
        },
    ]
    if provider_message:
        status_cards.append(
            {
                "title": "LLM 状态",
                "title_label": "LLM 状态",
                "level": "warning" if provider_status in {"missing_env", "fallback"} else "info",
                "content": provider_message,
                "content_label": provider_message,
            }
        )

    report_reviewer_notes = []
    for item in snapshot.get("report_reviewer_notes", []):
        report_reviewer_notes.append(
            {
                **item,
                "level_label": to_user_label("severity", "info" if item.get("level") == "info" else "medium"),
                "message_label": to_user_message(str(item.get("message", ""))),
            }
        )

    run_id = str(snapshot.get("run_id", "")).strip()
    return {
        "run_id_label": f"当前 Run ID：{run_id}" if run_id else "尚未创建任务",
        "current_stage_label": to_user_label("stage", str(snapshot.get("current_stage", ""))),
        "steps_label": f"{len(snapshot.get('completed_steps', []))}/{len(plan_steps)}",
        "pending_confirmations_label": len(snapshot.get("pending_confirmations", [])),
        "plan_steps": plan_steps,
        "findings": findings,
        "advice_timeline": advice_timeline,
        "events": events,
        "status_cards": status_cards,
        "execution_scope": {
            "auto_modules": auto_modules,
            "approval_modules": approval_modules,
        },
        "runtime_summary": {
            "requested_agent_mode": requested_mode,
            "requested_agent_mode_label": to_user_label("mode", requested_mode),
            "effective_agent_mode": effective_mode,
            "effective_agent_mode_label": to_user_label("mode", effective_mode),
            "provider_name": provider_name,
            "model_id": str(run_model_context.get("model_id", "")),
            "base_url": str(run_model_context.get("base_url", "")),
            "provider_status": provider_status,
            "provider_status_label": to_user_label("provider_status", provider_status),
            "provider_message": provider_message,
            "provider_help": provider_help,
            "provider_preview_message": provider_message or provider_help,
            "planning_status_label": planning_status_label,
            "execution_state": execution_state,
            "execution_state_label": execution_state_label,
            "execution_message": execution_message,
            "llm_enabled": bool(run_model_context.get("llm_enabled", False)),
        },
        "report_reviewer_notes": report_reviewer_notes,
    }


def build_report_view_model_zh(model: Any) -> Any:
    return model
