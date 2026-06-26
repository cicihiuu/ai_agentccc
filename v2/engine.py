from __future__ import annotations

import json
import re
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from ai_security_agent.llm import LLMError, complete_json_object
from ai_security_agent.llm.factory import create_provider_from_config
from ai_security_agent.i18n import to_user_title

from .models import (
    AgentEvent,
    AgentProfile,
    DecisionRecord,
    Lead,
    Observation,
    ScanPlan,
    ScanState,
    SkillCard,
    StepSpec,
    StepState,
    SubAgentState,
    SubAgentTask,
    ToolAction,
    VerificationRecord,
    VerifiedFinding,
    make_id,
    now_iso,
)
from .skills import SkillCatalog
from .tools import ToolExecution, ToolRegistry


FALLBACK_REASONS = {
    "invalid_json",
    "llm_exception",
    "empty_decision",
    "llm_unavailable",
    "missing_api_key",
    "provider_timeout",
    "tool_not_allowed",
    "hallucinated_tool",
    "repeated_action",
    "sql_deterministic_path",
    "schema_repair_failed",
    "provider_rate_limited",
    "stagnation_guard_triggered",
}


def _latest_body(state: StepState) -> str:
    for observation in reversed(state.observations):
        if isinstance(observation.payload, dict) and observation.payload.get("body"):
            return str(observation.payload.get("body", ""))
    return ""


def _action_signature(tool_name: str, arguments: dict[str, Any]) -> str:
    return f"{tool_name}:{json.dumps(arguments, ensure_ascii=False, sort_keys=True, default=str)}"


def _severity_rank(value: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(str(value).strip().lower(), 5)


def _first_line(text: str, fallback: str) -> str:
    line = str(text or "").strip().splitlines()
    return line[0].strip() if line and line[0].strip() else fallback


def _normalize_llm_decision_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload or {})
    tool_name = str(normalized.get("tool_name", "")).strip() or str(normalized.get("tool", "")).strip()
    arguments = normalized.get("arguments", {})
    if not isinstance(arguments, dict):
        arguments = {}
    if not arguments and isinstance(normalized.get("params"), dict):
        arguments = dict(normalized.get("params", {}))
    rationale = str(normalized.get("rationale", "")).strip() or str(normalized.get("reason", "")).strip()
    hypothesis = str(normalized.get("hypothesis", "")).strip() or str(normalized.get("thought", "")).strip()
    normalized["tool_name"] = tool_name
    normalized["arguments"] = arguments
    normalized["rationale"] = rationale
    normalized["hypothesis"] = hypothesis
    return normalized


def _compact_step_contexts(step_contexts: dict[str, Any]) -> dict[str, Any]:
    compact: dict[str, Any] = {}
    for key, value in list((step_contexts or {}).items())[:4]:
        if isinstance(value, dict):
            preview: dict[str, Any] = {}
            for inner_key, inner_value in list(value.items())[:6]:
                if isinstance(inner_value, list):
                    preview[inner_key] = inner_value[:3]
                elif isinstance(inner_value, dict):
                    preview[inner_key] = list(inner_value.keys())[:3]
                else:
                    preview[inner_key] = inner_value
            compact[key] = preview
        elif isinstance(value, list):
            compact[key] = value[:3]
        else:
            compact[key] = value
    return compact


class StepPromptBuilder:
    def __init__(self, skills: SkillCatalog | None = None):
        self.skills = skills

    def build(
        self,
        scan: ScanState,
        spec: StepSpec,
        state: StepState,
        *,
        step_contexts: dict[str, Any] | None = None,
        replan_hint: str = "",
    ) -> str:
        skill = self._skill_for(spec)
        step_contexts = step_contexts or {}
        upstream = ", ".join(sorted(step_contexts.keys())) or "none"
        requirements = "\n".join(f"- {item}" for item in getattr(skill, "verification_requirements", [])[:6]) or "- keep evidence structured"
        criteria = "\n".join(f"- {item}" for item in getattr(skill, "success_criteria", [])[:6]) or "- produce bounded progress"
        false_positive_rules = "\n".join(f"- {item}" for item in getattr(skill, "false_positive_rules", [])[:6]) or "- do not over-report"
        checklist = "\n".join(f"- {item}" for item in getattr(skill, "checklist", [])[:8]) or "- follow the step goal"
        recent_observations = [
            {
                "tool": item.tool_name,
                "status": item.status,
                "summary": item.summary[:160],
                "payload_keys": list(item.payload.keys())[:6] if isinstance(item.payload, dict) else [],
            }
            for item in state.observations[-3:]
        ]
        recent_decisions = [
            {
                "tool_name": item.tool_name,
                "source": item.source,
                "fallback_reason": item.fallback_reason,
            }
            for item in state.decision_records[-3:]
        ]
        context_preview = _compact_step_contexts(step_contexts)
        return (
            f"Step: {spec.name}\n"
            f"Goal: {spec.goal}\n"
            f"Target: {scan.target}\n"
            f"Allowed tools: {', '.join(spec.allowed_tools)}\n"
            f"Iterations used: {state.iterations}/{spec.budget.max_iterations}\n"
            f"Tool calls used: {state.tool_calls}/{spec.budget.max_tool_calls}\n"
            f"Verification Goal: {self.verification_goal(spec)}\n"
            f"Upstream contexts: {upstream}\n"
            f"Replan hint: {replan_hint or '-'}\n\n"
            f"Checklist:\n{checklist}\n\n"
            f"Verification requirements:\n{requirements}\n\n"
            f"Success criteria:\n{criteria}\n\n"
            f"False-positive rules:\n{false_positive_rules}\n\n"
            f"Recent decisions:\n{json.dumps(recent_decisions, ensure_ascii=False)}\n\n"
            f"Recent observations:\n{json.dumps(recent_observations, ensure_ascii=False)}\n\n"
            f"Context preview:\n{json.dumps(context_preview, ensure_ascii=False)}\n\n"
            "Do not repeat an identical tool call if the same action was already attempted without new evidence.\n"
            "Prefer the next allowed tool that advances the current step.\n"
        )

    def verification_goal(self, spec: StepSpec) -> str:
        skill = self._skill_for(spec)
        requirements = list(getattr(skill, "verification_requirements", []) or [])
        if requirements:
            return "; ".join(str(item) for item in requirements[:3])
        criteria = list(getattr(skill, "success_criteria", []) or [])
        if criteria:
            return "; ".join(str(item) for item in criteria[:3])
        return spec.verification_policy

    def _skill_for(self, spec: StepSpec) -> SkillCard:
        if self.skills and spec.skill_names:
            try:
                return self.skills.get(spec.skill_names[0])
            except Exception:
                pass
        return SkillCard(
            name=spec.skill_names[0] if spec.skill_names else spec.name,
            module=spec.name,
            category=spec.category,
            description=spec.goal,
            checklist=[],
            recommended_tools=list(spec.allowed_tools),
            verification_requirements=[],
            followup_routes=[],
        )


def _observation_from_execution(tool_name: str, execution: ToolExecution) -> Observation:
    artifact_ids = [artifact.artifact_id for artifact in execution.artifacts]
    return Observation(
        observation_id=make_id("obs"),
        tool_name=tool_name,
        status="ok" if execution.status == "ok" else "error",
        summary=execution.summary,
        payload=dict(execution.payload),
        artifact_ids=artifact_ids,
    )


class EvidenceGate:
    def promote(self, step: StepState) -> list[VerifiedFinding]:
        deduped_findings: dict[tuple[str, str, str], VerifiedFinding] = {}
        for finding in step.verified_findings:
            source = str(finding.metadata.get("verification_source", "")).strip()
            deduped_findings[(finding.category, finding.location, source)] = finding
        step.verified_findings = list(
            sorted(
                deduped_findings.values(),
                key=lambda item: (_severity_rank(item.severity), item.category, item.location, item.finding_id),
            )
        )
        deduped_records: dict[str, VerificationRecord] = {}
        for record in step.verification_records:
            deduped_records[record.verification_id] = record
        step.verification_records = list(deduped_records.values())
        deduped_leads: dict[tuple[str, str, str], Lead] = {}
        for lead in step.leads:
            deduped_leads[(lead.category, lead.location, lead.title)] = lead
        step.leads = list(deduped_leads.values())
        return step.verified_findings


class RuleDecisionEngine:
    def decide(self, scan: ScanState, spec: StepSpec, state: StepState, *, step_contexts: dict[str, Any]) -> ToolAction | None:
        if state.iterations >= spec.budget.max_iterations or state.tool_calls >= spec.budget.max_tool_calls:
            return None

        target = scan.target
        name = spec.name

        if name == "state_bootstrap":
            if state.tool_calls == 0:
                return ToolAction("state_bootstrap_bridge", {}, "Build reusable authenticated request context when the target exposes login state.")
            return None

        if name == "recon":
            if state.tool_calls == 0:
                return ToolAction("http_request", {"url": target, "method": "GET"}, "Fetch the entry page baseline.")
            if state.tool_calls == 1 and state.observations:
                return ToolAction("extract_links_from_html", {}, "Extract same-origin links from the baseline page.")
            if state.tool_calls == 2 and state.observations:
                return ToolAction("extract_forms_from_html", {}, "Extract forms and input names from the baseline page.")
            if state.tool_calls == 3 and state.observations:
                return ToolAction("extract_parameters_from_response", {"url": target}, "Extract URL and form parameter hints from the baseline page.")
            if state.tool_calls == 4:
                return ToolAction("recon_bridge", {}, "Run the recon module bridge for structured inventory and follow-up routing context.")
            if state.tool_calls == 5 and state.observations:
                return ToolAction(
                    "artifact_capture",
                    {"name": "recon-homepage", "content": _latest_body(state), "kind": "http_body"},
                    "Capture the entry page body as baseline evidence.",
                )
            return None

        if name == "backup_audit_extended":
            if state.tool_calls == 0:
                return ToolAction("backup_audit_bridge", {}, "Run the backup audit module bridge.")
            if state.tool_calls == 1:
                return ToolAction("fetch_candidate_file", {"target": target, "candidate": ".git/config"}, "Fetch a high-signal backup candidate.")
            return None

        if name == "config_audit":
            if state.tool_calls == 0:
                return ToolAction("config_audit_bridge", {}, "Run the config audit module bridge.")
            if state.tool_calls == 1:
                return ToolAction("fetch_candidate_file", {"target": target, "candidate": ".env"}, "Fetch a common config candidate.")
            if state.tool_calls == 2 and state.observations:
                return ToolAction("parse_config", {"content": _latest_body(state)}, "Parse the fetched config content.")
            return None

        if name == "sql_scan":
            if state.tool_calls == 0:
                return ToolAction("discover_sql_candidates", {}, "Discover SQL candidates from module inventory.")
            if state.tool_calls == 1:
                candidate = _first_sql_candidate_from_context(step_contexts, state)
                if candidate:
                    return ToolAction("probe_sql_boolean", {"candidate": candidate}, "Run a bounded boolean differential probe.")
            return None

        if name == "sql_bypass":
            if state.tool_calls == 0:
                candidate = _first_sql_candidate_from_context(step_contexts, state)
                if candidate:
                    return ToolAction("generate_sql_bypass_plan", {"candidate": candidate}, "Generate a bounded SQL bypass plan.")
            if state.tool_calls == 1 and state.observations:
                payload = state.observations[-1].payload if isinstance(state.observations[-1].payload, dict) else {}
                candidate = dict(payload.get("candidate", {})) if isinstance(payload.get("candidate", {}), dict) else {}
                strategies = payload.get("strategies", [])
                if candidate and isinstance(strategies, list) and strategies and isinstance(strategies[0], dict):
                    return ToolAction("run_sql_bypass_probe", {"candidate": candidate, "strategy": strategies[0]}, "Run the top bounded bypass strategy.")
            if state.tool_calls == 2:
                candidate = _first_sql_candidate_from_context(step_contexts, state)
                if candidate:
                    return ToolAction("run_waf_bypass_strategy", {"candidate": candidate}, "Record the WAF bypass assessment output.")
            return None

        if name == "js_audit":
            if state.tool_calls == 0:
                return ToolAction("js_audit_bridge", {}, "Run the JavaScript audit module bridge.")
            if state.tool_calls == 1:
                return ToolAction("http_request", {"url": target, "method": "GET"}, "Fetch page content for lightweight JS heuristics.")
            if state.tool_calls == 2:
                return ToolAction("parse_js_ast", {"source": _latest_body(state)}, "Parse lightweight JS heuristics.")
            if state.tool_calls == 3:
                return ToolAction("extract_js_endpoints", {"source": _latest_body(state), "base_url": target}, "Extract JS-derived endpoints.")
            if state.tool_calls == 4:
                return ToolAction("extract_fetch_calls", {"source": _latest_body(state)}, "Extract fetch/axios calls.")
            if state.tool_calls == 5:
                return ToolAction("extract_dom_sinks", {"source": _latest_body(state)}, "Extract DOM sinks.")
            return None

        if name == "xss_triage":
            if state.tool_calls == 0:
                return ToolAction("xss_triage_bridge", {}, "Run the XSS module bridge.")
            if state.tool_calls == 1:
                return ToolAction(
                    "replay_request_with_mutation",
                    {"url": target, "method": "GET", "parameter": "message", "value": "<script>alert(1)</script>"},
                    "Replay a bounded reflected XSS marker.",
                )
            if state.tool_calls == 2:
                return ToolAction("browser_action", {"command": "screenshot"}, "Capture browser-side evidence.")
            return None

        if name == "ssrf_triage":
            token = f"{scan.scan_id}-ssrf"
            if state.tool_calls == 0:
                return ToolAction("create_callback_endpoint", {"token": token}, "Create an OOB callback endpoint.")
            if state.tool_calls == 1:
                callback = _last_callback_endpoint(state) or f"callback://{token}"
                return ToolAction("build_ssrf_probe_set", {"callback": callback}, "Build the SSRF probe set.")
            if state.tool_calls == 2:
                callback = _last_callback_endpoint(state) or f"callback://{token}"
                separator = "&" if "?" in target else "?"
                return ToolAction("http_request", {"url": f"{target}{separator}url={callback}", "method": "GET"}, "Send a bounded SSRF callback probe.")
            if state.tool_calls == 3:
                return ToolAction("poll_callback_events", {"token": token}, "Poll the callback endpoint for hits.")
            if state.tool_calls == 4:
                probe_target = _first_ssrf_probe_target(step_contexts, scan.target)
                return ToolAction(
                    "parser_confusion_probe",
                    {"url": probe_target, "callback": _last_callback_endpoint(state) or f"callback://{token}", "parameter": "url"},
                    "Generate parser-confusion SSRF probe variants.",
                )
            if state.tool_calls == 5:
                return ToolAction("ssrf_triage_bridge", {}, "Run the SSRF module bridge for richer context.")
            return None

        if name == "permission_bypass":
            admin_url = target.rstrip("/") + "/admin"
            session_overrides = {
                "user_a": {"headers": {"X-Agent-Role": "admin"}, "cookies": {"role": "admin"}},
                "user_b": {"headers": {"X-Agent-Role": "guest"}, "cookies": {"role": "guest"}},
            }
            if state.tool_calls == 0:
                return ToolAction("permission_bypass_bridge", {}, "Run the permission-bypass module bridge.")
            if state.tool_calls == 1:
                return ToolAction("create_identity", {"prefix": "auth", "role": "user_a"}, "Create the first test identity.")
            if state.tool_calls == 2:
                return ToolAction("create_identity", {"prefix": "auth", "role": "user_b"}, "Create the second test identity.")
            if state.tool_calls == 3:
                return ToolAction("session_store", {"action": "set_cookie", "session_name": "user_a", "name": "role", "value": "admin"}, "Seed the high-privilege session.")
            if state.tool_calls == 4:
                return ToolAction("session_store", {"action": "set_cookie", "session_name": "user_b", "name": "role", "value": "guest"}, "Seed the low-privilege session.")
            if state.tool_calls == 5:
                return ToolAction(
                    "same_request_different_session_replay",
                    {"url": admin_url, "method": "GET", "sessions": ["user_a", "user_b"], "session_overrides": session_overrides},
                    "Replay the same request across two identities.",
                )
            if state.tool_calls == 6 and state.observations:
                responses = state.observations[-1].payload.get("responses", []) if isinstance(state.observations[-1].payload, dict) else []
                before = responses[0] if isinstance(responses, list) and responses else {}
                after = responses[1] if isinstance(responses, list) and len(responses) > 1 else {}
                return ToolAction("compare_http_responses", {"before": before, "after": after}, "Compare the differential auth responses.")
            return None

        if name == "weak_password":
            if state.tool_calls == 0:
                return ToolAction("weak_password_bridge", {}, "Run the weak-password module bridge.")
            return None

        if name == "cors_audit":
            if state.tool_calls == 0:
                return ToolAction("cors_audit_bridge", {}, "Run the CORS audit module bridge.")
            return None

        if name == "jwt_audit":
            if state.tool_calls == 0:
                return ToolAction("jwt_audit_bridge", {}, "Run the JWT audit module bridge.")
            return None

        if name == "poc_verify":
            processed_ids = {
                str(item.payload.get("source_finding_id", "")).strip()
                for item in state.observations
                if item.tool_name == "generate_poc_verification_case"
                and isinstance(item.payload, dict)
                and str(item.payload.get("source_finding_id", "")).strip()
            }
            last_case = next(
                (
                    item.payload
                    for item in reversed(state.observations)
                    if item.tool_name == "generate_poc_verification_case" and isinstance(item.payload, dict)
                ),
                {},
            )
            last_status = str(last_case.get("status", "")).strip()
            last_source_finding_id = str(last_case.get("source_finding_id", "")).strip()
            case_finished = bool(
                last_status == "ready"
                and state.observations
                and state.observations[-1].tool_name == "run_poc_in_docker"
            )
            if state.tool_calls == 0:
                return ToolAction("generate_poc_verification_case", {}, "Generate a bounded POC verification case.")
            if last_status == "no_candidate":
                return None
            if last_status == "manual_only" and last_source_finding_id and last_source_finding_id in processed_ids:
                return ToolAction("generate_poc_verification_case", {}, "Generate the next bounded POC verification case.")
            if case_finished:
                return ToolAction("generate_poc_verification_case", {}, "Generate the next bounded POC verification case.")
            if state.observations:
                payload = state.observations[-1].payload if isinstance(state.observations[-1].payload, dict) else {}
                if str(payload.get("status", "")).strip() == "ready" and str(payload.get("script", "")).strip():
                    return ToolAction(
                        "run_poc_in_docker",
                        {
                            "script": payload.get("script", ""),
                            "source_finding_id": str(payload.get("source_finding_id", "")).strip(),
                            "env_names": list(payload.get("env_names", [])) if isinstance(payload.get("env_names", []), list) else [],
                        },
                        "Run the bounded docker POC.",
                    )
            return None

        return None


class LLMDecisionEngine:
    def __init__(self, profile: AgentProfile):
        self.profile = profile
        self.enabled = bool(getattr(profile, "llm_enabled", False))
        self.model_id = str(getattr(profile, "model_id", "")).strip()
        self.provider_name = str(getattr(profile, "provider_name", "")).strip()
        self.provider = None
        if not self.enabled:
            return
        try:
            self.provider = create_provider_from_config(profile, agent_mode="llm")
        except Exception:
            self.provider = None

    def decide(self, prompt: str) -> dict[str, Any]:
        if not self.enabled or self.provider is None:
            raise LLMError("llm unavailable")
        payload = complete_json_object(
            self.provider,
            (
                prompt
                + "\n\nReturn exactly one JSON object and nothing else.\n"
                + 'Required keys: "hypothesis", "tool_name", "arguments", "rationale".\n'
                + 'Do not use alternative keys like "tool", "params", or markdown fences.\n'
            ),
            model_id=self.model_id or "unknown-model",
            max_tokens=512,
            schema_hint='{"hypothesis":"string","tool_name":"http_request","arguments":{"url":"https://example.com"},"rationale":"string"}',
        )
        return _normalize_llm_decision_payload(payload)


class SubAgentRunner:
    def __init__(self, runner, *, max_workers: int = 2):
        self.runner = runner
        self.executor = ThreadPoolExecutor(max_workers=max(1, int(max_workers or 1)))
        self.futures: dict[str, Future] = {}

    def spawn(self, task: SubAgentTask) -> str:
        subagent_id = make_id("subagent")
        self.futures[subagent_id] = self.executor.submit(self.runner, subagent_id, task)
        return subagent_id

    def collect_ready(self) -> list[tuple[str, SubAgentState]]:
        ready: list[tuple[str, SubAgentState]] = []
        for subagent_id, future in list(self.futures.items()):
            if not future.done():
                continue
            del self.futures[subagent_id]
            ready.append((subagent_id, future.result()))
        return ready


class StepExecutor:
    def __init__(
        self,
        registry: ToolRegistry,
        evidence_gate: EvidenceGate,
        profile: AgentProfile,
        skills: SkillCatalog | None = None,
    ):
        self.registry = registry
        self.evidence_gate = evidence_gate
        self.profile = profile
        self.skills = skills
        self.prompt_builder = StepPromptBuilder(skills)
        self.rule_engine = RuleDecisionEngine()
        self.llm_engine = LLMDecisionEngine(profile)

    def execute(self, scan: ScanState, spec: StepSpec, state: StepState) -> StepState:
        if state.status in {"completed", "failed", "blocked"}:
            return state

        state.status = "running"
        state.started_at = state.started_at or now_iso()

        while state.iterations < spec.budget.max_iterations and state.tool_calls < spec.budget.max_tool_calls:
            step_contexts = self._step_contexts(scan, spec)
            action, record, stop_now = self._decide_action(scan, spec, state, step_contexts)
            if record is not None:
                state.decision_records.append(record)
            if stop_now:
                state.status = "blocked"
                state.error = "stagnation_guard_triggered"
                break
            if action is None:
                break

            execution_context = {
                "target": scan.target,
                "scan_id": scan.scan_id,
                "profile": scan.profile.to_dict(),
                "current_step": spec.name,
                "last_observation_payload": state.observations[-1].payload if state.observations else {},
                "step_contexts": step_contexts,
                "verified_findings": [item.to_dict() for item in scan.verified_findings],
                "processed_poc_finding_ids": [
                    str(item.payload.get("source_finding_id", "")).strip()
                    for item in state.observations
                    if item.tool_name == "generate_poc_verification_case"
                    and isinstance(item.payload, dict)
                    and str(item.payload.get("source_finding_id", "")).strip()
                ],
                "legacy_context": self._legacy_context(step_contexts),
            }
            execution = self.registry.execute(action.tool_name, action.arguments, execution_context)
            observation = _observation_from_execution(action.tool_name, execution)
            for artifact in execution.artifacts:
                scan.artifacts[artifact.artifact_id] = artifact
                if artifact.artifact_id not in state.artifact_ids:
                    state.artifact_ids.append(artifact.artifact_id)
            if record is not None and observation.observation_id not in record.observation_refs:
                record.observation_refs.append(observation.observation_id)
            state.observations.append(observation)
            state.iterations += 1
            state.tool_calls += 1
            self._derive_step_outputs(spec, state, observation, execution, scan=scan, step_contexts=step_contexts)
            self.evidence_gate.promote(state)
            self._merge_scan_findings(scan, state)

        if state.status == "running":
            state.status = "completed" if (state.observations or state.leads or state.verified_findings) else "blocked"
        state.finished_at = now_iso()
        state.output_context = self._build_output_context(scan, spec, state, self._step_contexts(scan, spec))
        return state

    def _decide_action(
        self,
        scan: ScanState,
        spec: StepSpec,
        state: StepState,
        step_contexts: dict[str, Any],
    ) -> tuple[ToolAction | None, DecisionRecord | None, bool]:
        prompt = self.prompt_builder.build(scan, spec, state, step_contexts=step_contexts)
        input_summary = f"upstream={','.join(sorted(step_contexts.keys())) or 'none'}; obs={len(state.observations)}; findings={len(state.verified_findings)}"

        if spec.name in {"sql_scan", "sql_bypass", "poc_verify"}:
            action = self.rule_engine.decide(scan, spec, state, step_contexts=step_contexts)
            if action is None:
                return None, None, False
            duplicate_ratio, stagnation_rounds = self._action_repeat_metrics(state, action.tool_name, action.arguments)
            record = self._decision_record(
                spec,
                state,
                action,
                source="fallback",
                hypothesis=spec.goal,
                rationale=action.rationale or "sql-focused deterministic step action",
                input_summary=input_summary,
                fallback_reason="sql_deterministic_path",
                stagnation_rounds=stagnation_rounds,
                duplicate_action_ratio=duplicate_ratio,
            )
            return action, record, False

        if self.llm_engine.enabled and self.llm_engine.provider is not None:
            try:
                payload = self.llm_engine.decide(prompt)
                tool_name = str(payload.get("tool_name", "")).strip()
                arguments = dict(payload.get("arguments", {})) if isinstance(payload.get("arguments", {}), dict) else {}
                hypothesis = str(payload.get("hypothesis", "")).strip()
                rationale = str(payload.get("rationale", "")).strip()
                if not tool_name:
                    raise LLMError("empty decision")
                if tool_name not in spec.allowed_tools:
                    fallback = self._fallback_action(scan, spec, state, step_contexts)
                    record = self._decision_record(
                        spec,
                        state,
                        fallback,
                        source="fallback",
                        hypothesis=hypothesis,
                        rationale=rationale,
                        input_summary=input_summary,
                        fallback_reason="tool_not_allowed",
                    )
                    return fallback, record, False
                duplicate_ratio, stagnation_rounds = self._action_repeat_metrics(state, tool_name, arguments)
                fallback = None
                if duplicate_ratio > 0:
                    fallback = self._fallback_action(scan, spec, state, step_contexts)
                    fallback_signature = ""
                    fallback_duplicate_ratio = duplicate_ratio
                    fallback_stagnation_rounds = stagnation_rounds
                    if fallback is not None:
                        fallback_signature = _action_signature(fallback.tool_name, fallback.arguments)
                        fallback_duplicate_ratio, fallback_stagnation_rounds = self._action_repeat_metrics(
                            state,
                            fallback.tool_name,
                            fallback.arguments,
                        )
                    if fallback is not None and fallback_signature != _action_signature(tool_name, arguments):
                        if fallback_stagnation_rounds >= 3:
                            record = self._decision_record(
                                spec,
                                state,
                                None,
                                source="fallback",
                                hypothesis=hypothesis,
                                rationale="LLM repeated a previously attempted action and the fallback path is now also repeating.",
                                input_summary=input_summary,
                                fallback_reason="stagnation_guard_triggered",
                                stagnation_rounds=fallback_stagnation_rounds,
                                duplicate_action_ratio=fallback_duplicate_ratio,
                            )
                            return None, record, True
                        record = self._decision_record(
                            spec,
                            state,
                            fallback,
                            source="fallback",
                            hypothesis=hypothesis,
                            rationale="LLM repeated a previously attempted action; advancing with the rule-based next tool.",
                            input_summary=input_summary,
                            fallback_reason="repeated_action",
                            stagnation_rounds=fallback_stagnation_rounds,
                            duplicate_action_ratio=fallback_duplicate_ratio,
                        )
                        state.llm_fallback_count += 1
                        return fallback, record, False
                if stagnation_rounds >= 3:
                    record = self._decision_record(
                        spec,
                        state,
                        None,
                        source="fallback",
                        hypothesis=hypothesis,
                        rationale=rationale,
                        input_summary=input_summary,
                        fallback_reason="stagnation_guard_triggered",
                        stagnation_rounds=stagnation_rounds,
                        duplicate_action_ratio=duplicate_ratio,
                    )
                    return None, record, True
                action = ToolAction(tool_name, arguments, rationale)
                record = self._decision_record(
                    spec,
                    state,
                    action,
                    source="llm",
                    hypothesis=hypothesis,
                    rationale=rationale,
                    input_summary=input_summary,
                    stagnation_rounds=stagnation_rounds,
                    duplicate_action_ratio=duplicate_ratio,
                    model=self.llm_engine.model_id,
                    provider=self.llm_engine.provider_name,
                )
                return action, record, False
            except Exception as exc:
                fallback = self._fallback_action(scan, spec, state, step_contexts)
                if fallback is not None:
                    record = self._decision_record(
                        spec,
                        state,
                        fallback,
                        source="fallback",
                        hypothesis="fallback rule plan",
                        rationale="LLM unavailable or invalid; using rule-based action.",
                        input_summary=input_summary,
                        fallback_reason="llm_exception",
                        fallback_detail=f"{type(exc).__name__}: {str(exc).strip()}",
                    )
                    state.llm_fallback_count += 1
                    return fallback, record, False

        action = self.rule_engine.decide(scan, spec, state, step_contexts=step_contexts)
        if action is None:
            return None, None, False
        duplicate_ratio, stagnation_rounds = self._action_repeat_metrics(state, action.tool_name, action.arguments)
        record = self._decision_record(
            spec,
            state,
            action,
            source="fallback",
            hypothesis=spec.goal,
            rationale=action.rationale or "rule-based step action",
            input_summary=input_summary,
            fallback_reason="llm_unavailable" if self.llm_engine.enabled else "",
            stagnation_rounds=stagnation_rounds,
            duplicate_action_ratio=duplicate_ratio,
        )
        if self.llm_engine.enabled:
            state.llm_fallback_count += 1
        return action, record, False

    def _fallback_action(self, scan: ScanState, spec: StepSpec, state: StepState, step_contexts: dict[str, Any]) -> ToolAction | None:
        action = self.rule_engine.decide(scan, spec, state, step_contexts=step_contexts)
        if action is not None and action.tool_name in spec.allowed_tools:
            return action
        if spec.allowed_tools:
            if spec.allowed_tools[0] == "http_request":
                return ToolAction("http_request", {"url": scan.target, "method": "GET"}, "Fallback to a safe baseline request.")
            return ToolAction(spec.allowed_tools[0], {}, "Fallback to the first allowed tool.")
        return None

    def _decision_record(
        self,
        spec: StepSpec,
        state: StepState,
        action: ToolAction | None,
        *,
        source: str,
        hypothesis: str,
        rationale: str,
        input_summary: str,
        fallback_reason: str = "",
        fallback_detail: str = "",
        stagnation_rounds: int = 0,
        duplicate_action_ratio: float = 0.0,
        model: str = "",
        provider: str = "",
    ) -> DecisionRecord:
        tool_name = action.tool_name if action is not None else (state.decision_records[-1].tool_name if state.decision_records else "")
        arguments = dict(action.arguments) if action is not None else {}
        return DecisionRecord(
            decision_id=make_id("decision"),
            source=source,
            tool_name=tool_name,
            arguments=arguments,
            hypothesis=hypothesis,
            rationale=rationale,
            skill_name=spec.skill_names[0] if spec.skill_names else spec.name,
            step_name=spec.name,
            input_summary=input_summary,
            verification_goal=self.prompt_builder.verification_goal(spec),
            progress_score=round(min((state.iterations + 1) / max(spec.budget.max_iterations, 1), 1.0), 2),
            stagnation_rounds=stagnation_rounds,
            duplicate_action_ratio=round(duplicate_action_ratio, 2),
            model=model,
            provider=provider,
            fallback_reason=fallback_reason,
            fallback_detail=fallback_detail,
        )

    def _action_repeat_metrics(self, state: StepState, tool_name: str, arguments: dict[str, Any]) -> tuple[float, int]:
        signature = _action_signature(tool_name, arguments)
        signatures = [_action_signature(item.tool_name, item.arguments) for item in state.decision_records]
        total = len(signatures) + 1
        duplicate_ratio = (signatures.count(signature) + 1) / max(total, 1)
        rounds = 1
        for item in reversed(signatures):
            if item != signature:
                break
            rounds += 1
        return duplicate_ratio, rounds

    def _legacy_context(self, step_contexts: dict[str, Any]) -> dict[str, Any]:
        upstream = {}
        for name, context in step_contexts.items():
            if name == "child_contributions" or not isinstance(context, dict):
                continue
            followup = context.get("followup_context", {})
            if isinstance(followup, dict) and followup:
                upstream[name] = followup
        return {"upstream_followup_context": upstream}

    def _step_contexts(self, scan: ScanState, current_spec: StepSpec) -> dict[str, Any]:
        contexts: dict[str, Any] = {}
        for step in scan.plan.steps:
            state = scan.step_states.get(step.step_id)
            if state is None or state.step_id == current_spec.step_id:
                continue
            if state.output_context:
                contexts[step.name] = dict(state.output_context)
        child_recommended: list[dict[str, Any]] = []
        for subagent in scan.subagents.values():
            if subagent.status != "completed":
                continue
            for item in subagent.output_context.get("recommended_next_tests", []) if isinstance(subagent.output_context, dict) else []:
                if isinstance(item, dict):
                    child_recommended.append(dict(item))
        contexts["child_contributions"] = {"recommended_next_tests": child_recommended[:20]}
        return contexts

    def _merge_scan_findings(self, scan: ScanState, state: StepState) -> None:
        existing = {item.finding_id for item in scan.verified_findings}
        for finding in state.verified_findings:
            if finding.finding_id not in existing:
                scan.verified_findings.append(finding)
                existing.add(finding.finding_id)

    def _ensure_lead(
        self,
        step: StepState,
        *,
        title: str,
        category: str,
        severity: str,
        location: str,
        rationale: str,
        evidence: str,
        next_steps: list[str],
        metadata: dict[str, Any],
    ) -> Lead:
        for lead in step.leads:
            if lead.title == title and lead.category == category and lead.location == location:
                return lead
        lead = Lead(
            lead_id=make_id("lead"),
            title=title,
            category=category,
            severity=severity,
            location=location,
            rationale=rationale,
            evidence=evidence,
            next_steps=list(next_steps),
            metadata=dict(metadata),
        )
        step.leads.append(lead)
        return lead

    def _ensure_verification(
        self,
        step: StepState,
        *,
        lead: Lead,
        method: str,
        status: str,
        summary: str,
        proof: str,
        metadata: dict[str, Any],
    ) -> VerificationRecord:
        for record in step.verification_records:
            if record.lead_id == lead.lead_id and record.method == method:
                return record
        record = VerificationRecord(
            verification_id=make_id("verify"),
            lead_id=lead.lead_id,
            method=method,
            status=status,
            summary=summary,
            proof=proof,
            artifact_ids=list(step.artifact_ids),
            metadata=dict(metadata),
        )
        step.verification_records.append(record)
        return record

    def _ensure_finding(
        self,
        step: StepState,
        *,
        title: str,
        category: str,
        severity: str,
        location: str,
        impact: str,
        evidence: str,
        recommendation: str,
        reproduction_steps: list[str],
        verification: VerificationRecord,
        metadata: dict[str, Any],
    ) -> VerifiedFinding:
        source = str(metadata.get("verification_source", "")).strip()
        for finding in step.verified_findings:
            if finding.category == category and finding.location == location and str(finding.metadata.get("verification_source", "")).strip() == source:
                return finding
        finding = VerifiedFinding(
            finding_id=make_id("finding"),
            title=title,
            category=category,
            severity=severity,
            location=location,
            impact=impact,
            evidence=evidence,
            recommendation=recommendation,
            reproduction_steps=list(reproduction_steps),
            artifact_ids=list(step.artifact_ids),
            verification_id=verification.verification_id,
            metadata=dict(metadata),
        )
        step.verified_findings.append(finding)
        return finding

    def _derive_step_outputs(
        self,
        spec: StepSpec,
        state: StepState,
        observation: Observation,
        execution: ToolExecution,
        *,
        scan: ScanState | None = None,
        step_contexts: dict[str, Any] | None = None,
    ) -> None:
        step_contexts = step_contexts or {}
        payload = execution.payload if isinstance(execution.payload, dict) else {}

        if observation.tool_name in {
            "state_bootstrap_bridge",
            "recon_bridge",
            "js_audit_bridge",
            "xss_triage_bridge",
            "ssrf_triage_bridge",
            "permission_bypass_bridge",
            "weak_password_bridge",
            "backup_audit_bridge",
            "config_audit_bridge",
            "cors_audit_bridge",
            "jwt_audit_bridge",
        }:
            self._promote_bridge_findings(spec, state, payload, observation.tool_name)

        if observation.tool_name == "run_skill_deep_scan":
            self._promote_skill_runner_findings(spec, state, payload)

        if observation.tool_name == "discover_sql_candidates":
            self._promote_sql_scan_findings(spec, state, payload)
        elif observation.tool_name == "probe_sql_boolean":
            self._promote_sql_boolean_result(spec, state, payload)
        elif observation.tool_name in {"run_sql_bypass_probe", "run_waf_bypass_strategy"}:
            self._record_sql_bypass_assessment(state, payload)
        elif observation.tool_name == "browser_action" and spec.name == "xss_triage":
            fallback = _fallback_xss_candidate_from_state(state)
            if fallback and not any(item.category == "xss" for item in state.verified_findings):
                raw = {
                    "title": f"Reflected XSS evidence candidate: {fallback.get('parameter', 'parameter')}",
                    "severity": "high",
                    "location": str(fallback.get("request_url", "") or fallback.get("page_url", state.step_id)),
                    "evidence": str(fallback.get("basis", "")).strip() or "Reflected marker reached the rendered response path during bounded replay.",
                    "recommendation": "Apply contextual output encoding and avoid unsafe DOM/HTML sinks.",
                }
                self._promote_generic_verified(
                    state,
                    raw,
                    category="xss",
                    method=_xss_verification_method(fallback),
                    impact=_first_line(str(fallback.get("basis", "")), "Browser-confirmed XSS signal."),
                    reproduction_steps=_xss_reproduction_steps(fallback),
                    metadata={"xss_candidate": fallback, "verification_source": "xss_triage"},
                )
        elif observation.tool_name == "compare_http_responses" and spec.name == "permission_bypass":
            fallback = _fallback_permission_context_from_state(state)
            if fallback and not any(item.category == "authorization" for item in state.verified_findings):
                raw = {
                    "title": f"Authorization differential evidence: {fallback.get('parameter', 'resource')}",
                    "severity": "high",
                    "location": str(fallback.get("url", state.step_id)),
                    "evidence": str(fallback.get("basis", "")).strip() or "Same request produced role-dependent differential behavior in bounded replay.",
                    "recommendation": "Enforce server-side authorization checks for each object and action.",
                }
                self._promote_generic_verified(
                    state,
                    raw,
                    category="authorization",
                    method=_permission_verification_method(fallback),
                    impact=_first_line(raw.get("evidence", ""), "Authorization boundary was bypassed."),
                    reproduction_steps=_permission_reproduction_steps(fallback),
                    metadata={"permission_context": fallback, "verification_source": "permission_bypass"},
                )
        elif observation.tool_name == "poll_callback_events":
            self._promote_ssrf_callback_result(state, payload)
        elif observation.tool_name == "generate_poc_verification_case":
            self._record_poc_case(state, payload)
        elif observation.tool_name == "run_poc_in_docker" and scan is not None:
            self._promote_docker_poc(scan, state, payload)

        state.output_context = self._build_output_context(scan, spec, state, step_contexts)

    def _promote_bridge_findings(self, spec: StepSpec, state: StepState, payload: dict[str, Any], tool_name: str) -> None:
        findings = payload.get("findings", [])
        followup_context = payload.get("followup_context", {})
        if isinstance(followup_context, dict):
            state.output_context["followup_context"] = dict(followup_context)
        if not isinstance(findings, list):
            return

        if spec.name == "js_audit":
            self._promote_js_findings(state, findings)
            return
        if spec.name == "xss_triage":
            promoted = False
            for raw in findings:
                if _is_confirmed_raw_finding(raw) and isinstance(raw.get("metadata", {}), dict) and raw["metadata"].get("xss_candidate"):
                    candidate = dict(raw["metadata"].get("xss_candidate", {}))
                    self._promote_generic_verified(
                        state,
                        raw,
                        category="xss",
                        method=_xss_verification_method(candidate),
                        impact=_first_line(candidate.get("basis", "") or raw.get("evidence", ""), "Browser-confirmed XSS signal."),
                        reproduction_steps=_xss_reproduction_steps(candidate),
                        metadata={"xss_candidate": candidate, "verification_source": "xss_triage"},
                    )
                    promoted = True
            if not promoted:
                fallback = _fallback_xss_candidate_from_state(state)
                if fallback:
                    raw = {
                        "title": f"Reflected XSS evidence candidate: {fallback.get('parameter', 'parameter')}",
                        "severity": "high",
                        "location": str(fallback.get("request_url", "") or fallback.get("page_url", state.step_id)),
                        "evidence": str(fallback.get("basis", "")).strip() or "Reflected marker reached the rendered response path during bounded replay.",
                        "recommendation": "Apply contextual output encoding and avoid unsafe DOM/HTML sinks.",
                    }
                    self._promote_generic_verified(
                        state,
                        raw,
                        category="xss",
                        method=_xss_verification_method(fallback),
                        impact=_first_line(str(fallback.get("basis", "")), "Browser-confirmed XSS signal."),
                        reproduction_steps=_xss_reproduction_steps(fallback),
                        metadata={"xss_candidate": fallback, "verification_source": "xss_triage"},
                    )
            return
        if spec.name == "ssrf_triage":
            for raw in findings:
                if _is_confirmed_raw_finding(raw) and isinstance(raw.get("metadata", {}), dict) and raw["metadata"].get("ssrf_context"):
                    context = dict(raw["metadata"].get("ssrf_context", {}))
                    self._promote_generic_verified(
                        state,
                        raw,
                        category="ssrf",
                        method=_ssrf_verification_method(context),
                        impact=_first_line(context.get("reason", "") or raw.get("evidence", ""), "Confirmed SSRF signal."),
                        reproduction_steps=_ssrf_reproduction_steps(context),
                        metadata={"ssrf_context": context, "verification_source": "ssrf_triage"},
                    )
            return
        if spec.name == "permission_bypass":
            promoted = False
            for raw in findings:
                if _is_confirmed_raw_finding(raw) and isinstance(raw.get("metadata", {}), dict) and raw["metadata"].get("permission_context"):
                    context = dict(raw["metadata"].get("permission_context", {}))
                    self._promote_generic_verified(
                        state,
                        raw,
                        category="authorization",
                        method=_permission_verification_method(context),
                        impact=_first_line(raw.get("evidence", ""), "Authorization boundary was bypassed."),
                        reproduction_steps=_permission_reproduction_steps(context),
                        metadata={"permission_context": context, "verification_source": "permission_bypass"},
                    )
                    promoted = True
            if not promoted:
                fallback = _fallback_permission_context_from_state(state)
                if fallback:
                    raw = {
                        "title": f"Authorization differential evidence: {fallback.get('parameter', 'resource')}",
                        "severity": "high",
                        "location": str(fallback.get("url", state.step_id)),
                        "evidence": str(fallback.get("basis", "")).strip() or "Same request produced role-dependent differential behavior in bounded replay.",
                        "recommendation": "Enforce server-side authorization checks for each object and action.",
                    }
                    self._promote_generic_verified(
                        state,
                        raw,
                        category="authorization",
                        method=_permission_verification_method(fallback),
                        impact=_first_line(raw.get("evidence", ""), "Authorization boundary was bypassed."),
                        reproduction_steps=_permission_reproduction_steps(fallback),
                        metadata={"permission_context": fallback, "verification_source": "permission_bypass"},
                    )
            return
        if spec.name == "weak_password":
            for raw in findings:
                if _is_confirmed_raw_finding(raw) and isinstance(raw.get("metadata", {}), dict) and raw["metadata"].get("weak_password_context"):
                    context = dict(raw["metadata"].get("weak_password_context", {}))
                    self._promote_generic_verified(
                        state,
                        raw,
                        category="weak_password",
                        method="bounded_login_submission",
                        impact=_first_line(raw.get("evidence", ""), "A weak/default credential was accepted by the login endpoint."),
                        reproduction_steps=_weak_password_reproduction_steps(context),
                        metadata={"weak_password_context": context, "verification_source": "weak_password"},
                    )
            return
        if spec.name == "cors_audit":
            for raw in findings:
                if _is_confirmed_raw_finding(raw) and isinstance(raw.get("metadata", {}), dict) and raw["metadata"].get("cors_context"):
                    context = dict(raw["metadata"].get("cors_context", {}))
                    self._promote_generic_verified(
                        state,
                        raw,
                        category="cors",
                        method=_cors_verification_method(context),
                        impact=_first_line(raw.get("evidence", ""), "Confirmed dangerous credentialed CORS trust behavior."),
                        reproduction_steps=_cors_reproduction_steps(context),
                        metadata={"cors_context": context, "verification_source": "cors_audit"},
                    )
            return
        if spec.name == "jwt_audit":
            for raw in findings:
                if _is_confirmed_raw_finding(raw) and isinstance(raw.get("metadata", {}), dict) and raw["metadata"].get("jwt_context"):
                    context = dict(raw["metadata"].get("jwt_context", {}))
                    self._promote_generic_verified(
                        state,
                        raw,
                        category="jwt",
                        method=_jwt_verification_method(context),
                        impact=_first_line(raw.get("evidence", ""), "Confirmed JWT algorithm, signature, or disclosure weakness."),
                        reproduction_steps=_jwt_reproduction_steps(context),
                        metadata={"jwt_context": context, "verification_source": "jwt_audit"},
                    )
            return
        if spec.name == "backup_audit_extended":
            for raw in findings:
                if _is_confirmed_raw_finding(raw):
                    metadata = dict(raw.get("metadata", {})) if isinstance(raw.get("metadata", {}), dict) else {}
                    context = dict(metadata.get("backup_context", {})) if isinstance(metadata.get("backup_context", {}), dict) else {}
                    self._promote_generic_verified(
                        state,
                        raw,
                        category="backup_source_audit",
                        method="backup_passive_exposure",
                        impact=_first_line(raw.get("evidence", ""), "Confirmed passive exposure of backup or source metadata."),
                        reproduction_steps=_backup_reproduction_steps(context, str(raw.get("location", ""))),
                        metadata={"backup_context": context, "verification_source": "backup_audit_extended"},
                    )
            return
        if spec.name == "config_audit":
            for raw in findings:
                if _is_confirmed_raw_finding(raw):
                    metadata = dict(raw.get("metadata", {})) if isinstance(raw.get("metadata", {}), dict) else {}
                    context = dict(metadata.get("config_context", {})) if isinstance(metadata.get("config_context", {}), dict) else {}
                    self._promote_generic_verified(
                        state,
                        raw,
                        category="config_exposure",
                        method=_config_verification_method(context),
                        impact=_first_line(raw.get("evidence", ""), "Confirmed configuration exposure or weak deployment configuration."),
                        reproduction_steps=_config_reproduction_steps(context, str(raw.get("location", ""))),
                        metadata={"config_context": context, "verification_source": "config_audit"},
                    )
            return

    def _promote_skill_runner_findings(self, spec: StepSpec, state: StepState, payload: dict[str, Any]) -> None:
        findings = payload.get("verified_findings", [])
        records = payload.get("verification_records", [])
        if not isinstance(findings, list) or not isinstance(records, list):
            return
        record_lookup = {str(item.get("verification_id", "")): item for item in records if isinstance(item, dict)}
        for raw in findings:
            if not isinstance(raw, dict):
                continue
            metadata = dict(raw.get("metadata", {})) if isinstance(raw.get("metadata", {}), dict) else {}
            metadata.setdefault("verification_source", spec.name)
            record_payload = record_lookup.get(str(raw.get("verification_id", "")), {})
            title = to_user_title(str(raw.get("title", "Verified finding")).strip() or "Verified finding")
            lead = self._ensure_lead(
                state,
                title=title,
                category=str(raw.get("category", "generic")).strip() or "generic",
                severity=str(raw.get("severity", "medium")).strip() or "medium",
                location=str(raw.get("location", state.step_id)).strip() or state.step_id,
                rationale=_first_line(raw.get("evidence", ""), "技能扫描器已完成验证。"),
                evidence=str(raw.get("evidence", "")).strip(),
                next_steps=["复核结构化验证记录。"],
                metadata=metadata,
            )
            verification = self._ensure_verification(
                state,
                lead=lead,
                method=str(record_payload.get("method", "skill_deep_scan")).strip() or "skill_deep_scan",
                status="verified",
                summary=to_user_title(str(record_payload.get("summary", title)).strip() or title),
                proof=str(record_payload.get("proof", raw.get("evidence", ""))).strip(),
                metadata=metadata,
            )
            self._ensure_finding(
                state,
                title=title,
                category=str(raw.get("category", "generic")).strip() or "generic",
                severity=str(raw.get("severity", "medium")).strip() or "medium",
                location=str(raw.get("location", state.step_id)).strip() or state.step_id,
                impact=_first_line(raw.get("impact", "") or raw.get("evidence", ""), "技能扫描器已完成验证。"),
                evidence=str(raw.get("evidence", "")).strip(),
                recommendation=str(raw.get("recommendation", "复核并修复该已验证问题。")).strip(),
                reproduction_steps=[str(item).strip() for item in raw.get("reproduction_steps", []) if str(item).strip()] if isinstance(raw.get("reproduction_steps", []), list) else ["复核技能执行证据。"],
                verification=verification,
                metadata=metadata,
            )

    def _promote_sql_scan_findings(self, spec: StepSpec, state: StepState, payload: dict[str, Any]) -> None:
        findings = payload.get("findings", [])
        candidates = payload.get("candidates", [])
        if not isinstance(findings, list):
            return
        for raw in findings:
            if not _is_confirmed_raw_finding(raw):
                continue
            candidate = _match_sql_candidate_for_finding(raw, candidates)
            if not candidate:
                continue
            metadata = {"sql_candidate": candidate, "verification_source": "sql_scan"}
            self._promote_generic_verified(
                state,
                raw,
                category="sql_injection",
                method=_sql_verification_method(candidate),
                impact=_first_line(candidate.get("basis", "") or raw.get("evidence", ""), "Attacker-controlled input alters database-backed responses."),
                reproduction_steps=_sql_reproduction_steps(candidate),
                metadata=metadata,
            )

    def _promote_sql_boolean_result(self, spec: StepSpec, state: StepState, payload: dict[str, Any]) -> None:
        candidate = dict(payload.get("candidate", {})) if isinstance(payload.get("candidate", {}), dict) else {}
        if not candidate or not bool(payload.get("suspicious_boolean_difference", False)):
            return
        evidence = json.dumps(
            {
                "parameter": candidate.get("parameter", ""),
                "true_probe": payload.get("true_probe", {}),
                "false_probe": payload.get("false_probe", {}),
                "length_delta": payload.get("length_delta", 0),
                "status_changed": bool(payload.get("status_changed", False)),
            },
            ensure_ascii=False,
        )
        raw = {
            "title": f"SQL 注入证据候选参数：{candidate.get('parameter', 'parameter')}",
            "severity": "high",
            "location": str(candidate.get("source_location", "") or candidate.get("page_url", state.step_id)),
            "evidence": evidence,
            "recommendation": "Use parameterized queries and strict server-side validation.",
        }
        self._promote_generic_verified(
            state,
            raw,
            category="sql_injection",
            method="boolean_differential",
            impact="Controlled boolean predicates changed the response.",
            reproduction_steps=_sql_reproduction_steps(candidate),
            metadata={"sql_candidate": candidate, "verification_source": "sql_scan"},
        )

    def _record_sql_bypass_assessment(self, state: StepState, payload: dict[str, Any]) -> None:
        def upsert_assessment(
            candidate: dict[str, Any],
            *,
            strategy: dict[str, Any] | None = None,
            signal_summary: dict[str, Any] | None = None,
            best_observation: dict[str, Any] | None = None,
            waf_profile: dict[str, Any] | None = None,
            tamper_recommendations: list[dict[str, Any]] | None = None,
            dbms_hint: str = "",
            summary: str,
        ) -> None:
            strategy = dict(strategy or {})
            signal_summary = dict(signal_summary or {})
            best_observation = dict(best_observation or {})
            waf_profile = dict(waf_profile or {})
            tamper_recommendations = [dict(item) for item in (tamper_recommendations or []) if isinstance(item, dict)]
            title_suffix = str(candidate.get("parameter", "")).strip() or "parameter"
            metadata = {
                "sql_candidate": dict(candidate),
                "strategy": strategy,
                "signal_summary": signal_summary,
                "best_observation": best_observation,
                "waf_profile": waf_profile,
                "tamper_recommendations": tamper_recommendations,
                "dbms_hint": dbms_hint,
            }
            lead = self._ensure_lead(
                state,
                title=f"SQL 绕过评估：{title_suffix}",
                category="sql_bypass_assessment",
                severity="info",
                location=str(candidate.get("source_location", "") or candidate.get("page_url", state.step_id) or state.step_id),
                rationale="受控 WAF 绕过评估仅作为辅助信息，确认可利用前不计入已验证漏洞。",
                evidence=summary,
                next_steps=["基于该评估进行人工复核或沙箱重放。"],
                metadata=metadata,
            )
            lead.rationale = "受控 WAF 绕过评估仅作为辅助信息，确认可利用前不计入已验证漏洞。"
            lead.evidence = summary
            lead.next_steps = ["基于该评估进行人工复核或沙箱重放。"]
            lead.metadata = metadata
            verification = self._ensure_verification(
                state,
                lead=lead,
                method="strategy_assessment",
                status="manual_required",
                summary="SQL 绕过评估已记录",
                proof=summary,
                metadata=metadata,
            )
            verification.status = "manual_required"
            verification.summary = "SQL 绕过评估已记录"
            verification.proof = summary
            verification.metadata = metadata

        followup_context = payload.get("followup_context", {}) if isinstance(payload.get("followup_context", {}), dict) else {}
        assessments = followup_context.get("sql_bypass_assessments", [])
        if isinstance(assessments, list) and assessments:
            for item in assessments[:6]:
                if not isinstance(item, dict):
                    continue
                candidate = dict(item.get("candidate", {})) if isinstance(item.get("candidate", {}), dict) else {}
                signal_summary = dict(item.get("signal_summary", {})) if isinstance(item.get("signal_summary", {}), dict) else {}
                best_observation = dict(item.get("best_observation", {})) if isinstance(item.get("best_observation", {}), dict) else {}
                strategy = best_observation.get("strategy", {}) if isinstance(best_observation.get("strategy", {}), dict) else {}
                waf_profile = dict(item.get("waf_profile", {})) if isinstance(item.get("waf_profile", {}), dict) else {}
                tamper_recommendations = [dict(entry) for entry in item.get("tamper_recommendations", []) if isinstance(entry, dict)] if isinstance(item.get("tamper_recommendations", []), list) else []
                summary = (
                    f"signal_count={signal_summary.get('signal_count', 0)}; "
                    f"signal_types={','.join(signal_summary.get('signal_types', [])) or 'none'}; "
                    f"best_strategy={signal_summary.get('best_strategy', '') or strategy.get('name', '') or 'none'}; "
                    f"waf={waf_profile.get('waf_type', 'generic')}; "
                    f"dbms={str(item.get('dbms_hint', '')).strip() or 'unknown'}"
                )
                upsert_assessment(
                    candidate,
                    strategy=strategy,
                    signal_summary=signal_summary,
                    best_observation=best_observation,
                    waf_profile=waf_profile,
                    tamper_recommendations=tamper_recommendations,
                    dbms_hint=str(item.get("dbms_hint", "")).strip(),
                    summary=summary,
                )
            return

        candidate = dict(payload.get("candidate", {})) if isinstance(payload.get("candidate", {}), dict) else {}
        strategy = dict(payload.get("strategy", {})) if isinstance(payload.get("strategy", {}), dict) else {}
        observation = dict(payload.get("observation", {})) if isinstance(payload.get("observation", {}), dict) else {}
        summary = (
            f"assessment_signal={payload.get('assessment_signal', '')}; "
            f"signal_type={payload.get('signal_type', '')}; "
            f"strategy={strategy.get('name', '') or 'unknown'}"
        )
        upsert_assessment(
            candidate,
            strategy=strategy,
            signal_summary={
                "signal_count": 1 if bool(payload.get("assessment_signal", False)) else 0,
                "signal_types": [str(payload.get("signal_type", "")).strip()] if str(payload.get("signal_type", "")).strip() and str(payload.get("signal_type", "")).strip() != "none" else [],
                "attempted_strategy_names": [str(strategy.get("name", "")).strip()] if str(strategy.get("name", "")).strip() else [],
                "best_strategy": str(strategy.get("name", "")).strip(),
                "best_signal_type": str(payload.get("signal_type", "")).strip(),
                "has_assessment_signal": bool(payload.get("assessment_signal", False)),
            },
            best_observation=observation,
            summary=summary,
        )

    def _record_poc_case(self, state: StepState, payload: dict[str, Any]) -> None:
        status = str(payload.get("status", "")).strip()
        if status != "manual_only":
            return
        source_finding_id = str(payload.get("source_finding_id", "")).strip()
        summary = str(payload.get("summary", "manual POC verification case")).strip()
        lead = self._ensure_lead(
            state,
            title=f"人工 POC 验证用例：{payload.get('category', 'finding')}",
            category="manual_poc_case",
            severity=str(payload.get("source_severity", "medium")).strip() or "medium",
            location=str(payload.get("verification_target", "") or payload.get("source_location", state.step_id)),
            rationale="该上游已验证漏洞暂无可用的安全 Docker 重放模板。",
            evidence=summary,
            next_steps=["使用已记录上下文进行人工跟进。"],
            metadata={"verification_case_status": "manual_only", "source_finding_id": source_finding_id},
        )
        self._ensure_verification(
            state,
            lead=lead,
            method="manual_poc_case",
            status="manual_required",
            summary=summary,
            proof=summary,
            metadata={
                "verification_case_status": "manual_only",
                "source_finding_id": source_finding_id,
                "verification_target": str(payload.get("verification_target", "")).strip(),
            },
        )

    def _promote_ssrf_callback_result(self, state: StepState, payload: dict[str, Any]) -> None:
        hit_count = int(payload.get("hit_count", 0) or 0)
        if hit_count <= 0:
            return
        probe_request = next(
            (
                item
                for item in reversed(state.observations)
                if item.tool_name == "http_request" and isinstance(item.payload, dict) and "callback://" in str(item.payload.get("url", ""))
            ),
            None,
        )
        request_url = str(probe_request.payload.get("url", "")) if probe_request is not None else state.step_id
        callback = _last_callback_endpoint(state)
        context = {
            "page_url": request_url.split("?", 1)[0],
            "request_url": request_url,
            "method": "GET",
            "parameter": "url",
            "source": "oob_callback",
            "reason": f"callback hit count={hit_count}",
            "probe_type": "callback",
            "probe_value": callback,
            "probe_url": callback,
            "baseline_status": 0,
            "probe_status": 200,
            "matched_markers": ["callback-hit"],
        }
        raw = {
            "title": "Confirmed SSRF callback interaction",
            "severity": "high",
            "location": request_url,
            "evidence": json.dumps({"hit_count": hit_count, "request_url": request_url, "callback": callback}, ensure_ascii=False),
            "recommendation": "Restrict outbound fetch targets, validate schemes/hosts, and block loopback and metadata endpoints.",
        }
        self._promote_generic_verified(
            state,
            raw,
            category="ssrf",
            method="oob_callback",
            impact="The application issued a server-side request to a controlled callback target.",
            reproduction_steps=_ssrf_reproduction_steps(context),
            metadata={"ssrf_context": context, "verification_source": "ssrf_triage"},
        )

    def _promote_docker_poc(self, scan: ScanState, state: StepState, payload: dict[str, Any]) -> None:
        parsed = dict(payload.get("parsed", {})) if isinstance(payload.get("parsed", {}), dict) else {}
        if not bool(parsed.get("verified", False)):
            return
        source_finding = _source_finding_for_poc(scan, state)
        if not source_finding:
            return
        metadata = dict(source_finding.metadata)
        metadata["verification_source"] = "docker_poc"
        metadata["sandbox_verified"] = True
        metadata["source_finding_id"] = source_finding.finding_id
        proof = json.dumps(parsed, ensure_ascii=False)
        lead = self._ensure_lead(
            state,
            title=f"沙箱验证通过：{to_user_title(source_finding.title)}",
            category=source_finding.category,
            severity=source_finding.severity,
            location=source_finding.location,
            rationale="Docker 沙箱重放复现了上游验证信号。",
            evidence=proof,
            next_steps=["将沙箱验证证据与源漏洞一并归档。"],
            metadata=metadata,
        )
        verification = self._ensure_verification(
            state,
            lead=lead,
            method="docker_poc",
            status="verified",
            summary="Sandbox docker replay confirmed the upstream finding.",
            proof=proof,
            metadata=metadata,
        )
        self._ensure_finding(
            state,
            title=source_finding.title,
            category=source_finding.category,
            severity=source_finding.severity,
            location=source_finding.location,
            impact=source_finding.impact,
            evidence=proof,
            recommendation=source_finding.recommendation,
            reproduction_steps=list(source_finding.reproduction_steps),
            verification=verification,
            metadata=metadata,
        )

    def _promote_js_findings(self, state: StepState, findings: list[Any]) -> None:
        for raw in findings:
            if not isinstance(raw, dict):
                continue
            metadata = dict(raw.get("metadata", {})) if isinstance(raw.get("metadata", {}), dict) else {}
            context = dict(metadata.get("js_context", {})) if isinstance(metadata.get("js_context", {}), dict) else {}
            category = str(context.get("category", "")).strip()
            if _is_confirmed_raw_finding(raw) and category == "frontend_secret_exposure":
                self._promote_generic_verified(
                    state,
                    raw,
                    category="frontend_secret_exposure",
                    method="static_js_secret_exposure",
                    impact=_first_line(raw.get("evidence", ""), "Browser-delivered JavaScript exposes masked sensitive material."),
                    reproduction_steps=_js_reproduction_steps(context, str(raw.get("location", ""))),
                    metadata={"js_context": context, "verification_source": "js_audit"},
                )
            else:
                self._ensure_lead(
                    state,
                    title="JavaScript 辅助评估",
                    category="js_auxiliary",
                    severity=str(raw.get("severity", "info")).strip() or "info",
                    location=str(raw.get("location", state.step_id)).strip() or state.step_id,
                    rationale="静态 JS 发现仅保留为辅助上下文。",
                    evidence=str(raw.get("evidence", "")).strip(),
                    next_steps=["将该 JS 上下文作为后续清单使用。"],
                    metadata={"js_context": context, "raw_title": str(raw.get("title", ""))},
                )

    def _promote_generic_verified(
        self,
        state: StepState,
        raw: dict[str, Any],
        *,
        category: str,
        method: str,
        impact: str,
        reproduction_steps: list[str],
        metadata: dict[str, Any],
    ) -> None:
        title = to_user_title(str(raw.get("title", "Verified finding")).strip() or "Verified finding")
        severity = str(raw.get("severity", "medium")).strip() or "medium"
        location = str(raw.get("location", state.step_id)).strip() or state.step_id
        evidence = str(raw.get("evidence", "")).strip()
        recommendation = str(raw.get("recommendation", "复核并修复该已验证问题。")).strip()
        lead = self._ensure_lead(
            state,
            title=title,
            category=category,
            severity=severity,
            location=location,
            rationale=_first_line(evidence, "从受控证据提升为已验证漏洞。"),
            evidence=evidence,
            next_steps=["保留验证证据并完成修复复测。"],
            metadata=metadata,
        )
        verification = self._ensure_verification(
            state,
            lead=lead,
            method=method,
            status="verified",
            summary=title,
            proof=evidence,
            metadata=metadata,
        )
        self._ensure_finding(
            state,
            title=title,
            category=category,
            severity=severity,
            location=location,
            impact=impact,
            evidence=evidence,
            recommendation=recommendation,
            reproduction_steps=reproduction_steps or ["复核已记录的验证证据。"],
            verification=verification,
            metadata=metadata,
        )

    def _build_output_context(
        self,
        scan: ScanState | None,
        spec: StepSpec,
        state: StepState,
        step_contexts: dict[str, Any],
    ) -> dict[str, Any]:
        followup_context = state.output_context.get("followup_context", {})
        context: dict[str, Any] = {
            "upstream_steps": sorted(name for name in step_contexts.keys() if name != "child_contributions"),
            "iterations": state.iterations,
            "tool_calls": state.tool_calls,
            "decision_count": len(state.decision_records),
            "llm_fallback_count": int(state.llm_fallback_count),
            "lead_ids": [item.lead_id for item in state.leads],
            "verification_ids": [item.verification_id for item in state.verification_records],
            "verified_finding_ids": [item.finding_id for item in state.verified_findings],
            "artifact_ids": list(state.artifact_ids),
            "followup_context": dict(followup_context) if isinstance(followup_context, dict) else {},
        }

        if spec.name == "recon":
            context["links"] = _collect_observation_list(state, "extract_links_from_html", "links")
            context["forms"] = _collect_observation_list(state, "extract_forms_from_html", "forms")
            context["parameters"] = _collect_observation_list(state, "extract_parameters_from_response", "parameters")
        elif spec.name == "sql_scan":
            context["sql_candidates"] = _collect_sql_candidates_from_state(state)
            context["primary_sql_candidate"] = context["sql_candidates"][0] if context["sql_candidates"] else {}
        elif spec.name == "sql_bypass":
            context["primary_sql_candidate"] = _first_sql_candidate_from_context(step_contexts, state) or {}
            context["strategy_names"] = _collect_strategy_names(state)
            context["assessment_signals"] = _collect_assessment_signals(state)
        elif spec.name == "js_audit":
            context["heuristics"] = _collect_js_heuristics(state)
            context["endpoint_candidates"] = _collect_endpoint_candidates(state)
            context["route_candidates"] = list(context["endpoint_candidates"])
        elif spec.name == "xss_triage":
            context["xss_locations"] = [item.location for item in state.verified_findings if item.category == "xss"]
            context["reflected_probe_urls"] = [
                str(item.payload.get("url", ""))
                for item in state.observations
                if item.tool_name == "replay_request_with_mutation" and isinstance(item.payload, dict) and str(item.payload.get("url", "")).strip()
            ]
        elif spec.name == "ssrf_triage":
            context["callback_hit_count"] = _collect_callback_hits(state)
            context["ssrf_locations"] = [item.location for item in state.verified_findings if item.category == "ssrf"]
            context["ssrf_contexts"] = [dict(item.metadata.get("ssrf_context", {})) for item in state.verified_findings if isinstance(item.metadata.get("ssrf_context", {}), dict)]
        elif spec.name == "permission_bypass":
            checked_urls = []
            for finding in state.verified_findings:
                if finding.category != "authorization":
                    continue
                context_payload = finding.metadata.get("permission_context", {})
                if isinstance(context_payload, dict) and str(context_payload.get("url", "")).strip():
                    checked_urls.append(str(context_payload.get("url", "")).strip())
            if not checked_urls:
                checked_urls = [state.observations[-1].payload.get("url", "")] if state.observations and isinstance(state.observations[-1].payload, dict) else []
            context["checked_urls"] = [item for item in checked_urls if str(item).strip()]
            context["differential_signals"] = _collect_differential_signals(state)
        elif spec.name == "config_audit":
            context["config_locations"] = [item.location for item in state.verified_findings if item.category == "config_exposure"]
            context["config_contexts"] = [dict(item.metadata.get("config_context", {})) for item in state.verified_findings if isinstance(item.metadata.get("config_context", {}), dict)]
        elif spec.name == "cors_audit":
            context["cors_locations"] = [item.location for item in state.verified_findings if item.category == "cors"]
            context["cors_contexts"] = [dict(item.metadata.get("cors_context", {})) for item in state.verified_findings if isinstance(item.metadata.get("cors_context", {}), dict)]
        elif spec.name == "jwt_audit":
            context["jwt_locations"] = [item.location for item in state.verified_findings if item.category == "jwt"]
            context["jwt_contexts"] = [dict(item.metadata.get("jwt_context", {})) for item in state.verified_findings if isinstance(item.metadata.get("jwt_context", {}), dict)]
        elif spec.name == "poc_verify":
            context["consumed_verified_finding_ids"] = [
                str(item.payload.get("source_finding_id", ""))
                for item in state.observations
                if item.tool_name == "generate_poc_verification_case" and isinstance(item.payload, dict) and str(item.payload.get("source_finding_id", "")).strip()
            ]
            context["sandbox_verified_finding_ids"] = [
                item.finding_id for item in state.verified_findings if bool(item.metadata.get("sandbox_verified", False))
            ]
            child = step_contexts.get("child_contributions", {})
            recommendations = child.get("recommended_next_tests", []) if isinstance(child, dict) else []
            context["consumed_child_recommendations"] = [dict(item) for item in recommendations if isinstance(item, dict)]

        return context


class AgentLoop:
    def __init__(
        self,
        profile: AgentProfile,
        plan: ScanPlan,
        tool_registry: ToolRegistry,
        skills: SkillCatalog | None,
    ):
        self.profile = profile
        self.plan = plan
        self.tool_registry = tool_registry
        self.evidence_gate = EvidenceGate()
        self.step_executor = StepExecutor(tool_registry, self.evidence_gate, profile, skills)

    def new_scan(self, scan_id: str) -> ScanState:
        step_states = {step.step_id: StepState(step_id=step.step_id) for step in self.plan.steps}
        return ScanState(
            scan_id=scan_id,
            target=self.plan.target,
            profile=self.profile,
            stage="plan",
            plan=self.plan,
            status="ready",
            step_states=step_states,
        )

    def run_next_step(self, scan: ScanState, *, legacy_context: dict[str, Any] | None = None) -> ScanState:
        scan.updated_at = now_iso()
        self._emit(scan, "step", "loop_start", f"scan loop evaluating {len(scan.plan.steps)} planned steps.")
        ready = [
            step
            for step in scan.plan.steps
            if scan.step_states[step.step_id].status == "pending"
            and all(_dependency_satisfied_for_step(scan, step, item) for item in step.depends_on)
        ]
        if not ready:
            scan.stage = "step_replan"
            self._emit(scan, "step_replan", "no_ready_step", "no ready step was available.")
            if all(item.status in {"completed", "failed", "blocked"} for item in scan.step_states.values()):
                scan.stage = "final_answer"
                scan.status = "completed"
                scan.summary = self._summary(scan)
                self._emit(scan, "final_answer", "scan_completed", scan.summary)
            return scan

        scan.stage = "step"
        step = ready[0]
        step_state = self.step_executor.execute(scan, step, scan.step_states[step.step_id])
        scan.step_states[step.step_id] = step_state
        self._merge_step_findings(scan, step_state)
        scan.stage = "step_replan"
        self._emit(
            scan,
            "step_replan",
            "step_completed",
            f"step {step.name} completed with status {step_state.status}.",
            {"step_id": step.step_id},
        )
        if all(item.status in {"completed", "failed", "blocked"} for item in scan.step_states.values()):
            scan.stage = "final_answer"
            scan.status = "completed"
            scan.summary = self._summary(scan)
            self._emit(scan, "final_answer", "scan_completed", scan.summary)
        return scan

    def continue_until_pause(self, scan: ScanState, *, legacy_context: dict[str, Any] | None = None) -> ScanState:
        max_rounds = max(len(scan.plan.steps) + 2, 2)
        for _ in range(max_rounds):
            before = [(key, value.status) for key, value in scan.step_states.items()]
            updated = self.run_next_step(scan, legacy_context=legacy_context)
            after = [(key, value.status) for key, value in updated.step_states.items()]
            scan = updated
            if scan.status == "completed":
                break
            if before == after and scan.stage == "step_replan":
                break
        return scan

    def _summary(self, scan: ScanState) -> str:
        return f"scan completed: steps={len(scan.plan.steps)}; verified_findings={len(scan.verified_findings)}; artifacts={len(scan.artifacts)}"

    def _emit(self, scan: ScanState, stage: str, kind: str, message: str, payload: dict[str, Any] | None = None) -> None:
        scan.events.append(
            AgentEvent(
                event_id=make_id("evt"),
                stage=stage,
                kind=kind,
                message=message,
                payload=dict(payload or {}),
            )
        )

    def _merge_step_findings(self, scan: ScanState, state: StepState) -> None:
        existing = {item.finding_id for item in scan.verified_findings}
        for finding in state.verified_findings:
            if finding.finding_id not in existing:
                scan.verified_findings.append(finding)
                existing.add(finding.finding_id)


def _is_confirmed_raw_finding(raw: Any) -> bool:
    if not isinstance(raw, dict):
        return False
    if str(raw.get("kind", "")).strip() != "vulnerability":
        return False
    if str(raw.get("verification_status", "")).strip() != "confirmed":
        return False
    return bool(raw.get("verified", False))


def _collect_observation_list(state: StepState, tool_name: str, payload_key: str) -> list[Any]:
    values: list[Any] = []
    for observation in state.observations:
        if observation.tool_name != tool_name or not isinstance(observation.payload, dict):
            continue
        payload_value = observation.payload.get(payload_key, [])
        if isinstance(payload_value, list):
            values.extend(payload_value)
    return values


def _collect_sql_candidates_from_state(state: StepState) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for observation in state.observations:
        if not isinstance(observation.payload, dict):
            continue
        payload_candidates = observation.payload.get("candidates", [])
        if isinstance(payload_candidates, list):
            for item in payload_candidates:
                if isinstance(item, dict):
                    candidates.append(dict(item))
        payload_candidate = observation.payload.get("candidate", {})
        if isinstance(payload_candidate, dict) and payload_candidate:
            candidates.append(dict(payload_candidate))
    deduped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in candidates:
        key = (
            str(item.get("page_url", "")),
            str(item.get("method", "")),
            str(item.get("parameter", "")),
        )
        deduped[key] = item
    return list(deduped.values())


def _first_sql_candidate_from_context(step_contexts: dict[str, Any], state: StepState) -> dict[str, Any] | None:
    sql_context = step_contexts.get("sql_scan", {}) if isinstance(step_contexts.get("sql_scan", {}), dict) else {}
    primary = sql_context.get("primary_sql_candidate", {})
    if isinstance(primary, dict) and primary:
        return dict(primary)
    sql_candidates = sql_context.get("sql_candidates", [])
    if isinstance(sql_candidates, list) and sql_candidates and isinstance(sql_candidates[0], dict):
        return dict(sql_candidates[0])
    state_candidates = _collect_sql_candidates_from_state(state)
    return dict(state_candidates[0]) if state_candidates else None


def _match_sql_candidate_for_finding(raw: dict[str, Any], candidates: Any) -> dict[str, Any]:
    metadata = raw.get("metadata", {}) if isinstance(raw.get("metadata", {}), dict) else {}
    if isinstance(metadata.get("sql_candidate", {}), dict) and metadata.get("sql_candidate", {}):
        return dict(metadata.get("sql_candidate", {}))
    location = str(raw.get("location", "")).strip()
    title = str(raw.get("title", "")).strip()
    if not isinstance(candidates, list):
        return {}
    for item in candidates:
        if not isinstance(item, dict):
            continue
        source_location = str(item.get("source_location", "")).strip()
        source_title = str(item.get("source_title", "")).strip()
        page_url = str(item.get("page_url", "")).strip()
        parameter = str(item.get("parameter", "")).strip()
        if source_location and source_location == location:
            return dict(item)
        if source_title and source_title == title:
            return dict(item)
        if page_url and parameter and page_url in location and parameter in title.lower():
            return dict(item)
    return {}


def _sql_verification_method(candidate: dict[str, Any]) -> str:
    basis = str(candidate.get("basis", "")).lower()
    strategies = {str(item).strip().lower() for item in candidate.get("confirmed_strategies", [])} if isinstance(candidate.get("confirmed_strategies", []), list) else set()
    if "time" in basis or "time_delay" in strategies:
        return "time_differential"
    if "boolean" in basis:
        return "boolean_differential"
    return "sql_differential"


def _sql_reproduction_steps(candidate: dict[str, Any]) -> list[str]:
    page_url = str(candidate.get("page_url", "")).strip()
    parameter = str(candidate.get("parameter", "")).strip()
    method = str(candidate.get("method", "GET") or "GET").upper()
    baseline_url = str(candidate.get("baseline_url", "")).strip()
    steps = []
    if baseline_url:
        steps.append(f"Send the baseline {method} request to {baseline_url}.")
    if page_url and parameter:
        steps.append(f"Replay {method} against {page_url} with controlled parameter {parameter}.")
    if candidate.get("confirmed_strategies"):
        strategies = ", ".join(str(item) for item in candidate.get("confirmed_strategies", [])[:4])
        steps.append(f"Apply the confirmed strategy set: {strategies}.")
    return steps[:4] or ["Review the bounded SQL verification evidence."]


def _xss_verification_method(candidate: dict[str, Any]) -> str:
    context = str(candidate.get("context", "")).lower()
    if "script" in context:
        return "browser_script_context"
    if "href" in context:
        return "browser_href_context"
    if "attribute" in context:
        return "browser_attribute_context"
    return "browser_dom_execution_context"


def _xss_reproduction_steps(candidate: dict[str, Any]) -> list[str]:
    page_url = str(candidate.get("page_url", "")).strip()
    request_url = str(candidate.get("request_url", "")).strip()
    parameter = str(candidate.get("parameter", "")).strip()
    method = str(candidate.get("method", "GET") or "GET").upper()
    steps = []
    if page_url and parameter:
        steps.append(f"Replay {method} against {page_url} with controlled parameter {parameter}.")
    if request_url and method == "GET":
        steps.append(f"Open the controlled URL {request_url}.")
    return steps[:4] or ["Review the browser-side XSS proof."]


def _ssrf_reproduction_steps(context: dict[str, Any]) -> list[str]:
    page_url = str(context.get("page_url", "")).strip()
    request_url = str(context.get("request_url", "")).strip()
    probe_url = str(context.get("probe_url", "")).strip()
    parameter = str(context.get("parameter", "")).strip()
    steps = []
    if page_url and parameter:
        steps.append(f"Replay the SSRF entry page {page_url} and control parameter {parameter}.")
    if request_url:
        steps.append(f"Replay the recorded request {request_url}.")
    if probe_url:
        steps.append(f"Use the controlled internal/OOB probe value {probe_url}.")
    steps.append("Confirm the matched internal markers or callback proof.")
    return steps[:4]


def _ssrf_verification_method(context: dict[str, Any]) -> str:
    probe_type = str(context.get("probe_type", "")).strip().lower()
    if "callback" in probe_type or "oob" in probe_type:
        return "oob_callback"
    if any(marker in probe_type for marker in ("loopback", "internal", "reflection")):
        return "internal_content_reflection"
    return "ssrf_structured_proof"


def _backup_reproduction_steps(context: dict[str, Any], location: str) -> list[str]:
    path = str(context.get("path", "")).strip()
    status_code = int(context.get("status_code", 0) or 0)
    steps = [f"GET {location}."]
    if path:
        steps.append(f"Confirm the exposed artifact path {path}.")
    if status_code:
        steps.append(f"Confirm the passive exposure returned HTTP {status_code}.")
    steps.append("Review the masked source/config evidence from the artifact.")
    return steps[:4]


def _config_reproduction_steps(context: dict[str, Any], location: str) -> list[str]:
    path = str(context.get("path", "")).strip() or location
    evidence_kind = str(context.get("evidence_kind", "")).strip()
    steps = [f"Review the exposed configuration location {path}."]
    if evidence_kind:
        steps.append(f"Confirm the configuration evidence kind {evidence_kind}.")
    if context.get("db_hosts"):
        steps.append("Validate that the exposed configuration contains database connectivity indicators.")
    steps.append("Check for secret material, debug toggles, or weak deployment defaults in the exposed config.")
    return steps[:4]


def _config_verification_method(context: dict[str, Any]) -> str:
    evidence_kind = str(context.get("evidence_kind", "")).strip().lower()
    if "secret" in evidence_kind:
        return "config_secret_exposure"
    if "weak" in evidence_kind or "runtime" in evidence_kind:
        return "config_weak_runtime_review"
    return "config_context_review"


def _cors_reproduction_steps(context: dict[str, Any]) -> list[str]:
    url = str(context.get("url", "")).strip()
    probe_origin = str(context.get("probe_origin", "")).strip()
    steps = []
    if url:
        steps.append(f"Send a GET request to {url}.")
    if probe_origin:
        steps.append(f"Set Origin: {probe_origin}.")
    steps.append("Confirm Access-Control-Allow-Origin and Access-Control-Allow-Credentials in the response headers.")
    return steps[:4]


def _cors_verification_method(context: dict[str, Any]) -> str:
    risk = str(context.get("risk", "")).strip().lower()
    if "origin_reflection_credentials" in risk:
        return "cors_origin_reflection_credentials"
    if "wildcard" in risk:
        return "cors_wildcard_credentials"
    if "null" in risk:
        return "cors_null_origin_credentials"
    return "cors_header_review"


def _jwt_reproduction_steps(context: dict[str, Any]) -> list[str]:
    url = str(context.get("url", "")).strip()
    steps = []
    if url:
        steps.append(f"Fetch the response from {url}.")
    steps.append("Extract the JWT-like token from the response body.")
    steps.append("Base64url-decode the JWT header and payload and review the masked evidence.")
    return steps[:4]


def _jwt_verification_method(context: dict[str, Any]) -> str:
    issue = str(context.get("issue", "")).strip().lower()
    if "alg=none" in issue:
        return "jwt_none_algorithm_decode"
    if "empty_signature" in issue:
        return "jwt_empty_signature_decode"
    if "sensitive_claims" in issue:
        return "jwt_sensitive_claim_decode"
    return "jwt_static_review"


def _js_reproduction_steps(context: dict[str, Any], location: str) -> list[str]:
    script = str(context.get("script", "")).strip() or location
    line = int(context.get("line", 0) or 0)
    steps = [f"GET {script}."]
    if line:
        steps.append(f"Review JavaScript line {line} for the masked sensitive assignment.")
    if str(context.get("rule_id", "")).strip():
        steps.append(f"Confirm the matched secret rule {context.get('rule_id')}.")
    return steps[:4]


def _permission_reproduction_steps(context: dict[str, Any]) -> list[str]:
    url = str(context.get("url", "")).strip()
    parameter = str(context.get("parameter", "")).strip()
    steps = []
    if url:
        steps.append(f"Replay the protected request to {url} across multiple identities.")
    if parameter:
        steps.append(f"Mutate identifier parameter {parameter} across object boundaries.")
    steps.append("Compare status codes and sensitive response markers across identities.")
    return steps[:4]


def _permission_verification_method(context: dict[str, Any]) -> str:
    context_type = str(context.get("type", "")).strip().lower()
    source = str(context.get("source", "")).strip().lower()
    if "vertical" in context_type or "privileged_route" in source:
        return "authenticated_privileged_route_replay"
    if "authenticated" in context_type or "authenticated" in source:
        return "authenticated_idor_object_access"
    if context.get("parameter"):
        return "idor_parameter_differential"
    return "differential_access"


def _weak_password_reproduction_steps(context: dict[str, Any]) -> list[str]:
    page_url = str(context.get("page_url", "")).strip()
    action = str(context.get("action", "")).strip()
    method = str(context.get("method", "POST") or "POST").upper()
    username = str(context.get("username", "")).strip()
    steps = []
    if page_url:
        steps.append(f"Open the login page {page_url}.")
    if action:
        steps.append(f"Submit the {method} login form to {action}.")
    if username:
        steps.append(f"Use username={username} with the recorded masked weak/default password candidate.")
    steps.append("Confirm authenticated response markers such as logout/profile/dashboard or a post-login URL.")
    return steps[:4]


def _collect_strategy_names(state: StepState) -> list[str]:
    names: list[str] = []
    for observation in state.observations:
        payload = observation.payload if isinstance(observation.payload, dict) else {}
        strategy = payload.get("strategy", {})
        if isinstance(strategy, dict) and strategy.get("name"):
            names.append(str(strategy.get("name")))
        strategies = payload.get("strategies", [])
        if isinstance(strategies, list):
            for item in strategies:
                if isinstance(item, dict) and item.get("name"):
                    names.append(str(item.get("name")))
    return sorted(dict.fromkeys(names))


def _collect_assessment_signals(state: StepState) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for observation in state.observations:
        payload = observation.payload if isinstance(observation.payload, dict) else {}
        if "assessment_signal" not in payload and "signal_type" not in payload:
            continue
        signals.append(
            {
                "tool_name": observation.tool_name,
                "assessment_signal": payload.get("assessment_signal"),
                "signal_type": payload.get("signal_type", ""),
                "basis": payload.get("basis", ""),
            }
        )
    return signals


def _collect_callback_hits(state: StepState) -> int:
    hit_count = 0
    for observation in state.observations:
        if observation.tool_name != "poll_callback_events" or not isinstance(observation.payload, dict):
            continue
        hit_count = max(hit_count, int(observation.payload.get("hit_count", 0) or 0))
    return hit_count


def _collect_differential_signals(state: StepState) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for observation in state.observations:
        if observation.tool_name != "compare_http_responses" or not isinstance(observation.payload, dict):
            continue
        signals.append(
            {
                "status_changed": bool(observation.payload.get("status_changed", False)),
                "added_chars": int(observation.payload.get("added_chars", 0) or 0),
                "removed_chars": int(observation.payload.get("removed_chars", 0) or 0),
                "suspicious_difference": bool(observation.payload.get("suspicious_difference", False)),
            }
        )
    return signals


def _collect_js_heuristics(state: StepState) -> dict[str, int]:
    heuristics = {"eval_calls": 0, "inner_html": 0, "dangerous_sources": 0}
    for observation in state.observations:
        if observation.tool_name != "parse_js_ast" or not isinstance(observation.payload, dict):
            continue
        for key in heuristics:
            heuristics[key] = max(heuristics[key], int(observation.payload.get(key, 0) or 0))
    return heuristics


def _collect_endpoint_candidates(state: StepState) -> list[str]:
    endpoints: list[str] = []
    for observation in state.observations:
        if not isinstance(observation.payload, dict):
            continue
        if observation.tool_name == "extract_js_endpoints":
            items = observation.payload.get("endpoint_candidates", [])
        elif observation.tool_name == "parse_js_ast":
            items = observation.payload.get("endpoint_candidates", [])
        elif observation.tool_name == "extract_fetch_calls":
            raw_calls = observation.payload.get("fetch_calls", [])
            items = [item.get("url", "") for item in raw_calls if isinstance(item, dict)] if isinstance(raw_calls, list) else []
        elif observation.tool_name == "js_audit_bridge":
            followup = observation.payload.get("followup_context", {})
            if isinstance(followup, dict):
                items = []
                for key in ("api_paths", "auth_paths", "route_prefixes", "endpoint_candidates"):
                    value = followup.get(key, [])
                    if isinstance(value, list):
                        items.extend(value)
            else:
                items = []
        else:
            items = []
        if isinstance(items, list):
            for item in items:
                value = str(item).strip()
                if value and value not in endpoints:
                    endpoints.append(value)
    return endpoints


def _fallback_xss_candidate_from_state(state: StepState) -> dict[str, Any]:
    request_url = ""
    method = "GET"
    parameter = "message"
    for observation in reversed(state.observations):
        payload = observation.payload if isinstance(observation.payload, dict) else {}
        if observation.tool_name == "replay_request_with_mutation":
            if observation.status != "ok":
                return {}
            if int(payload.get("status_code", 0) or 0) <= 0 or str(payload.get("error", "")).strip():
                return {}
            body = str(payload.get("body", "") or payload.get("truncated_body", ""))
            decoded_url = unquote(str(payload.get("url", "")))
            if not _xss_replay_contains_controlled_marker(body, decoded_url):
                return {}
            request_url = str(payload.get("url", "")).strip()
            method = str(payload.get("method", "GET") or "GET").upper()
            parameter = str(payload.get("parameter", parameter)).strip() or parameter
            break
    if not request_url:
        return {}
    page_url = request_url.split("?", 1)[0]
    return {
        "page_url": page_url,
        "request_url": request_url,
        "method": method,
        "parameter": parameter,
        "context": "html",
        "basis": "Bounded reflected replay generated a controllable XSS marker path and browser-side evidence artifact.",
    }


def _xss_replay_contains_controlled_marker(body: str, decoded_url: str) -> bool:
    lowered_body = body.lower()
    lowered_url = decoded_url.lower()
    markers = ("<script", "alert(1)", "<svg", "onload=", "onerror=", "xss_marker")
    return any(marker in lowered_url and marker in lowered_body for marker in markers)


def _dependency_satisfied_for_step(scan: ScanState, step: StepSpec, dependency_step_id: str) -> bool:
    status = scan.step_states[dependency_step_id].status
    if status == "completed":
        return True
    return step.name == "poc_verify" and status in {"blocked", "failed"}


def _fallback_permission_context_from_state(state: StepState) -> dict[str, Any]:
    comparison = None
    for observation in reversed(state.observations):
        if observation.tool_name == "compare_http_responses" and isinstance(observation.payload, dict):
            comparison = dict(observation.payload)
            break
    if not comparison or not bool(comparison.get("suspicious_difference", False)):
        return {}
    replay_payload = {}
    for observation in reversed(state.observations):
        if observation.tool_name == "same_request_different_session_replay" and isinstance(observation.payload, dict):
            replay_payload = dict(observation.payload)
            break
    responses = replay_payload.get("responses", []) if isinstance(replay_payload.get("responses", []), list) else []
    first_url = ""
    baseline = {}
    mutated = {}
    if responses and isinstance(responses[0], dict):
        baseline = dict(responses[0])
        first_url = str(baseline.get("url", "")).strip()
    if len(responses) > 1 and isinstance(responses[1], dict):
        mutated = dict(responses[1])
        first_url = first_url or str(mutated.get("url", "")).strip()
    return {
        "url": first_url,
        "type": "role_differential",
        "method": "GET",
        "parameter": "role",
        "baseline_value": "admin",
        "mutated_value": "guest",
        "baseline": baseline,
        "mutated": mutated,
        "basis": (
            "Bounded dual-session replay produced suspicious authorization differential: "
            f"status_changed={bool(comparison.get('status_changed', False))}, "
            f"added_chars={int(comparison.get('added_chars', 0) or 0)}, "
            f"removed_chars={int(comparison.get('removed_chars', 0) or 0)}"
        ),
    }


def _last_callback_endpoint(state: StepState) -> str:
    for observation in reversed(state.observations):
        if observation.tool_name == "create_callback_endpoint" and isinstance(observation.payload, dict):
            endpoint = str(observation.payload.get("endpoint", "")).strip()
            if endpoint:
                return endpoint
    return ""


def _first_ssrf_probe_target(step_contexts: dict[str, Any], target: str) -> str:
    ssrf_context = step_contexts.get("ssrf_triage", {}) if isinstance(step_contexts.get("ssrf_triage", {}), dict) else {}
    locations = ssrf_context.get("ssrf_locations", [])
    if isinstance(locations, list):
        for item in locations:
            value = str(item).strip()
            if value:
                return value
    return f"{target.rstrip('/')}?url=http://example.test"


def _source_finding_for_poc(scan: ScanState, state: StepState) -> VerifiedFinding | None:
    source_finding_id = ""
    for observation in reversed(state.observations):
        if observation.tool_name == "run_poc_in_docker" and isinstance(observation.payload, dict):
            source_finding_id = str(observation.payload.get("source_finding_id", "")).strip()
            if source_finding_id:
                break
        if observation.tool_name == "generate_poc_verification_case" and isinstance(observation.payload, dict):
            source_finding_id = str(observation.payload.get("source_finding_id", "")).strip()
            if source_finding_id:
                break
    if not source_finding_id:
        return None
    for finding in scan.verified_findings:
        if finding.finding_id == source_finding_id:
            return finding
    return None
