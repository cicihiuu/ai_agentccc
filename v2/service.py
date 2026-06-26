from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urljoin
from uuid import uuid4

from ai_security_agent.integrations.readiness import _ollama_readiness
from ai_security_agent.llm import LLMError, complete_json_object
from ai_security_agent.llm.provider_registry import get_provider_spec, provider_api_key_envs

from .engine import AgentLoop, LLMDecisionEngine, SubAgentRunner
from .planner import build_plan
from .profiles import load_profile
from .reporting import ReportBuilder
from .skills import SkillCatalog
from .task_modes import module_bundle_label, module_bundle_skills, normalize_module_bundle, normalize_task_mode, task_mode_spec
from .tools import ToolRegistry
from .models import AgentEvent, make_id, now_iso


class AgentService:
    def __init__(self, *, project_root: Path | None = None):
        root = project_root or Path(__file__).resolve().parents[3]
        self.project_root = root
        self.profile_dir = root / "profiles"
        self.skill_dir = root / "skills"
        self.run_dir = root / "runs"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.skill_catalog = SkillCatalog(self.skill_dir)
        self.subagent_runner = SubAgentRunner(self._run_subagent, max_workers=2)

    def list_profiles(self) -> list[dict[str, Any]]:
        profiles = []
        for path in sorted(self.profile_dir.glob("*.yaml")):
            profile = load_profile(path)
            profiles.append(profile.to_dict())
        return profiles

    def create_scan(
        self,
        target: str,
        *,
        profile_name: str = "blackbox_web",
        module_bundle: str = "full",
        task_mode: str = "",
        provider_name: str = "",
        model_id: str = "",
        base_url: str = "",
    ) -> dict[str, Any]:
        profile = load_profile(self.profile_dir / f"{profile_name}.yaml")
        profile = self._apply_llm_overrides(
            profile,
            provider_name=provider_name,
            model_id=model_id,
            base_url=base_url,
        )
        mode = normalize_task_mode(task_mode)
        if mode:
            spec = task_mode_spec(mode)
            bundle = self._normalize_module_bundle(spec.module_bundle)
            runtime_profile = self._profile_for_skill_names(
                profile,
                spec.skill_names,
                max_parallel_steps=spec.max_parallel_steps,
            )
            task_label = spec.label
        else:
            bundle = self._normalize_module_bundle(module_bundle)
            runtime_profile = self._profile_for_bundle(profile, bundle)
            mode = "blackbox_pentest" if bundle == "full" else ""
            task_label = "黑盒 Web 渗透" if bundle == "full" else module_bundle_label(bundle)
        plan = build_plan(
            target,
            runtime_profile,
            self.skill_catalog,
            module_bundle=bundle,
            task_mode=mode,
            task_mode_label=task_label,
        )
        scan_id = str(uuid4())
        workspace = self.run_dir / scan_id
        registry = ToolRegistry(workspace / "artifacts")
        loop = AgentLoop(runtime_profile, plan, registry, self.skill_catalog)
        scan = loop.new_scan(scan_id)
        scan.provider_status = self._provider_status(runtime_profile)
        self._save(scan)
        return self._snapshot(scan)

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        scan = self._load(scan_id)
        self._collect_subagents(scan)
        pending = self._pending_confirmations(scan)
        if pending:
            if scan.status != "manual_required":
                scan = self._pause_for_pending_confirmations(scan, pending, action="inspect")
                self._save(scan)
            return self._snapshot(scan)
        self._maybe_spawn_subagents(scan)
        self._save(scan)
        return self._snapshot(scan)

    def step_scan(self, scan_id: str) -> dict[str, Any]:
        scan = self._load(scan_id)
        self._collect_subagents(scan)
        pending = self._pending_confirmations(scan)
        if pending:
            updated = self._pause_for_pending_confirmations(scan, pending, action="step")
            self._save(updated)
            return self._snapshot(updated)
        self._maybe_spawn_subagents(scan)
        workspace = self.run_dir / scan_id
        registry = ToolRegistry(workspace / "artifacts")
        loop = AgentLoop(scan.profile, scan.plan, registry, self.skill_catalog)
        updated = loop.run_next_step(scan)
        pending = self._pending_confirmations(updated)
        if pending:
            updated = self._pause_for_pending_confirmations(updated, pending, action="step")
            self._save(updated)
            return self._snapshot(updated)
        self._maybe_spawn_subagents(updated)
        self._collect_subagents(updated)
        self._save(updated)
        return self._snapshot(updated)

    def step_scan_parallel(self, scan_id: str) -> dict[str, Any]:
        scan = self._load(scan_id)
        self._collect_subagents(scan)
        pending = self._pending_confirmations(scan)
        if pending:
            updated = self._pause_for_pending_confirmations(scan, pending, action="step_parallel")
            self._save(updated)
            return self._snapshot(updated)
        self._maybe_spawn_subagents(scan)
        updated = self._run_ready_steps_parallel(scan)
        pending = self._pending_confirmations(updated)
        if pending:
            updated = self._pause_for_pending_confirmations(updated, pending, action="step_parallel")
            self._save(updated)
            return self._snapshot(updated)
        self._maybe_spawn_subagents(updated)
        self._collect_subagents(updated)
        self._save(updated)
        return self._snapshot(updated)

    def continue_scan(self, scan_id: str) -> dict[str, Any]:
        scan = self._load(scan_id)
        pending = self._pending_confirmations(scan)
        if pending:
            updated = self._pause_for_pending_confirmations(scan, pending, action="continue")
            self._save(updated)
            return self._snapshot(updated)
        updated = scan
        max_rounds = max(len(updated.plan.steps) + 2, 2)
        for _ in range(max_rounds):
            before = [state.status for state in updated.step_states.values()]
            updated = self._run_ready_steps_parallel(updated)
            self._save(updated)
            pending = self._pending_confirmations(updated)
            if pending:
                updated = self._pause_for_pending_confirmations(updated, pending, action="continue")
                self._save(updated)
                break
            self._maybe_spawn_subagents(updated)
            self._collect_subagents_until_quiet(updated, max_wait_seconds=0.2)
            self._maybe_spawn_subagents(updated)
            self._save(updated)
            after = [state.status for state in updated.step_states.values()]
            if updated.status == "completed":
                break
            if before == after and updated.stage == "step_replan":
                break
        pending = self._pending_confirmations(updated)
        if not pending:
            self._collect_subagents(updated)
            self._maybe_spawn_subagents(updated)
        self._save(updated)
        return self._snapshot(updated)

    def approve_manual_confirmation(self, scan_id: str, verification_id: str, *, note: str = "") -> dict[str, Any]:
        scan = self._load(scan_id)
        confirmation = self._manual_confirmation_by_id(scan, verification_id)
        if not confirmation:
            raise ValueError(f"manual confirmation not found: {verification_id}")
        scan.manual_approvals[verification_id] = {
            "status": "approved",
            "lead_id": confirmation.get("lead_id", ""),
            "source_finding_id": confirmation.get("source_finding_id", ""),
            "step_id": confirmation.get("step_id", ""),
            "created_at": scan.manual_approvals.get(verification_id, {}).get("created_at", confirmation.get("created_at", now_iso())),
            "updated_at": now_iso(),
            "note": str(note or "").strip(),
        }
        remaining = self._pending_confirmations(scan)
        if scan.status == "manual_required":
            if remaining:
                scan.summary = f"pending_manual_confirmations={len(remaining)}"
            else:
                scan.status = "ready"
                scan.summary = ""
        self._append_unique_event(
            scan,
            AgentEvent(
                event_id=make_id("evt"),
                stage="step_replan",
                kind="human_gate_approved",
                message=f"manual confirmation approved: {verification_id}",
                payload={"verification_id": verification_id, "lead_id": confirmation.get("lead_id", "")},
            ),
        )
        self._save(scan)
        return self._snapshot(scan)

    def deny_manual_confirmation(self, scan_id: str, verification_id: str, *, note: str = "") -> dict[str, Any]:
        scan = self._load(scan_id)
        confirmation = self._manual_confirmation_by_id(scan, verification_id)
        if not confirmation:
            raise ValueError(f"manual confirmation not found: {verification_id}")
        scan.manual_approvals[verification_id] = {
            "status": "denied",
            "lead_id": confirmation.get("lead_id", ""),
            "source_finding_id": confirmation.get("source_finding_id", ""),
            "step_id": confirmation.get("step_id", ""),
            "created_at": scan.manual_approvals.get(verification_id, {}).get("created_at", confirmation.get("created_at", now_iso())),
            "updated_at": now_iso(),
            "note": str(note or "").strip(),
        }
        remaining = self._pending_confirmations(scan)
        if scan.status == "manual_required":
            if remaining:
                scan.summary = f"pending_manual_confirmations={len(remaining)}"
            else:
                scan.status = "ready"
                scan.summary = ""
        self._append_unique_event(
            scan,
            AgentEvent(
                event_id=make_id("evt"),
                stage="step_replan",
                kind="human_gate_denied",
                message=f"manual confirmation denied: {verification_id}",
                payload={"verification_id": verification_id, "lead_id": confirmation.get("lead_id", "")},
            ),
        )
        self._save(scan)
        return self._snapshot(scan)

    def _run_ready_steps_parallel(self, scan):
        pending = self._pending_confirmations(scan)
        if pending:
            return self._pause_for_pending_confirmations(scan, pending, action="parallel")
        ready_steps = self._ready_steps(scan)
        if not ready_steps:
            workspace = self.run_dir / scan.scan_id
            registry = ToolRegistry(workspace / "artifacts")
            return AgentLoop(scan.profile, scan.plan, registry, self.skill_catalog).run_next_step(scan)
        max_workers = max(1, int(getattr(scan.profile, "max_parallel_steps", 1) or 1))
        if max_workers <= 1 or len(ready_steps) == 1:
            workspace = self.run_dir / scan.scan_id
            registry = ToolRegistry(workspace / "artifacts")
            return AgentLoop(scan.profile, scan.plan, registry, self.skill_catalog).run_next_step(scan)
        selected = ready_steps[:max_workers]
        base_snapshot = scan.to_dict()
        workspace = self.run_dir / scan.scan_id
        results = []
        with ThreadPoolExecutor(max_workers=len(selected)) as executor:
            futures = {
                executor.submit(self._execute_step_from_snapshot, base_snapshot, step.step_id, workspace): step
                for step in selected
            }
            for future in as_completed(futures):
                results.append((futures[future], future.result()))
        scan.updated_at = now_iso()
        scan.stage = "step"
        for step, result in sorted(results, key=lambda item: self._step_index(scan, item[0].step_id)):
            step_state, artifacts, events = result
            scan.step_states[step.step_id] = step_state
            for artifact in artifacts:
                scan.artifacts[artifact.artifact_id] = artifact
            existing_finding_ids = {item.finding_id for item in scan.verified_findings}
            for finding in step_state.verified_findings:
                if finding.finding_id not in existing_finding_ids:
                    scan.verified_findings.append(finding)
                    existing_finding_ids.add(finding.finding_id)
            scan.events.extend(events)
            scan.events.append(
                AgentEvent(
                    event_id=make_id("evt"),
                    stage="step_replan",
                    kind="step_completed",
                    message=f"step {step.name} parallel completed with status {step_state.status}.",
                    payload={"step_id": step.step_id, "parallel": True},
                )
            )
        scan.stage = "step_replan"
        if all(item.status in {"completed", "failed", "blocked"} for item in scan.step_states.values()):
            scan.stage = "final_answer"
            scan.status = "completed"
            scan.summary = f"扫描完成：steps={len(scan.plan.steps)}，verified_findings={len(scan.verified_findings)}，artifacts={len(scan.artifacts)}"
            scan.events.append(
                AgentEvent(
                    event_id=make_id("evt"),
                    stage="final_answer",
                    kind="scan_completed",
                    message=scan.summary,
                )
            )
        return scan

    def _execute_step_from_snapshot(self, payload: dict[str, Any], step_id: str, workspace: Path):
        scan = self._scan_from_payload(payload)
        step = next(item for item in scan.plan.steps if item.step_id == step_id)
        registry = ToolRegistry(workspace / "artifacts" / step_id)
        loop = AgentLoop(scan.profile, scan.plan, registry, self.skill_catalog)
        before_events = len(scan.events)
        step_state = loop.step_executor.execute(scan, step, scan.step_states[step_id])
        return step_state, list(scan.artifacts.values()), scan.events[before_events:]

    def _ready_steps(self, scan) -> list[Any]:
        return [
            step
            for step in scan.plan.steps
            if scan.step_states[step.step_id].status == "pending"
            and all(self._dependency_satisfied(scan, step, item) for item in step.depends_on)
        ]

    def _dependency_satisfied(self, scan, step, dependency_step_id: str) -> bool:
        status = scan.step_states[dependency_step_id].status
        if status == "completed":
            return True
        return step.name == "poc_verify" and status in {"blocked", "failed"}

    def _step_index(self, scan, step_id: str) -> int:
        for index, step in enumerate(scan.plan.steps):
            if step.step_id == step_id:
                return index
        return len(scan.plan.steps)

    def _manual_confirmation_records(self, scan) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for step_id, step_state in scan.step_states.items():
            lead_lookup = {item.lead_id: item for item in step_state.leads}
            for record in step_state.verification_records:
                if str(record.method).strip().lower() != "manual_poc_case" or str(record.status).strip().lower() != "manual_required":
                    continue
                lead = lead_lookup.get(record.lead_id)
                approval = scan.manual_approvals.get(record.verification_id, {})
                records.append(
                    {
                        "verification_id": record.verification_id,
                        "lead_id": record.lead_id,
                        "step_id": step_id,
                        "step_name": step_state.step_id,
                        "status": str(approval.get("status", "pending")).strip() or "pending",
                        "summary": record.summary,
                        "proof": record.proof,
                        "created_at": record.created_at,
                        "location": "" if lead is None else lead.location,
                        "title": "" if lead is None else lead.title,
                        "severity": "" if lead is None else lead.severity,
                        "source_finding_id": str(record.metadata.get("source_finding_id", "")).strip(),
                        "verification_target": str(record.metadata.get("verification_target", "")).strip(),
                        "note": str(approval.get("note", "")).strip(),
                    }
                )
        return records

    def _manual_confirmation_by_id(self, scan, verification_id: str) -> dict[str, Any] | None:
        verification_id = str(verification_id or "").strip()
        if not verification_id:
            return None
        for item in self._manual_confirmation_records(scan):
            if item.get("verification_id") == verification_id:
                return item
        return None

    def _pending_confirmations(self, scan) -> list[dict[str, Any]]:
        return [item for item in self._manual_confirmation_records(scan) if str(item.get("status", "pending")).strip().lower() == "pending"]

    def _pause_for_pending_confirmations(self, scan, pending: list[dict[str, Any]], *, action: str):
        verification_ids = [str(item.get("verification_id", "")).strip() for item in pending if str(item.get("verification_id", "")).strip()]
        scan.updated_at = now_iso()
        scan.stage = "step_replan"
        scan.status = "manual_required"
        scan.summary = f"pending_manual_confirmations={len(verification_ids)}"
        self._append_unique_event(
            scan,
            AgentEvent(
                event_id=make_id("evt"),
                stage="step_replan",
                kind="human_gate_waiting",
                message=f"manual confirmation required before {action} can continue.",
                payload={"action": action, "verification_ids": verification_ids},
            ),
        )
        return scan

    def _append_unique_event(self, scan, event: AgentEvent) -> None:
        if scan.events:
            last = scan.events[-1]
            if last.kind == event.kind and last.stage == event.stage and dict(last.payload) == dict(event.payload):
                return
        scan.events.append(event)

    def generate_report(self, scan_id: str) -> dict[str, Any]:
        scan = self._load(scan_id)
        report_dir = self.run_dir / scan_id / "report"
        report_findings = self._select_report_findings(scan)
        report_findings = [item for item in report_findings if self._passes_report_gate(scan, item)]
        report_findings = self._collapse_supplemental_poc_findings(report_findings)
        report_findings = self._sort_and_deduplicate_findings(report_findings)
        verification_records = self._collect_report_verification_records(scan, report_findings)
        artifact_ids = {
            artifact_id
            for item in report_findings
            for artifact_id in item.artifact_ids
        }
        artifact_ids.update(
            artifact_id
            for record in verification_records
            for artifact_id in record.get("artifact_ids", [])
        )
        related_artifacts = self._sort_artifacts([item.to_dict() for item in scan.artifacts.values() if item.artifact_id in artifact_ids])
        unverified_leads = self._collect_unverified_leads(scan, verification_records, report_findings=report_findings)
        auxiliary_assessments = self._collect_auxiliary_assessments(scan, verification_records)
        severity_summary = self._build_severity_summary(report_findings)
        execution_summary = self._build_execution_summary(scan, report_findings, verification_records, unverified_leads)
        attack_paths = self._build_attack_paths(report_findings)
        coverage_metrics = self._build_coverage_metrics(scan)
        benchmark_summary = self._build_benchmark_summary(coverage_metrics)
        verified_findings_payload = [
            self._normalize_finding_for_report(item, verification_records=verification_records, artifacts=related_artifacts)
            for item in report_findings
        ]
        payload = {
            "report_version": "v2.1",
            "generated_at": scan.updated_at or scan.created_at,
            "scan_id": scan.scan_id,
            "target": scan.target,
            "summary": scan.summary,
            "scan_overview": {
                "scan_id": scan.scan_id,
                "target": scan.target,
                "profile_name": scan.plan.profile_name,
                "task_mode": scan.plan.task_mode,
                "task_mode_label": scan.plan.task_mode_label,
                "module_bundle": scan.plan.module_bundle,
                "status": scan.status,
                "stage": scan.stage,
            },
            "execution_summary": execution_summary,
            "coverage_metrics": coverage_metrics,
            "benchmark_summary": benchmark_summary,
            "severity_summary": severity_summary,
            "verified_findings": verified_findings_payload,
            "verification_records": verification_records,
            "artifacts": related_artifacts,
            "attack_paths": attack_paths,
            "appendix": {
                "unverified_leads": unverified_leads,
                "auxiliary_assessments": auxiliary_assessments,
            },
            "finding_count": len(report_findings),
        }
        manifest = ReportBuilder(report_dir, base_url=f"/runs/{scan.scan_id}/report").build(payload)
        scan.report_manifest = dict(manifest)
        self._save(scan)
        return manifest

    def _select_report_findings(self, scan) -> list[Any]:
        task_mode_findings = self._task_mode_findings(scan)
        if task_mode_findings is not None:
            return task_mode_findings
        bundle = str(scan.plan.module_bundle or "full").strip().lower()
        if bundle in {"sql", "sql_bypass"}:
            sql_scan_findings = [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "sql_injection"
                and str(item.metadata.get("verification_source", "")).strip() == "sql_scan"
            ]
            if sql_scan_findings:
                return sql_scan_findings
        if bundle == "xss":
            return [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "xss"
                and str(item.metadata.get("verification_source", "")).strip() == "xss_triage"
            ]
        if bundle == "ssrf":
            ssrf_findings = [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "ssrf"
                and str(item.metadata.get("verification_source", "")).strip() == "ssrf_triage"
            ]
            if ssrf_findings:
                return ssrf_findings
            return [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "ssrf"
            ]
        if bundle == "backup":
            return [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "backup_source_audit"
                and str(item.metadata.get("verification_source", "")).strip() == "backup_audit_extended"
            ]
        if bundle == "config":
            return [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "config_exposure"
                and str(item.metadata.get("verification_source", "")).strip() == "config_audit"
            ]
        if bundle == "cors":
            return [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "cors"
                and str(item.metadata.get("verification_source", "")).strip() == "cors_audit"
            ]
        if bundle == "jwt":
            return [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "jwt"
                and str(item.metadata.get("verification_source", "")).strip() == "jwt_audit"
            ]
        if bundle == "js":
            return [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "frontend_secret_exposure"
                and str(item.metadata.get("verification_source", "")).strip() == "js_audit"
            ]
        if bundle == "permission":
            return [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "authorization"
                and str(item.metadata.get("verification_source", "")).strip() == "permission_bypass"
            ]
        if bundle == "weak":
            return [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "weak_password"
                and str(item.metadata.get("verification_source", "")).strip() == "weak_password"
            ]
        return list(scan.verified_findings)

    def _task_mode_findings(self, scan) -> list[Any] | None:
        mode = str(getattr(scan.plan, "task_mode", "") or "").strip().lower()
        if not mode or mode == "blackbox_pentest":
            return None
        categories_by_mode = {
            "frontend_audit": {
                "frontend_secret_exposure",
                "js_derived_api",
                "xss",
                "xss_child_audit",
                "authorization",
                "authorization_child_audit",
            },
            "sql_focus": {"sql_injection"},
            "exposure_audit": {
                "backup_source_audit",
                "config_exposure",
                "frontend_secret_exposure",
                "js_derived_api",
            },
            "auth_audit": {
                "authorization",
                "authorization_child_audit",
                "weak_password",
                "jwt",
                "cors",
            },
        }
        sources_by_mode = {
            "frontend_audit": {"js_audit", "xss_triage", "permission_bypass", "docker_poc"},
            "sql_focus": {"sql_scan", "sql_bypass", "docker_poc"},
            "exposure_audit": {"backup_audit_extended", "config_audit", "js_audit", "docker_poc"},
            "auth_audit": {"permission_bypass", "weak_password", "jwt_audit", "cors_audit", "docker_poc"},
        }
        categories = categories_by_mode.get(mode)
        sources = sources_by_mode.get(mode)
        if not categories and not sources:
            return None
        filtered = [
            item
            for item in scan.verified_findings
            if str(item.category).strip() in categories
            or str(item.metadata.get("verification_source", "")).strip() in sources
        ]
        return filtered or list(scan.verified_findings)

    def _collapse_supplemental_poc_findings(self, findings) -> list[Any]:
        source_finding_ids = {
            str(item.finding_id).strip()
            for item in findings
            if str(item.finding_id).strip()
            and str(item.metadata.get("verification_source", "")).strip() != "docker_poc"
            and not bool(item.metadata.get("sandbox_verified", False))
        }
        collapsed = []
        for item in findings:
            source = str(item.metadata.get("verification_source", "")).strip()
            source_finding_id = str(item.metadata.get("source_finding_id", "")).strip()
            if (source == "docker_poc" or bool(item.metadata.get("sandbox_verified", False))) and source_finding_id in source_finding_ids:
                continue
            collapsed.append(item)
        return collapsed

    def _passes_report_gate(self, scan, finding) -> bool:
        if not finding.verification_id or not finding.evidence or not finding.reproduction_steps:
            return False
        records = []
        for step_state in scan.step_states.values():
            records.extend(step_state.verification_records)
        for subagent in scan.subagents.values():
            records.extend(subagent.verification_records)
        record = next((item for item in records if item.verification_id == finding.verification_id), None)
        if record is None or record.status != "verified" or not str(record.proof or record.summary).strip():
            return False
        category = str(finding.category).lower()
        method = str(record.method).lower()
        proof = str(record.proof or record.summary or "")
        evidence = str(finding.evidence or "")
        combined = f"{proof}\n{evidence}".lower()
        textual_weak_markers = (
            "assessment only",
            "not a standalone confirmed vulnerability",
            "unconfirmed",
        )
        if any(marker in combined for marker in textual_weak_markers):
            return False
        proof_lower = proof.lower()
        if "docker" not in method and ('"verified": false' in proof_lower or "'verified': false" in proof_lower):
            return False
        if category == "xss" and "browser" not in method and "dom" not in method:
            return False
        if category == "authorization" and not any(marker in method for marker in ("differential", "idor", "object_access", "authenticated")):
            return False
        if category == "ssrf" and not any(marker in method for marker in ("callback", "oob", "internal", "reflection", "loopback")):
            return False
        if category == "weak_password" and not any(marker in method for marker in ("login", "credential", "password", "submission")):
            return False
        if category == "sql_injection":
            if "strategy" in method or "assessment" in method:
                return False
            if not any(marker in method for marker in ("boolean", "time", "docker", "differential", "sqlmap")):
                return False
        if category in {"backup_source_audit", "backup_exposure", "config_exposure"}:
            if self._is_weak_backup_proof(proof, evidence):
                return False
        return True

    def _is_weak_backup_proof(self, proof: str, evidence: str = "") -> bool:
        text = f"{proof}\n{evidence}".strip().lower()
        compact = text.replace(" ", "")
        if not text or "risky_keys=;patterns=" in compact:
            return True
        strong_markers = (
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "access_key",
            "private_key",
            "db_",
            "database",
            "debug=true",
            ".env",
            "db.sql",
            "[core]",
            "[remote",
            "repositoryformatversion",
            "git_repository_metadata",
            "git_index",
            "git_config",
            "ds_store",
            ".ds_store",
            "dockerfile",
            "deployment_metadata",
            "source_metadata",
            "editor_backup",
            ".bak",
        )
        return not any(marker in text for marker in strong_markers)

    def _collect_report_verification_records(self, scan, report_findings) -> list[dict[str, Any]]:
        verification_ids = {item.verification_id for item in report_findings if item.verification_id}
        source_finding_ids = {item.finding_id for item in report_findings if item.finding_id}
        artifact_lookup = {item.artifact_id: item.to_dict() for item in scan.artifacts.values()}
        records = []
        for step_id, step_state in scan.step_states.items():
            for record in step_state.verification_records:
                if not self._record_matches_report_finding(record, verification_ids, source_finding_ids):
                    continue
                records.append(
                    self._normalize_verification_record(
                        record.to_dict(),
                        artifact_lookup,
                        source={"kind": "step", "id": step_id, "name": step_state.step_id},
                    )
                )
        for subagent_id, subagent in scan.subagents.items():
            for record in subagent.verification_records:
                if not self._record_matches_report_finding(record, verification_ids, source_finding_ids):
                    continue
                records.append(
                    self._normalize_verification_record(
                        record.to_dict(),
                        artifact_lookup,
                        source={"kind": "subagent", "id": subagent_id, "name": subagent.task.name},
                    )
                )
        return self._sort_verification_records(records)

    def _record_matches_report_finding(self, record, verification_ids: set[str], source_finding_ids: set[str]) -> bool:
        if record.verification_id in verification_ids:
            return True
        source_finding_id = str(record.metadata.get("source_finding_id", "")).strip()
        return bool(source_finding_id and source_finding_id in source_finding_ids)

    def _normalize_verification_record(
        self,
        record: dict[str, Any],
        artifact_lookup: dict[str, dict[str, Any]],
        *,
        source: dict[str, Any],
    ) -> dict[str, Any]:
        artifact_ids = [str(item) for item in record.get("artifact_ids", [])]
        proof = str(record.get("proof", ""))
        proof_type = self._infer_proof_type(record, artifact_ids, artifact_lookup)
        evidence_bundle = {
            "proof": proof,
            "proof_excerpt": proof[:240],
            "proof_type": proof_type,
            "artifact_count": len(artifact_ids),
            "artifacts": [artifact_lookup[item] for item in artifact_ids if item in artifact_lookup],
            "completeness_score": self._evidence_completeness_score(record, proof_type, artifact_ids, artifact_lookup),
        }
        return {
            **record,
            "source": dict(source),
            "proof_type": proof_type,
            "evidence_bundle": evidence_bundle,
            "completeness_score": evidence_bundle["completeness_score"],
        }

    def _normalize_finding_for_report(
        self,
        finding,
        *,
        verification_records: list[dict[str, Any]],
        artifacts: list[dict[str, Any]],
    ) -> dict[str, Any]:
        payload = finding.to_dict()
        verification = next((item for item in verification_records if item.get("verification_id") == finding.verification_id), {})
        supplemental = [
            item
            for item in verification_records
            if str(item.get("metadata", {}).get("source_finding_id", "")).strip() == str(finding.finding_id).strip()
            and item.get("verification_id") != finding.verification_id
        ]
        artifact_map = {item["artifact_id"]: item for item in artifacts if item.get("artifact_id")}
        severity = str(payload.get("severity", "")).strip().lower()
        payload["evidence_bundle"] = {
            "verification": verification,
            "supplemental_verifications": supplemental,
            "artifacts": [artifact_map[item] for item in finding.artifact_ids if item in artifact_map],
            "artifact_count": len(finding.artifact_ids),
            "completeness_score": self._finding_completeness_score(payload, verification, finding.artifact_ids),
        }
        payload["severity_rank"] = self._severity_rank(severity)
        payload["verification_status"] = str(verification.get("status", "verified"))
        payload["reportable"] = True
        payload["source"] = dict(verification.get("source", {})) if isinstance(verification.get("source", {}), dict) else {}
        payload["proof_type"] = str(verification.get("proof_type", "structured_proof"))
        payload["completeness_score"] = payload["evidence_bundle"]["completeness_score"]
        payload["promotion_reason"] = self._promotion_reason(payload, verification)
        payload["sql_context"] = self._sql_context_for_finding(payload)
        payload["xss_context"] = self._xss_context_for_finding(payload)
        payload["ssrf_context"] = self._ssrf_context_for_finding(payload)
        payload["backup_context"] = self._backup_context_for_finding(payload)
        payload["js_context"] = self._js_context_for_finding(payload)
        payload["permission_context"] = self._permission_context_for_finding(payload)
        payload["jwt_context"] = self._jwt_context_for_finding(payload)
        payload["supplemental_verifications"] = supplemental
        return payload

    def _sql_context_for_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        metadata = finding.get("metadata", {}) if isinstance(finding.get("metadata", {}), dict) else {}
        candidate = metadata.get("sql_candidate", {}) if isinstance(metadata.get("sql_candidate", {}), dict) else {}
        if not candidate:
            return {}
        strategies = candidate.get("confirmed_strategies", [])
        return {
            "page": str(candidate.get("page_url", "")).strip(),
            "method": str(candidate.get("method", "")).strip(),
            "parameter": str(candidate.get("parameter", "")).strip(),
            "baseline_url": str(candidate.get("baseline_url", "")).strip(),
            "confirmed_strategies": [str(item).strip() for item in strategies if str(item).strip()] if isinstance(strategies, list) else [],
            "basis": str(candidate.get("basis", "")).strip(),
        }

    def _xss_context_for_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        metadata = finding.get("metadata", {}) if isinstance(finding.get("metadata", {}), dict) else {}
        candidate = metadata.get("xss_candidate", {}) if isinstance(metadata.get("xss_candidate", {}), dict) else {}
        if not candidate:
            return {}
        strategies = candidate.get("confirmed_strategies", [])
        return {
            "page": str(candidate.get("page_url", "")).strip(),
            "method": str(candidate.get("method", "")).strip(),
            "parameter": str(candidate.get("parameter", "")).strip(),
            "context": str(candidate.get("context", "")).strip(),
            "request_url": str(candidate.get("request_url", "")).strip(),
            "confirmed_strategies": [str(item).strip() for item in strategies if str(item).strip()] if isinstance(strategies, list) else [],
            "basis": str(candidate.get("basis", "")).strip(),
        }

    def _ssrf_context_for_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        metadata = finding.get("metadata", {}) if isinstance(finding.get("metadata", {}), dict) else {}
        context = metadata.get("ssrf_context", {}) if isinstance(metadata.get("ssrf_context", {}), dict) else {}
        if not context:
            return {}
        markers = context.get("matched_markers", [])
        return {
            "page": str(context.get("page_url", "")).strip(),
            "request_url": str(context.get("request_url", "")).strip(),
            "method": str(context.get("method", "")).strip(),
            "parameter": str(context.get("parameter", "")).strip(),
            "source": str(context.get("source", "")).strip(),
            "reason": str(context.get("reason", "")).strip(),
            "probe_type": str(context.get("probe_type", "")).strip(),
            "probe_value": str(context.get("probe_value", "")).strip(),
            "probe_url": str(context.get("probe_url", "")).strip(),
            "baseline_status": int(context.get("baseline_status", 0) or 0),
            "probe_status": int(context.get("probe_status", 0) or 0),
            "matched_markers": [str(item).strip() for item in markers if str(item).strip()] if isinstance(markers, list) else [],
        }

    def _backup_context_for_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        metadata = finding.get("metadata", {}) if isinstance(finding.get("metadata", {}), dict) else {}
        context = metadata.get("backup_context", {}) if isinstance(metadata.get("backup_context", {}), dict) else {}
        if not context:
            return {}
        members = context.get("members", [])
        return {
            "path": str(context.get("path", "")).strip(),
            "status_code": int(context.get("status_code", 0) or 0),
            "artifact_type": str(context.get("artifact_type", "")).strip(),
            "evidence_kind": str(context.get("evidence_kind", "")).strip(),
            "group_key": str(context.get("group_key", "")).strip(),
            "members": [str(item).strip() for item in members if str(item).strip()] if isinstance(members, list) else [],
        }

    def _js_context_for_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        metadata = finding.get("metadata", {}) if isinstance(finding.get("metadata", {}), dict) else {}
        context = metadata.get("js_context", {}) if isinstance(metadata.get("js_context", {}), dict) else {}
        if not context:
            return {}
        return {
            "script": str(context.get("script", "")).strip(),
            "origin": str(context.get("origin", "")).strip(),
            "content_type": str(context.get("content_type", "")).strip(),
            "category": str(context.get("category", "")).strip(),
            "line": int(context.get("line", 0) or 0),
            "source": str(context.get("source", "")).strip(),
            "sink": str(context.get("sink", "")).strip(),
            "api_path": str(context.get("api_path", "")).strip(),
            "masked_sample": str(context.get("masked_sample", "")).strip(),
            "rule_id": str(context.get("rule_id", "")).strip(),
        }

    def _permission_context_for_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        metadata = finding.get("metadata", {}) if isinstance(finding.get("metadata", {}), dict) else {}
        context = metadata.get("permission_context", {}) if isinstance(metadata.get("permission_context", {}), dict) else {}
        if not context:
            return {}
        normalized: dict[str, Any] = {
            "url": str(context.get("url", "")).strip(),
            "method": str(context.get("method", "")).strip(),
            "type": str(context.get("type", "")).strip(),
            "parameter": str(context.get("parameter", "")).strip(),
            "baseline_value": str(context.get("baseline_value", "")).strip(),
            "mutated_value": str(context.get("mutated_value", "")).strip(),
            "source": str(context.get("source", "")).strip(),
        }
        for key in ("anonymous", "high", "low", "baseline", "mutated"):
            value = context.get(key, {})
            if isinstance(value, dict):
                normalized[key] = {
                    "url": str(value.get("url", "")).strip(),
                    "status_code": int(value.get("status_code", 0) or 0),
                    "length": int(value.get("length", 0) or 0),
                    "sensitive_markers": [str(item).strip() for item in value.get("sensitive_markers", []) if str(item).strip()]
                    if isinstance(value.get("sensitive_markers", []), list)
                    else [],
                }
        if context.get("mutated_url"):
            normalized["mutated_url"] = str(context.get("mutated_url", "")).strip()
        return normalized

    def _jwt_context_for_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        metadata = finding.get("metadata", {}) if isinstance(finding.get("metadata", {}), dict) else {}
        context = metadata.get("jwt_context", {}) if isinstance(metadata.get("jwt_context", {}), dict) else {}
        if not context:
            return {}
        payload_keys = context.get("payload_keys", [])
        return {
            "url": str(context.get("url", "")).strip(),
            "issue": str(context.get("issue", "")).strip(),
            "alg": str(context.get("alg", "")).strip(),
            "typ": str(context.get("typ", "")).strip(),
            "signature_present": bool(context.get("signature_present", False)),
            "payload_keys": [str(item).strip() for item in payload_keys if str(item).strip()] if isinstance(payload_keys, list) else [],
        }

    def _evidence_completeness_score(
        self,
        record: dict[str, Any],
        proof_type: str,
        artifact_ids: list[str],
        artifact_lookup: dict[str, dict[str, Any]],
    ) -> float:
        score = 0.0
        if str(record.get("proof", "")).strip():
            score += 0.3
        if artifact_ids:
            score += 0.2
        if str(record.get("method", "")).strip():
            score += 0.15
        if proof_type in {"docker_poc", "browser_capture", "oob_callback", "response_diff"}:
            score += 0.2
        kinds = {str(artifact_lookup[item].get("kind", "")).strip().lower() for item in artifact_ids if item in artifact_lookup}
        if {"screenshot", "http_body", "subagent_seed"} & kinds:
            score += 0.15
        return round(min(score, 1.0), 2)

    def _finding_completeness_score(self, finding: dict[str, Any], verification: dict[str, Any], artifact_ids: list[str]) -> float:
        score = 0.0
        if finding.get("evidence"):
            score += 0.2
        if finding.get("reproduction_steps"):
            score += 0.2
        if finding.get("verification_id"):
            score += 0.2
        if artifact_ids:
            score += 0.15
        if verification.get("proof_type"):
            score += 0.15
        if verification.get("source"):
            score += 0.1
        return round(min(score, 1.0), 2)

    def _promotion_reason(self, finding: dict[str, Any], verification: dict[str, Any]) -> str:
        proof_type = str(verification.get("proof_type", "structured_proof"))
        method = str(verification.get("method", "verification"))
        source = verification.get("source", {}) if isinstance(verification.get("source", {}), dict) else {}
        source_label = f"{source.get('kind', 'unknown')}:{source.get('name') or source.get('id', '')}".strip(":")
        return f"promoted because method={method}, proof_type={proof_type}, source={source_label}"

    def _collect_unverified_leads(self, scan, verification_records: list[dict[str, Any]], *, report_findings=None) -> list[dict[str, Any]]:
        verified_lead_ids = {str(item.get("lead_id", "")) for item in verification_records if item.get("lead_id")}
        report_finding_locations: dict[str, list[str]] = {}
        for item in report_findings or []:
            category = str(item.category).strip()
            location = str(item.location).strip()
            if category and location:
                report_finding_locations.setdefault(category, []).append(location)
        auxiliary_lead_ids = {
            record.lead_id
            for step_state in scan.step_states.values()
            for record in step_state.verification_records
            if str(record.method).strip().lower() in {"strategy_assessment"}
        }
        appendix = []
        for step_id, step_state in scan.step_states.items():
            for lead in step_state.leads:
                if lead.lead_id in verified_lead_ids or lead.lead_id in auxiliary_lead_ids:
                    continue
                if self._lead_location_is_covered_by_report_finding(lead, report_finding_locations):
                    continue
                if (
                    str(lead.metadata.get("verification_case_status", "")).strip() == "manual_only"
                    and str(lead.metadata.get("source_finding_id", "")).strip()
                ):
                    continue
                appendix.append(
                    {
                        **lead.to_dict(),
                        "source": {"kind": "step", "id": step_id},
                    }
                )
        for subagent_id, subagent in scan.subagents.items():
            for lead in subagent.leads:
                if lead.lead_id in verified_lead_ids:
                    continue
                if self._lead_location_is_covered_by_report_finding(lead, report_finding_locations):
                    continue
                appendix.append(
                    {
                        **lead.to_dict(),
                        "source": {"kind": "subagent", "id": subagent_id},
                    }
                )
        appendix.sort(key=lambda item: (self._severity_rank(str(item.get("severity", "")).lower()), str(item.get("category", "")), str(item.get("location", ""))))
        return appendix

    def _lead_location_is_covered_by_report_finding(self, lead, report_finding_locations: dict[str, list[str]]) -> bool:
        category = str(lead.category).strip()
        location = str(lead.location).strip()
        if not category or not location:
            return False
        normalized_location = location.rstrip("/")
        for finding_location in report_finding_locations.get(category, []):
            normalized_finding = str(finding_location).strip().rstrip("/")
            if not normalized_finding:
                continue
            if normalized_location == normalized_finding:
                return True
            if normalized_location.startswith(normalized_finding + "/"):
                return True
            if normalized_finding.startswith(normalized_location + "/"):
                return True
        return False

    def _collect_auxiliary_assessments(self, scan, verification_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        included_ids = {str(item.get("verification_id", "")) for item in verification_records if item.get("verification_id")}
        artifact_lookup = {item.artifact_id: item.to_dict() for item in scan.artifacts.values()}
        assessments: list[dict[str, Any]] = []
        for step_id, step_state in scan.step_states.items():
            for record in step_state.verification_records:
                method = str(record.method).strip().lower()
                if method not in {"strategy_assessment", "manual_poc_case"}:
                    continue
                if method == "manual_poc_case":
                    source_finding_id = str(record.metadata.get("source_finding_id", "")).strip()
                    if source_finding_id and any(item.finding_id == source_finding_id for item in scan.verified_findings):
                        continue
                    if source_finding_id and any(item.get("finding_id") == source_finding_id for item in assessments):
                        continue
                    if source_finding_id:
                        continue
                if record.verification_id in included_ids:
                    continue
                assessments.append(
                    self._normalize_verification_record(
                        record.to_dict(),
                        artifact_lookup,
                        source={"kind": "step", "id": step_id, "name": step_state.step_id},
                    )
                )
        return self._sort_verification_records(assessments)

    def _build_severity_summary(self, report_findings) -> dict[str, int]:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for item in report_findings:
            severity = str(item.severity).strip().lower()
            if severity not in summary:
                severity = "info"
            summary[severity] += 1
        return summary

    def _build_execution_summary(self, scan, report_findings, verification_records: list[dict[str, Any]], unverified_leads: list[dict[str, Any]]) -> dict[str, Any]:
        completed_steps = sum(1 for item in scan.step_states.values() if item.status == "completed")
        completed_subagents = sum(1 for item in scan.subagents.values() if item.status == "completed")
        step_decisions = sum(len(item.decision_records) for item in scan.step_states.values())
        subagent_decisions = sum(len(item.decision_records) for item in scan.subagents.values())
        step_fallbacks = sum(int(item.llm_fallback_count) for item in scan.step_states.values())
        subagent_fallbacks = sum(int(item.llm_fallback_count) for item in scan.subagents.values())
        return {
            "completed_steps": completed_steps,
            "total_steps": len(scan.step_states),
            "completed_subagents": completed_subagents,
            "total_subagents": len(scan.subagents),
            "step_decision_count": step_decisions,
            "subagent_decision_count": subagent_decisions,
            "step_llm_fallback_count": step_fallbacks,
            "subagent_llm_fallback_count": subagent_fallbacks,
            "verified_finding_count": len(report_findings),
            "verification_record_count": len(verification_records),
            "verification_methods": sorted({str(item.get("method", "")).strip() for item in verification_records if str(item.get("method", "")).strip()}),
            "verification_sources": sorted({str(item.get("proof_type", "")).strip() for item in verification_records if str(item.get("proof_type", "")).strip()}),
            "unverified_lead_count": len(unverified_leads),
            "artifact_count": len(scan.artifacts),
        }

    def _build_attack_paths(self, report_findings) -> list[dict[str, Any]]:
        categories = {str(item.category).strip() for item in report_findings}
        paths: list[dict[str, Any]] = []
        if "backup_source_audit" in categories and "authorization_child_audit" in categories:
            paths.append(
                {
                    "name": "备份线索到权限边界扩展",
                    "categories": ["backup_source_audit", "authorization_child_audit"],
                    "summary": "备份/配置线索可为权限边界验证提供高价值上下文。",
                }
            )
        if "js_derived_api" in categories and "xss_child_audit" in categories:
            paths.append(
                {
                    "name": "前端派生入口到 XSS 复测",
                    "categories": ["js_derived_api", "xss_child_audit"],
                    "summary": "前端资源派生出的入口可继续扩展为前端执行面复测。",
                }
            )
        if "sql_injection" in categories:
            paths.append(
                {
                    "name": "注入发现到沙箱验证",
                    "categories": ["sql_injection"],
                    "summary": "SQL 注入线索已进入正式验证路径，可用于形成稳定 POC 记录。",
                }
            )
        return paths

    def _severity_rank(self, severity: str) -> int:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return order.get(str(severity).strip().lower(), 5)

    def _sort_and_deduplicate_findings(self, findings) -> list[Any]:
        deduped: dict[str, Any] = {}
        for item in findings:
            key = item.finding_id or f"{item.category}:{item.location}:{item.verification_id}"
            deduped[key] = item
        return sorted(
            deduped.values(),
            key=lambda item: (
                self._severity_rank(str(item.severity).strip().lower()),
                str(item.category),
                str(item.location),
                str(item.finding_id),
            ),
        )

    def _sort_verification_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped: dict[str, dict[str, Any]] = {}
        for item in records:
            verification_id = str(item.get("verification_id", "")).strip()
            if not verification_id:
                continue
            deduped[verification_id] = item
        return sorted(
            deduped.values(),
            key=lambda item: (
                self._severity_rank(str(item.get("metadata", {}).get("severity", "")).strip().lower()),
                str(item.get("method", "")),
                str(item.get("verification_id", "")),
            ),
        )

    def _sort_artifacts(self, artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped: dict[str, dict[str, Any]] = {}
        for item in artifacts:
            artifact_id = str(item.get("artifact_id", "")).strip()
            if not artifact_id:
                continue
            deduped[artifact_id] = item
        return sorted(deduped.values(), key=lambda item: (str(item.get("kind", "")), str(item.get("name", "")), str(item.get("artifact_id", ""))))

    def _infer_proof_type(self, record: dict[str, Any], artifact_ids: list[str], artifact_lookup: dict[str, dict[str, Any]]) -> str:
        method = str(record.get("method", "")).strip().lower()
        if "docker" in method:
            return "docker_poc"
        if "browser" in method:
            return "browser_capture"
        if "callback" in method:
            return "oob_callback"
        if any(marker in method for marker in ("internal", "reflection", "loopback")):
            return "internal_content_reflection"
        if method == "manual_poc_case":
            return "manual_supplemental"
        if method == "static_js_secret_exposure":
            return "static_secret_exposure"
        if "differential" in method:
            return "response_diff"
        kinds = {str(artifact_lookup[item].get("kind", "")).strip().lower() for item in artifact_ids if item in artifact_lookup}
        if "screenshot" in kinds:
            return "browser_capture"
        if {"http_body", "subagent_seed"} & kinds:
            return "artifact_capture"
        return "structured_proof"

    def _path_for(self, scan_id: str) -> Path:
        return self.run_dir / scan_id / "scan_state.json"

    def _normalize_module_bundle(self, module_bundle: str) -> str:
        return normalize_module_bundle(module_bundle)

    def _profile_for_skill_names(self, profile, skill_names: tuple[str, ...] | None, *, max_parallel_steps: int | None = 1):
        if skill_names is None:
            return profile if max_parallel_steps is None else replace(profile, max_parallel_steps=max_parallel_steps)
        return replace(
            profile,
            skill_names=list(skill_names),
            max_parallel_steps=max(1, int(max_parallel_steps or 1)),
        )

    def _profile_for_bundle(self, profile, module_bundle: str):
        return self._profile_for_skill_names(profile, module_bundle_skills(module_bundle), max_parallel_steps=None if module_bundle == "full" else 1)

    def _apply_llm_overrides(self, profile, *, provider_name: str = "", model_id: str = "", base_url: str = ""):
        resolved_provider = str(provider_name or "").strip().lower()
        resolved_model = str(model_id or "").strip()
        resolved_base = str(base_url or "").strip()
        if not resolved_provider and not resolved_model and not resolved_base:
            return profile
        api_key_env = str(getattr(profile, "api_key_env", "")).strip()
        if resolved_provider:
            spec = get_provider_spec(resolved_provider)
            api_key_env = str(spec.api_key_env).strip()
            if not resolved_model:
                resolved_model = str(spec.default_model).strip()
            if not resolved_base:
                resolved_base = str(spec.base_url).strip()
        return replace(
            profile,
            provider_name=resolved_provider or str(getattr(profile, "provider_name", "")).strip(),
            model_id=resolved_model or str(getattr(profile, "model_id", "")).strip(),
            base_url=resolved_base or str(getattr(profile, "base_url", "")).strip(),
            api_key_env=api_key_env,
        )

    def _save(self, scan) -> None:
        path = self._path_for(scan.scan_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(scan.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

    def _scan_from_payload(self, payload: dict[str, Any]):
        return self._load_payload(payload)

    def _load(self, scan_id: str):
        payload = json.loads(self._path_for(scan_id).read_text(encoding="utf-8"))
        return self._load_payload(payload)

    def _load_payload(self, payload: dict[str, Any]):
        from .models import (
            AgentEvent,
            AgentProfile,
            Artifact,
            DecisionRecord,
            Lead,
            Observation,
            ScanPlan,
            ScanState,
            StepBudget,
            StepSpec,
            StepState,
            SubAgentState,
            SubAgentTask,
            VerificationRecord,
            VerifiedFinding,
        )

        profile = AgentProfile(**payload["profile"])
        steps = [
            StepSpec(
                step_id=item["step_id"],
                name=item["name"],
                goal=item["goal"],
                skill_names=list(item["skill_names"]),
                allowed_tools=list(item["allowed_tools"]),
                depends_on=list(item.get("depends_on", [])),
                verification_policy=item.get("verification_policy", "bounded"),
                budget=StepBudget(**item.get("budget", {})),
                category=item.get("category", "generic"),
            )
            for item in payload["plan"]["steps"]
        ]
        plan = ScanPlan(
            target=payload["plan"]["target"],
            steps=steps,
            profile_name=payload["plan"]["profile_name"],
            module_bundle=str(payload["plan"].get("module_bundle", "full") or "full"),
            task_mode=str(payload["plan"].get("task_mode", "") or ""),
            task_mode_label=str(payload["plan"].get("task_mode_label", "") or ""),
        )
        step_states = {}
        for step_id, item in payload["step_states"].items():
            step_states[step_id] = StepState(
                step_id=step_id,
                status=item["status"],
                iterations=item["iterations"],
                tool_calls=item["tool_calls"],
                hypothesis=item.get("hypothesis", ""),
                decision_records=[DecisionRecord(**record) for record in item.get("decision_records", [])],
                llm_fallback_count=int(item.get("llm_fallback_count", 0)),
                verification_gap=item.get("verification_gap", ""),
                observations=[Observation(**obs) for obs in item.get("observations", [])],
                leads=[Lead(**lead) for lead in item.get("leads", [])],
                verification_records=[VerificationRecord(**record) for record in item.get("verification_records", [])],
                verified_findings=[VerifiedFinding(**finding) for finding in item.get("verified_findings", [])],
                output_context=dict(item.get("output_context", {})),
                artifact_ids=list(item.get("artifact_ids", [])),
                spawned_subagents=list(item.get("spawned_subagents", [])),
                error=item.get("error", ""),
                started_at=item.get("started_at", ""),
                finished_at=item.get("finished_at", ""),
            )
        scan = ScanState(
            scan_id=payload["scan_id"],
            target=payload["target"],
            profile=profile,
            stage=payload["stage"],
            plan=plan,
            status=payload.get("status", "ready"),
            provider_status=dict(payload.get("provider_status", {})),
            fallback_metrics=dict(payload.get("fallback_metrics", {})),
            manual_approvals={
                str(key): dict(value)
                for key, value in payload.get("manual_approvals", {}).items()
                if isinstance(value, dict)
            },
            report_manifest=dict(payload.get("report_manifest", {})),
            step_states=step_states,
            subagents={
                key: SubAgentState(
                    subagent_id=value["subagent_id"],
                    task=SubAgentTask(**value["task"]),
                    status=value.get("status", "queued"),
                    iterations=int(value.get("iterations", 0)),
                    tool_calls=int(value.get("tool_calls", 0)),
                    decision_records=[DecisionRecord(**record) for record in value.get("decision_records", [])],
                    llm_fallback_count=int(value.get("llm_fallback_count", 0)),
                    done_reason=value.get("done_reason", ""),
                    observations=[Observation(**obs) for obs in value.get("observations", [])],
                    leads=[Lead(**lead) for lead in value.get("leads", [])],
                    verification_records=[VerificationRecord(**record) for record in value.get("verification_records", [])],
                    verified_findings=[VerifiedFinding(**finding) for finding in value.get("verified_findings", [])],
                    output_context=dict(value.get("output_context", {})),
                    artifacts=[Artifact(**artifact) for artifact in value.get("artifacts", [])],
                    artifact_ids=list(value.get("artifact_ids", [])),
                    error=value.get("error", ""),
                    started_at=value.get("started_at", ""),
                    finished_at=value.get("finished_at", ""),
                )
                for key, value in payload.get("subagents", {}).items()
            },
            artifacts={item["artifact_id"]: Artifact(**item) for item in payload.get("artifacts", {}).values()},
            verified_findings=[VerifiedFinding(**item) for item in payload.get("verified_findings", [])],
            events=[AgentEvent(**item) for item in payload.get("events", [])],
            created_at=payload.get("created_at", ""),
            updated_at=payload.get("updated_at", ""),
            summary=payload.get("summary", ""),
        )
        return scan

    def _snapshot(self, scan) -> dict[str, Any]:
        if not scan.provider_status:
            scan.provider_status = self._provider_status(scan.profile)
        scan.fallback_metrics = {
            "step_llm_fallback_count": sum(int(item.llm_fallback_count) for item in scan.step_states.values()),
            "subagent_llm_fallback_count": sum(int(item.llm_fallback_count) for item in scan.subagents.values()),
        }
        coverage_metrics = self._build_coverage_metrics(scan)
        visible_findings = self._visible_snapshot_findings(scan)
        pending_confirmations = self._pending_confirmations(scan)
        return {
            "scan_id": scan.scan_id,
            "target": scan.target,
            "stage": scan.stage,
            "status": scan.status,
            "profile": scan.profile.to_dict(),
            "provider_status": dict(scan.provider_status),
            "fallback_metrics": dict(scan.fallback_metrics),
            "manual_approvals": {key: dict(value) for key, value in scan.manual_approvals.items()},
            "pending_confirmations": pending_confirmations,
            "coverage_metrics": coverage_metrics,
            "report_manifest": dict(scan.report_manifest),
            "plan": scan.plan.to_dict(),
            "step_states": {key: value.to_dict() for key, value in scan.step_states.items()},
            "verified_findings": [item.to_dict() for item in visible_findings],
            "artifacts": [item.to_dict() for item in scan.artifacts.values()],
            "events": [item.to_dict() for item in scan.events],
            "subagents": {key: value.to_dict() for key, value in scan.subagents.items()},
            "summary": scan.summary,
        }

    def _provider_status(self, profile) -> dict[str, Any]:
        import os

        enabled = bool(getattr(profile, "llm_enabled", False))
        provider_name = str(getattr(profile, "provider_name", "")).strip()
        model_id = str(getattr(profile, "model_id", "")).strip()
        base_url = str(getattr(profile, "base_url", "")).strip()
        api_key_env = str(getattr(profile, "api_key_env", "")).strip()
        if not enabled:
            return {
                "status": "disabled",
                "provider": provider_name or "-",
                "model": model_id or "-",
                "base_url": base_url or "-",
                "api_key_env": api_key_env or "",
                "message": "llm disabled",
            }
        try:
            spec = get_provider_spec(provider_name)
        except Exception:
            spec = None
        effective_api_key_env = api_key_env or ("" if spec is None else str(spec.api_key_env).strip())
        resolved_provider = provider_name or ("" if spec is None else spec.name)
        resolved_model = model_id or ("" if spec is None else spec.default_model)
        resolved_base_url = base_url or ("" if spec is None else spec.base_url)
        if str(resolved_provider).strip().lower() == "ollama":
            readiness = _ollama_readiness(resolved_base_url or "http://127.0.0.1:11434")
            return {
                "status": "ready" if readiness.ok else "offline",
                "provider": resolved_provider or "ollama",
                "model": resolved_model or "-",
                "base_url": resolved_base_url or "http://127.0.0.1:11434",
                "api_key_env": effective_api_key_env,
                "message": readiness.message,
            }
        env_candidates = [] if spec is None else provider_api_key_envs(spec, effective_api_key_env)
        matched_env = next((name for name in env_candidates if os.environ.get(name, "").strip()), "")
        display_env = matched_env or (env_candidates[0] if env_candidates else effective_api_key_env)
        has_api_key = True if not env_candidates else bool(matched_env)
        return {
            "status": "ready" if has_api_key else "missing_env",
            "provider": resolved_provider,
            "model": resolved_model,
            "base_url": resolved_base_url,
            "api_key_env": display_env,
            "message": "provider credentials available" if has_api_key else f"missing api key env: {display_env}",
        }

    def _visible_snapshot_findings(self, scan) -> list[Any]:
        task_mode_findings = self._task_mode_findings(scan)
        if task_mode_findings is not None:
            return task_mode_findings
        bundle = str(scan.plan.module_bundle or "full").strip().lower()
        if bundle in {"sql", "sql_bypass"}:
            filtered = [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "sql_injection"
                and str(item.metadata.get("verification_source", "")).strip() == "sql_scan"
            ]
            return filtered or list(scan.verified_findings)
        if bundle == "ssrf":
            filtered = [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "ssrf"
                and str(item.metadata.get("verification_source", "")).strip() == "ssrf_triage"
            ]
            return filtered or list(scan.verified_findings)
        if bundle == "permission":
            filtered = [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "authorization"
                and str(item.metadata.get("verification_source", "")).strip() == "permission_bypass"
            ]
            return filtered or list(scan.verified_findings)
        if bundle == "weak":
            filtered = [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "weak_password"
                and str(item.metadata.get("verification_source", "")).strip() == "weak_password"
            ]
            return filtered or list(scan.verified_findings)
        if bundle == "config":
            filtered = [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "config_exposure"
                and str(item.metadata.get("verification_source", "")).strip() == "config_audit"
            ]
            return filtered or list(scan.verified_findings)
        if bundle == "cors":
            filtered = [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "cors"
                and str(item.metadata.get("verification_source", "")).strip() == "cors_audit"
            ]
            return filtered or list(scan.verified_findings)
        if bundle == "jwt":
            filtered = [
                item
                for item in scan.verified_findings
                if str(item.category).strip() == "jwt"
                and str(item.metadata.get("verification_source", "")).strip() == "jwt_audit"
            ]
            return filtered or list(scan.verified_findings)
        return list(scan.verified_findings)

    def _build_coverage_metrics(self, scan) -> dict[str, Any]:
        step_by_name = {
            step.name: scan.step_states.get(step.step_id)
            for step in scan.plan.steps
            if scan.step_states.get(step.step_id) is not None
        }
        subagents = list(scan.subagents.values())
        step_observation_tools = [
            observation.tool_name
            for state in scan.step_states.values()
            for observation in state.observations
        ]
        subagent_observation_tools = [
            observation.tool_name
            for state in subagents
            for observation in state.observations
        ]
        step_decision_tools = [
            decision.tool_name
            for state in scan.step_states.values()
            for decision in state.decision_records
        ]
        subagent_decision_tools = [
            decision.tool_name
            for state in subagents
            for decision in state.decision_records
        ]
        tool_names = sorted(set(step_observation_tools + subagent_observation_tools + step_decision_tools + subagent_decision_tools))
        finding_categories = sorted({str(item.category) for item in scan.verified_findings})
        finding_category_by_id = {
            str(item.finding_id).strip(): str(item.category).strip()
            for item in scan.verified_findings
            if str(item.finding_id).strip()
        }
        verification_methods = sorted(
            {
                str(record.method)
                for state in list(scan.step_states.values()) + subagents
                for record in state.verification_records
                if str(record.method).strip()
            }
        )
        benchmark_manifest = self._load_benchmark_manifest()
        benchmark_categories = []
        for category in benchmark_manifest.get("categories", []):
            expected_steps = [str(item) for item in category.get("expected_steps", [])]
            expected_children = [str(item) for item in category.get("expected_children", [])]
            expected_tools = [str(item) for item in category.get("expected_tools", [])]
            expected_findings = [str(item) for item in category.get("expected_verified_categories", [])]
            related_steps = [step_by_name.get(name) for name in expected_steps if step_by_name.get(name) is not None]
            related_children = [state for state in subagents if state.task.name in expected_children]
            fallback_count = sum(int(state.llm_fallback_count) for state in related_steps) + sum(int(state.llm_fallback_count) for state in related_children)
            round_count = (
                sum(
                    self._benchmark_round_count_for_step(name, state, expected_findings, finding_category_by_id)
                    for name, state in ((name, step_by_name.get(name)) for name in expected_steps)
                    if state is not None
                )
                + sum(int(state.iterations) for state in related_children)
            )
            step_status = {name: (step_by_name[name].status if name in step_by_name else "missing") for name in expected_steps}
            child_status = {
                name: next((state.status for state in related_children if state.task.name == name), "missing")
                for name in expected_children
            }
            tool_seen = {name: name in tool_names for name in expected_tools}
            finding_seen = {name: name in finding_categories for name in expected_findings}
            checks = [
                all(status == "completed" for status in step_status.values()) if step_status else True,
                all(status == "completed" for status in child_status.values()) if child_status else True,
                all(tool_seen.values()) if tool_seen else True,
                any(finding_seen.values()) if finding_seen else True,
                fallback_count <= int(category.get("max_fallbacks", 10) or 10),
                round_count <= int(category.get("max_rounds", 99) or 99),
            ]
            passed = sum(1 for item in checks if item)
            benchmark_categories.append(
                {
                    "name": str(category.get("name", "")),
                    "step_status": step_status,
                    "child_status": child_status,
                    "tool_seen": tool_seen,
                    "finding_seen": finding_seen,
                    "fallback_count": fallback_count,
                    "round_count": round_count,
                    "max_fallbacks": int(category.get("max_fallbacks", 10) or 10),
                    "max_rounds": int(category.get("max_rounds", 99) or 99),
                    "score": round(passed / max(len(checks), 1), 2),
                    "passed": passed == len(checks),
                }
            )
        return {
            "manifest_name": str(benchmark_manifest.get("name", "")),
            "manifest_version": str(benchmark_manifest.get("manifest_version", "")),
            "steps": {
                "total": len(scan.step_states),
                "completed": sum(1 for item in scan.step_states.values() if item.status == "completed"),
                "blocked": sum(1 for item in scan.step_states.values() if item.status == "blocked"),
                "failed": sum(1 for item in scan.step_states.values() if item.status == "failed"),
                "by_name": {name: state.status for name, state in step_by_name.items()},
            },
            "subagents": {
                "total": len(subagents),
                "completed": sum(1 for item in subagents if item.status == "completed"),
                "blocked": sum(1 for item in subagents if item.status == "blocked"),
                "failed": sum(1 for item in subagents if item.status == "failed"),
                "by_name": {state.task.name: state.status for state in subagents},
                "contributions": [
                    {
                        "subagent_id": state.subagent_id,
                        "task_name": state.task.name,
                        "status": state.status,
                        "done_reason": state.done_reason,
                        "seed_step_id": state.task.seed_step_id,
                        "verified_finding_ids": [item.finding_id for item in state.verified_findings],
                        "output_context": dict(state.output_context),
                    }
                    for state in subagents
                ],
            },
            "tools": {
                "seen": tool_names,
                "step_observation_count": len(step_observation_tools),
                "subagent_observation_count": len(subagent_observation_tools),
            },
            "findings": {
                "verified_count": len(scan.verified_findings),
                "categories": finding_categories,
            },
            "verification": {
                "methods": verification_methods,
                "gaps": sorted({state.verification_gap for state in scan.step_states.values() if state.verification_gap}),
            },
            "fallbacks": {
                **dict(scan.fallback_metrics),
                "total": int(scan.fallback_metrics.get("step_llm_fallback_count", 0)) + int(scan.fallback_metrics.get("subagent_llm_fallback_count", 0)),
            },
            "benchmarks": benchmark_categories,
        }

    def _benchmark_round_count_for_step(
        self,
        step_name: str,
        step_state,
        expected_findings: list[str],
        finding_category_by_id: dict[str, str],
    ) -> int:
        if step_state is None:
            return 0
        if step_name != "poc_verify" or not expected_findings:
            return int(step_state.iterations)
        expected = {str(item).strip() for item in expected_findings if str(item).strip()}
        matched = 0
        for observation in step_state.observations:
            payload = observation.payload if isinstance(observation.payload, dict) else {}
            source_finding_id = str(payload.get("source_finding_id", "")).strip()
            if not source_finding_id:
                continue
            if finding_category_by_id.get(source_finding_id, "") in expected:
                matched += 1
        return matched or int(step_state.iterations)

    def _build_benchmark_summary(self, coverage_metrics: dict[str, Any]) -> dict[str, Any]:
        benchmarks = coverage_metrics.get("benchmarks", []) if isinstance(coverage_metrics, dict) else []
        benchmarks = [dict(item) for item in benchmarks if isinstance(item, dict)] if isinstance(benchmarks, list) else []
        passed = [item for item in benchmarks if bool(item.get("passed", False))]
        failed = [item for item in benchmarks if not bool(item.get("passed", False))]
        return {
            "manifest_name": str(coverage_metrics.get("manifest_name", "")) if isinstance(coverage_metrics, dict) else "",
            "manifest_version": str(coverage_metrics.get("manifest_version", "")) if isinstance(coverage_metrics, dict) else "",
            "passed_count": len(passed),
            "total_count": len(benchmarks),
            "all_passed": bool(benchmarks) and len(passed) == len(benchmarks),
            "passed_categories": [str(item.get("name", "")) for item in passed],
            "failed_categories": [str(item.get("name", "")) for item in failed],
            "category_scores": {
                str(item.get("name", "")): float(item.get("score", 0.0) or 0.0)
                for item in benchmarks
                if str(item.get("name", "")).strip()
            },
        }

    def _load_benchmark_manifest(self) -> dict[str, Any]:
        candidates = [
            self.project_root / "fixtures" / "v2_benchmark_manifest.json",
            Path(__file__).resolve().parents[3] / "fixtures" / "v2_benchmark_manifest.json",
        ]
        for path in candidates:
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        return {"manifest_version": "", "name": "", "categories": []}

    def _maybe_spawn_subagents(self, scan) -> None:
        from .models import AgentEvent, SubAgentState, SubAgentTask, make_id, now_iso

        running_count = sum(1 for item in scan.subagents.values() if item.status == "running")
        max_parallel = max(int(scan.profile.max_parallel_subagents or 1), 1)
        for step in scan.plan.steps:
            if running_count >= max_parallel:
                break
            state = scan.step_states.get(step.step_id)
            if state is None or state.status != "completed":
                continue
            for policy in self.skill_catalog.child_policies_for_module(step.name):
                if running_count >= max_parallel:
                    break
                if self._has_subagent_for_step(scan, step.step_id, policy.task_name):
                    continue
                seed_context = self._build_subagent_seed_context(scan, step.name, state)
                seed_context["_llm_profile"] = scan.profile.to_dict()
                if not self._should_spawn_subagent(policy.spawn_condition, state, seed_context):
                    continue
                task = SubAgentTask(
                    task_id=make_id("task"),
                    name=policy.task_name,
                    goal=policy.goal,
                    target=scan.target,
                    planned_tools=list(policy.planned_tools),
                    max_iterations=int(policy.max_iterations or 6),
                    seed_artifact_ids=list(state.artifact_ids),
                    seed_step_id=step.step_id,
                    seed_context=seed_context,
                    success_criteria=list(getattr(policy, "success_criteria", [])),
                    verification_gap=state.verification_gap,
                    already_attempted=[
                        f"{item.tool_name}:{json.dumps(item.arguments, ensure_ascii=False, sort_keys=True, default=str)}"
                        for item in state.decision_records[-8:]
                    ],
                    artifact_refs=list(state.artifact_ids),
                    budget={"max_iterations": int(policy.max_iterations or 6), "max_tool_calls": int(policy.max_iterations or 6)},
                    stop_conditions=list(getattr(policy, "stop_conditions", [])),
                    allowed_tools=list(policy.planned_tools),
                    output_contract=list(getattr(policy, "output_contract", [])),
                )
                subagent_id = self.subagent_runner.spawn(task)
                scan.subagents[subagent_id] = SubAgentState(subagent_id=subagent_id, task=task, status="running", started_at=now_iso())
                state.spawned_subagents.append(subagent_id)
                scan.events.append(
                    AgentEvent(
                        event_id=make_id("evt"),
                        stage="step",
                        kind="subagent_spawned",
                        message=f"已创建子 Agent：{task.name}",
                        payload={"subagent_id": subagent_id, "task_id": task.task_id, "seed_step_id": step.step_id},
                    )
                )
                running_count += 1

    def _has_subagent_for_step(self, scan, step_id: str, task_name: str) -> bool:
        for state in scan.subagents.values():
            if state.task.seed_step_id == step_id and state.task.name == task_name:
                return True
        return False

    def _build_subagent_seed_context(self, scan, step_name: str, step_state) -> dict[str, Any]:
        context = dict(step_state.output_context)
        if step_name == "js_audit":
            raw_candidates = context.get("endpoint_candidates", [])
            absolute_candidates = []
            for item in raw_candidates if isinstance(raw_candidates, list) else []:
                candidate = str(item).strip()
                if not candidate:
                    continue
                absolute = urljoin(scan.target, candidate)
                if absolute not in absolute_candidates:
                    absolute_candidates.append(absolute)
            context["endpoint_candidates"] = absolute_candidates[:6]
        if step_name == "xss_triage":
            raw_urls = []
            locations = context.get("xss_locations", [])
            reflected = context.get("reflected_probe_urls", [])
            if isinstance(locations, list):
                raw_urls.extend(str(item).strip() for item in locations if str(item).strip())
            if isinstance(reflected, list):
                raw_urls.extend(str(item).strip() for item in reflected if str(item).strip())
            deduped = []
            for item in raw_urls:
                normalized = urljoin(scan.target, item)
                if normalized not in deduped:
                    deduped.append(normalized)
            context["xss_probe_urls"] = deduped[:6]
        return context

    def _should_spawn_subagent(self, spawn_condition: str, step_state, seed_context: dict[str, Any]) -> bool:
        if spawn_condition == "has_leads":
            return bool(step_state.leads)
        if spawn_condition == "endpoint_candidates_or_js_heuristics":
            endpoint_candidates = seed_context.get("endpoint_candidates", [])
            heuristics = seed_context.get("heuristics", {})
            return bool(endpoint_candidates) or any(int(heuristics.get(key, 0)) > 0 for key in ("eval_calls", "inner_html", "dangerous_sources"))
        if spawn_condition == "xss_probe_urls":
            return bool(seed_context.get("xss_probe_urls", []))
        if spawn_condition == "suspicious_differential":
            differential_signals = seed_context.get("differential_signals", [])
            return any(bool(item.get("suspicious_difference", False)) for item in differential_signals if isinstance(item, dict))
        return False

    def _collect_subagents(self, scan) -> None:
        from .models import AgentEvent, make_id

        for subagent_id, result in self.subagent_runner.collect_ready():
            scan.subagents[subagent_id] = result
            for artifact in result.artifacts:
                scan.artifacts[artifact.artifact_id] = artifact
            for finding in result.verified_findings:
                if str(scan.plan.module_bundle or "full").strip().lower() == "js" and str(finding.category).strip() == "js_derived_api":
                    continue
                scan.verified_findings.append(finding)
            scan.events.append(
                AgentEvent(
                    event_id=make_id("evt"),
                    stage="step_replan",
                    kind="subagent_completed",
                    message=f"子 Agent {subagent_id} 已完成，发现 {len(result.leads)} 条线索。",
                    payload={"subagent_id": subagent_id, "lead_count": len(result.leads)},
                )
            )

    def _collect_subagents_until_quiet(self, scan, *, max_wait_seconds: float = 0.2) -> None:
        deadline = time.monotonic() + max_wait_seconds
        while True:
            before = {
                subagent_id
                for subagent_id, state in scan.subagents.items()
                if state.status in {"completed", "failed", "blocked"}
            }
            self._collect_subagents(scan)
            after = {
                subagent_id
                for subagent_id, state in scan.subagents.items()
                if state.status in {"completed", "failed", "blocked"}
            }
            running = any(state.status == "running" for state in scan.subagents.values())
            if after != before:
                continue
            if not running or time.monotonic() >= deadline:
                break
            time.sleep(0.02)

    def _run_subagent(self, subagent_id: str, task) -> Any:
        from .models import SubAgentState, now_iso

        workspace = self.run_dir / "subagents" / subagent_id
        registry = ToolRegistry(workspace / "artifacts")
        state = SubAgentState(subagent_id=subagent_id, task=task, status="running", started_at=now_iso())
        if task.name == "backup-source-audit-child":
            self._run_backup_subagent(state, registry)
        elif task.name in {"js-derived-api-child", "xss-multi-entry-child", "auth-differential-child"}:
            self._run_subagent_loop(state, registry)
        else:
            state.error = f"unsupported subagent task {task.name}"
            state.status = "failed"
            state.done_reason = "unsupported_task"
            state.finished_at = now_iso()
            return state
        if state.status not in {"failed", "blocked"}:
            state.status = "completed"
            state.done_reason = state.done_reason or "completed"
        state.finished_at = now_iso()
        return state

    def _record_subagent_execution(self, state, tool_name: str, execution) -> None:
        from .models import Observation, make_id

        artifact_ids = []
        for artifact in execution.artifacts:
            state.artifacts.append(artifact)
            state.artifact_ids.append(artifact.artifact_id)
            artifact_ids.append(artifact.artifact_id)
        state.observations.append(
            Observation(
                observation_id=make_id("obs"),
                tool_name=tool_name,
                status="ok" if execution.status == "ok" else "error",
                summary=execution.summary,
                payload=dict(execution.payload),
                artifact_ids=artifact_ids,
            )
        )
        state.iterations += 1
        state.tool_calls += 1

    def _run_subagent_loop(self, state, registry) -> None:
        max_iterations = max(int(getattr(state.task, "max_iterations", 6) or 6), 1)
        llm_engine = self._build_subagent_llm_engine(state)
        while state.iterations < max_iterations:
            action = self._decide_subagent_action(state, llm_engine)
            if action is None:
                state.done_reason = state.done_reason or "no_next_action"
                break
            tool_name, arguments = action
            context = {
                "target": self._subagent_context_target(state, arguments),
                "scan_id": state.subagent_id,
                "last_observation_payload": state.observations[-1].payload if state.observations else {},
                "subagent_seed_context": dict(state.task.seed_context),
            }
            execution = registry.execute(tool_name, arguments, context)
            self._record_subagent_execution(state, tool_name, execution)
            if self._derive_subagent_outputs(state):
                state.done_reason = "verified"
                break
        state.output_context = self._build_subagent_output_context(state)
        if not state.verified_findings and not state.leads and not state.observations:
            state.status = "blocked"
            state.done_reason = state.done_reason or "blocked_no_signal"

    def _build_subagent_llm_engine(self, state):
        from .models import AgentProfile

        payload = state.task.seed_context.get("_llm_profile", {}) if isinstance(state.task.seed_context, dict) else {}
        if isinstance(payload, dict) and payload:
            return LLMDecisionEngine(AgentProfile(**payload))
        return None

    def _decide_subagent_action(self, state, llm_engine) -> tuple[str, dict[str, Any]] | None:
        fallback_reason = ""
        action = None
        hypothesis = ""
        rationale = ""
        if llm_engine is not None and llm_engine.provider is not None and llm_engine.enabled:
            prompt = self._build_subagent_prompt(state)
            try:
                payload = complete_json_object(
                    llm_engine.provider,
                    prompt,
                    model_id=llm_engine.model_id,
                    max_tokens=512,
                    schema_hint='{"hypothesis":"string","tool_name":"http_request","arguments":{"url":"https://example.com"},"rationale":"string","done":false}',
                )
                if bool(payload.get("done", False)):
                    state.done_reason = "llm_done"
                    return None
                tool_name = str(payload.get("tool_name", "")).strip()
                arguments = dict(payload.get("arguments", {})) if isinstance(payload.get("arguments", {}), dict) else {}
                if tool_name and tool_name in state.task.planned_tools:
                    hypothesis = str(payload.get("hypothesis", "")).strip()
                    rationale = str(payload.get("rationale", "")).strip()
                    action = (tool_name, arguments)
                else:
                    fallback_reason = "tool_not_allowed_or_empty"
            except LLMError:
                fallback_reason = "llm_error"
        else:
            fallback_reason = "llm_unavailable"
        if action is None:
            action = self._fallback_subagent_action(state)
            if action is None:
                return None
            state.llm_fallback_count += 1
            rationale = rationale or "fallback subagent policy"
            self._record_subagent_decision(state, "fallback", action[0], action[1], hypothesis, rationale, fallback_reason, llm_engine)
            return action
        self._record_subagent_decision(state, "llm", action[0], action[1], hypothesis, rationale, "", llm_engine)
        return action

    def _record_subagent_decision(self, state, source: str, tool_name: str, arguments: dict[str, Any], hypothesis: str, rationale: str, fallback_reason: str, llm_engine) -> None:
        from .models import DecisionRecord, make_id

        state.decision_records.append(
            DecisionRecord(
                decision_id=make_id("decision"),
                source=source,
                tool_name=tool_name,
                arguments=dict(arguments),
                hypothesis=hypothesis,
                rationale=rationale,
                model="" if llm_engine is None else llm_engine.model_id,
                provider="" if llm_engine is None else llm_engine.provider_name,
                fallback_reason=fallback_reason,
            )
        )

    def _build_subagent_prompt(self, state) -> str:
        recent_observations = [item.to_dict() for item in state.observations[-4:]]
        recent_decisions = [item.to_dict() for item in state.decision_records[-4:]]
        return (
            "你是漏洞挖掘 child agent。请基于当前子任务目标和最近观察，选择下一步工具调用。\n"
            "只输出一个 JSON 对象："
            '{"hypothesis":"中文假设","tool_name":"工具名","arguments":{"k":"v"},"rationale":"中文理由","done":false}\n'
            f"Task: {state.task.name}\n"
            f"Goal: {state.task.goal}\n"
            f"Allowed tools: {', '.join(state.task.planned_tools)}\n"
            f"Seed context: {json.dumps(state.task.seed_context, ensure_ascii=False)}\n"
            f"Recent observations: {json.dumps(recent_observations, ensure_ascii=False)}\n"
            f"Recent decisions: {json.dumps(recent_decisions, ensure_ascii=False)}\n"
            "如果已无法推进或证据已足够，输出 done=true。"
        )

    def _fallback_subagent_action(self, state) -> tuple[str, dict[str, Any]] | None:
        if state.task.name == "js-derived-api-child":
            return self._decide_js_subagent_action(state)
        if state.task.name == "xss-multi-entry-child":
            return self._decide_xss_subagent_action(state)
        if state.task.name == "auth-differential-child":
            return self._decide_auth_subagent_action(state)
        return None

    def _subagent_context_target(self, state, arguments: dict[str, Any]) -> str:
        if state.task.name == "xss-multi-entry-child":
            action_url = str(arguments.get("url", "")).strip()
            if action_url:
                return action_url
            for observation in reversed(state.observations):
                if observation.tool_name == "http_request" and isinstance(observation.payload, dict):
                    url = str(observation.payload.get("url", "")).strip()
                    if url:
                        return url
        return state.task.target

    def _decide_js_subagent_action(self, state) -> tuple[str, dict[str, Any]] | None:
        endpoints = state.task.seed_context.get("endpoint_candidates", []) if isinstance(state.task.seed_context, dict) else []
        endpoints = [str(item) for item in endpoints] if isinstance(endpoints, list) else []
        checked = [
            str(item.payload.get("url", ""))
            for item in state.observations
            if item.tool_name == "http_request" and isinstance(item.payload, dict)
        ]
        for endpoint in endpoints[:3]:
            if endpoint not in checked:
                return ("http_request", {"url": endpoint, "method": "GET"})
        if checked and not any(item.tool_name == "artifact_capture" for item in state.observations):
            last_body = str(state.observations[-1].payload.get("body", "")) if state.observations else ""
            return (
                "artifact_capture",
                {"name": f"{state.task.name}-api-preview", "content": last_body[:400] or checked[0], "kind": "subagent_seed"},
            )
        return None

    def _decide_xss_subagent_action(self, state) -> tuple[str, dict[str, Any]] | None:
        urls = state.task.seed_context.get("xss_probe_urls", []) if isinstance(state.task.seed_context, dict) else []
        urls = [str(item) for item in urls] if isinstance(urls, list) else []
        checked = [
            str(item.payload.get("url", ""))
            for item in state.observations
            if item.tool_name == "http_request" and isinstance(item.payload, dict)
        ]
        for url in urls[:3]:
            if url not in checked:
                return ("http_request", {"url": url, "method": "GET"})
        reflected = any(
            item.tool_name == "http_request"
            and isinstance(item.payload, dict)
            and "<script>alert(1)</script>" in str(item.payload.get("body", "")).lower()
            for item in state.observations
        )
        browser_count = sum(1 for item in state.observations if item.tool_name == "browser_action")
        if reflected and browser_count == 0 and checked:
            return ("browser_action", {"command": "goto", "url": checked[0]})
        if reflected and browser_count == 1:
            return ("browser_action", {"command": "screenshot"})
        if reflected and browser_count >= 2 and not any(item.tool_name == "artifact_capture" for item in state.observations):
            last_body = next(
                (
                    str(item.payload.get("body", ""))[:400]
                    for item in reversed(state.observations)
                    if item.tool_name == "http_request" and isinstance(item.payload, dict)
                ),
                "",
            )
            return ("artifact_capture", {"name": f"{state.task.name}-reflection", "content": last_body or checked[0], "kind": "subagent_seed"})
        return None

    def _decide_auth_subagent_action(self, state) -> tuple[str, dict[str, Any]] | None:
        checked_urls = state.task.seed_context.get("checked_urls", []) if isinstance(state.task.seed_context, dict) else []
        target_url = str(checked_urls[0]).strip() if isinstance(checked_urls, list) and checked_urls else urljoin(state.task.target, "/admin")
        tool_names = [item.tool_name for item in state.observations]
        if "create_identity" not in tool_names:
            return ("create_identity", {"prefix": "childauth", "role": "user_a"})
        if tool_names.count("create_identity") == 1:
            return ("create_identity", {"prefix": "childauth", "role": "user_b"})
        if "session_store" not in tool_names:
            return ("session_store", {"action": "set_cookie", "session_name": "user_a", "name": "role", "value": "admin"})
        if tool_names.count("session_store") == 1:
            return ("session_store", {"action": "set_cookie", "session_name": "user_b", "name": "role", "value": "guest"})
        requests_seen = [item for item in state.observations if item.tool_name == "http_request"]
        if len(requests_seen) == 0:
            return (
                "http_request",
                {"url": target_url, "method": "GET", "session_name": "user_a", "headers": {"X-Agent-Role": "admin"}, "cookies": {"role": "admin"}},
            )
        if len(requests_seen) == 1:
            return (
                "http_request",
                {"url": target_url, "method": "GET", "session_name": "user_b", "headers": {"X-Agent-Role": "guest"}, "cookies": {"role": "guest"}},
            )
        if "compare_http_responses" not in tool_names:
            return ("compare_http_responses", {"before": requests_seen[0].payload, "after": requests_seen[1].payload})
        if "artifact_capture" not in tool_names:
            return (
                "artifact_capture",
                {"name": f"{state.task.name}-diff", "content": json.dumps(state.observations[-1].payload, ensure_ascii=False), "kind": "subagent_seed"},
            )
        return None

    def _derive_subagent_outputs(self, state) -> bool:
        if state.task.name == "js-derived-api-child":
            return self._derive_js_subagent_outputs(state)
        if state.task.name == "xss-multi-entry-child":
            return self._derive_xss_subagent_outputs(state)
        if state.task.name == "auth-differential-child":
            return self._derive_auth_subagent_outputs(state)
        return False

    def _promote_subagent_verified(
        self,
        state,
        *,
        title: str,
        category: str,
        severity: str,
        location: str,
        rationale: str,
        evidence: str,
        next_steps: list[str],
        method: str,
        summary: str,
        impact: str,
        recommendation: str,
        reproduction_steps: list[str],
        metadata: dict[str, Any] | None = None,
    ) -> None:
        from .models import Lead, VerificationRecord, VerifiedFinding, make_id

        lead = Lead(
            lead_id=make_id("lead"),
            title=title,
            category=category,
            severity=severity,
            location=location,
            rationale=rationale,
            evidence=evidence,
            next_steps=list(next_steps),
            metadata=dict(metadata or {}),
        )
        state.leads.append(lead)
        record = VerificationRecord(
            verification_id=make_id("verify"),
            lead_id=lead.lead_id,
            method=method,
            status="verified",
            summary=summary,
            proof=evidence,
            artifact_ids=list(state.artifact_ids),
            metadata=dict(metadata or {}),
        )
        state.verification_records.append(record)
        state.verified_findings.append(
            VerifiedFinding(
                finding_id=make_id("finding"),
                title=title,
                category=category,
                severity=severity,
                location=location,
                impact=impact,
                evidence=evidence,
                recommendation=recommendation,
                reproduction_steps=list(reproduction_steps),
                artifact_ids=list(state.artifact_ids),
                verification_id=record.verification_id,
                metadata=dict(metadata or {}),
            )
        )

    def _derive_js_subagent_outputs(self, state) -> bool:
        successful = [
            item
            for item in state.observations
            if item.tool_name == "http_request" and isinstance(item.payload, dict) and int(item.payload.get("status_code", 0)) < 400
        ]
        has_capture = any(item.tool_name == "artifact_capture" for item in state.observations)
        if not successful or not has_capture or state.verified_findings:
            return False
        first = successful[0]
        verified_url = str(first.payload.get("url", state.task.target))
        status_code = int(first.payload.get("status_code", 0))
        self._promote_subagent_verified(
            state,
            title="JS 派生接口验证成功",
            category="js_derived_api",
            severity="medium",
            location=verified_url,
            rationale="子 Agent 根据派生接口候选逐个试探，确认了真实可访问入口。",
            evidence=f"endpoint={verified_url}; status={status_code}",
            next_steps=["将入口回流主 Agent，继续做未授权、注入、XSS 或 SSRF 联动验证"],
            method="derived_api_replay",
            summary="子 Agent 多轮回放后确认派生接口可访问。",
            impact="证明前端资源中派生出的接口真实存在，可作为后续漏洞挖掘入口。",
            recommendation="将该接口纳入后续权限、注入与输入点测试。",
            reproduction_steps=[f"请求 {verified_url}", "确认接口返回可访问状态。"],
            metadata={"endpoint_url": verified_url},
        )
        return True

    def _derive_xss_subagent_outputs(self, state) -> bool:
        reflected = [
            item
            for item in state.observations
            if item.tool_name == "http_request"
            and isinstance(item.payload, dict)
            and "<script>alert(1)</script>" in str(item.payload.get("body", "")).lower()
        ]
        has_visual = any(item.tool_name == "browser_action" for item in state.observations)
        has_capture = any(item.tool_name == "artifact_capture" for item in state.observations)
        if not reflected or not has_visual or not has_capture or state.verified_findings:
            return False
        first = reflected[0]
        verified_url = str(first.payload.get("url", state.task.target))
        self._promote_subagent_verified(
            state,
            title="XSS 子任务复测到反射执行入口",
            category="xss_child_audit",
            severity="high",
            location=verified_url,
            rationale="子 Agent 多轮复测后确认 XSS payload 被反射，并固化了浏览器侧证据。",
            evidence=f"reflected_probe={verified_url}",
            next_steps=["将该入口回流主 Agent，继续做上下文识别与更强 payload 验证"],
            method="child_browser_reflection",
            summary="子 Agent 已完成 XSS 反射复测与浏览器证据固化。",
            impact="说明该输入点可被子 Agent 独立复测，为后续真实 XSS 利用链提供证据。",
            recommendation="对输出点做上下文敏感转义，并避免将未净化输入写入可执行上下文。",
            reproduction_steps=[f"请求 {verified_url}", "确认响应中反射 payload，并查看浏览器侧固化证据。"],
            metadata={"xss_probe_url": verified_url},
        )
        return True

    def _derive_auth_subagent_outputs(self, state) -> bool:
        diff_obs = next((item for item in reversed(state.observations) if item.tool_name == "compare_http_responses"), None)
        has_capture = any(item.tool_name == "artifact_capture" for item in state.observations)
        if diff_obs is None or not has_capture or state.verified_findings:
            return False
        suspicious = bool(diff_obs.payload.get("suspicious_difference", False)) if isinstance(diff_obs.payload, dict) else False
        if not suspicious:
            return False
        checked_urls = state.task.seed_context.get("checked_urls", []) if isinstance(state.task.seed_context, dict) else []
        target_url = str(checked_urls[0]).strip() if isinstance(checked_urls, list) and checked_urls else urljoin(state.task.target, "/admin")
        self._promote_subagent_verified(
            state,
            title="权限差分子任务验证到可疑越权边界",
            category="authorization_child_audit",
            severity="high",
            location=target_url,
            rationale="子 Agent 在多轮会话设置与访问后确认高低权限访问差异可复现。",
            evidence=json.dumps(diff_obs.payload, ensure_ascii=False),
            next_steps=["将差分结果回流主 Agent，继续扩展对象 ID 与更多角色验证"],
            method="child_differential_access",
            summary="子 Agent 已复测到可疑权限差异。",
            impact="证明子 Agent 可独立复测权限边界异常，为后续 IDOR 与垂直越权扩展提供证据。",
            recommendation="继续增加对象维度和多角色会话，固化可复现越权路径。",
            reproduction_steps=[f"以 admin 与 guest 分别访问 {target_url}", "比较返回状态码和响应差异。"],
            metadata={"target_url": target_url},
        )
        return True

    def _build_subagent_output_context(self, state) -> dict[str, Any]:
        context = {
            "task_name": state.task.name,
            "iterations": state.iterations,
            "tool_calls": state.tool_calls,
            "decision_count": len(state.decision_records),
            "llm_fallback_count": int(state.llm_fallback_count),
            "done_reason": state.done_reason,
            "lead_ids": [item.lead_id for item in state.leads],
            "verification_ids": [item.verification_id for item in state.verification_records],
            "verified_finding_ids": [item.finding_id for item in state.verified_findings],
            "artifact_ids": list(state.artifact_ids),
        }
        if state.task.name == "js-derived-api-child":
            checked_endpoints = [
                str(item.payload.get("url", ""))
                for item in state.observations
                if item.tool_name == "http_request" and isinstance(item.payload, dict)
            ]
            context["checked_endpoints"] = checked_endpoints
            context["endpoint_seeds"] = checked_endpoints
            context["route_candidates"] = checked_endpoints
            context["recommended_next_tests"] = [
                {
                    "type": "auth_replay",
                    "priority": "high",
                    "target": endpoint,
                    "reason": "JS-derived endpoint was reachable from child replay.",
                }
                for endpoint in checked_endpoints[:3]
            ]
        if state.task.name == "xss-multi-entry-child":
            checked_probe_urls = [
                str(item.payload.get("url", ""))
                for item in state.observations
                if item.tool_name == "http_request" and isinstance(item.payload, dict)
            ]
            context["checked_probe_urls"] = checked_probe_urls
            context["xss_probe_urls"] = checked_probe_urls
            context["xss_verified"] = any(item.category == "xss_child_audit" for item in state.verified_findings)
            context["recommended_next_tests"] = [
                {
                    "type": "browser_context_verify",
                    "priority": "high",
                    "target": url,
                    "reason": "Child observed reflected payload and browser-side artifact.",
                }
                for url in checked_probe_urls[:3]
            ]
        if state.task.name == "auth-differential-child":
            context["differential_verified"] = any(item.category == "authorization_child_audit" for item in state.verified_findings)
            context["session_seeds"] = ["user_a", "user_b"]
            checked_urls = state.task.seed_context.get("checked_urls", []) if isinstance(state.task.seed_context, dict) else []
            checked_urls = [str(item) for item in checked_urls] if isinstance(checked_urls, list) else []
            context["recommended_next_tests"] = [
                {
                    "type": "idor_expand",
                    "priority": "high",
                    "target": checked_urls[0] if checked_urls else state.task.target,
                    "reason": "Child verified differential access behavior.",
                }
            ]
        if state.task.name == "backup-source-audit-child":
            candidate_urls = [
                str(item.metadata.get("candidate_url", ""))
                for item in state.leads
                if isinstance(item.metadata, dict) and item.metadata.get("candidate_url")
            ]
            context["route_candidates"] = candidate_urls
            context["endpoint_seeds"] = candidate_urls
            context["recommended_next_tests"] = [
                {
                    "type": "source_route_followup",
                    "priority": "high",
                    "target": url,
                    "reason": "Backup child recovered accessible configuration/source artifact.",
                }
                for url in candidate_urls[:3]
            ]
        return context

    def _run_backup_subagent(self, state, registry) -> None:
        from .models import Lead, VerificationRecord, VerifiedFinding, make_id

        task = state.task
        fetch = None
        for candidate in [".git/config", ".env", "backup.zip", "www.zip", "site.zip", "db.sql"]:
            attempt = registry.execute("fetch_candidate_file", {"target": task.target, "candidate": candidate}, {"target": task.target, "scan_id": state.subagent_id})
            self._record_subagent_execution(state, "fetch_candidate_file", attempt)
            body = str(attempt.payload.get("body", "")) if isinstance(attempt.payload, dict) else ""
            if int(attempt.payload.get("status_code", 0) or 0) == 200 and body and "404 Not Found" not in body[:300]:
                fetch = attempt
                break
        if fetch is None:
            state.done_reason = "no_accessible_backup_artifact"
            state.output_context = self._build_subagent_output_context(state)
            return
        parsed = registry.execute(
            "parse_config",
            {"content": str(fetch.payload.get("body", ""))},
            {"target": task.target, "scan_id": state.subagent_id, "last_observation_payload": fetch.payload},
        )
        self._record_subagent_execution(state, "parse_config", parsed)
        grep = registry.execute(
            "grep_sensitive_patterns",
            {"content": str(fetch.payload.get("body", ""))},
            {"target": task.target, "scan_id": state.subagent_id, "last_observation_payload": fetch.payload},
        )
        self._record_subagent_execution(state, "grep_sensitive_patterns", grep)
        capture = registry.execute(
            "artifact_capture",
            {"name": f"{task.name}-config-preview", "content": str(fetch.payload.get("body", "")), "kind": "subagent_seed"},
            {"target": task.target, "scan_id": state.subagent_id},
        )
        self._record_subagent_execution(state, "artifact_capture", capture)
        risky_keys = parsed.payload.get("risky_keys", []) if isinstance(parsed.payload, dict) else []
        patterns = grep.payload.get("patterns", []) if isinstance(grep.payload, dict) else []
        proof = f"risky_keys={', '.join(str(item) for item in risky_keys)}; patterns={', '.join(str(item) for item in patterns)}"
        lead = Lead(
            lead_id=make_id("lead"),
            title="备份子任务发现配置敏感线索",
            category="backup_source_audit",
            severity="high" if risky_keys or patterns else "medium",
            location=str(fetch.payload.get("url", task.target)),
            rationale="子 Agent 独立分析了备份与配置内容，并提取出后续高价值审计线索。",
            evidence=proof,
            next_steps=["继续提取源码/配置内容", "向主 Agent 回传 follow-up context"],
            metadata={"candidate_url": str(fetch.payload.get("url", task.target))},
        )
        state.leads.append(lead)
        if self._is_weak_backup_proof(proof, lead.evidence):
            state.done_reason = "backup_artifact_without_sensitive_proof"
            state.output_context = self._build_subagent_output_context(state)
            return
        record = VerificationRecord(
            verification_id=make_id("verify"),
            lead_id=lead.lead_id,
            method="backup_config_review",
            status="verified",
            summary="子 Agent 已完成备份配置初步审计。",
            proof=lead.evidence,
            artifact_ids=list(state.artifact_ids),
        )
        state.verification_records.append(record)
        state.verified_findings.append(
            VerifiedFinding(
                finding_id=make_id("finding"),
                title="备份审计子任务提取到高价值配置线索",
                category="backup_source_audit",
                severity="medium",
                location=str(fetch.payload.get("url", task.target)),
                impact="为后续主任务补充源码与配置方向的高价值上下文。",
                evidence=lead.evidence,
                recommendation="继续下载、解压并解析备份内容，重点核验 secret、debug 与默认凭据。",
                reproduction_steps=["查看子 Agent 生成的 config-preview artifact。", "基于 lead 中的 URL 继续深度审计。"],
                artifact_ids=list(state.artifact_ids),
                verification_id=record.verification_id,
            )
        )
        state.output_context = self._build_subagent_output_context(state)
