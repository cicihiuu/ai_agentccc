from __future__ import annotations

import re
from typing import Any

from ai_security_agent.schemas import Finding, ModuleResult

from .common import is_local_or_lab_target, now_iso, target_scope_label
from .followup_bridge import extract_followup_inputs


SECRET_NAME_RE = re.compile(r"(?i)(secret|token|api[_-]?key|access[_-]?key|password|passwd|credential)")
DEBUG_FLAG_RE = re.compile(r"(?i)(debug|app_debug|trace|dev_mode|development)")
DEFAULT_CRED_RE = re.compile(r"(?i)(root|admin|test|demo)[:=/](root|admin|123456|password|demo)")
CONFIG_FILE_RE = re.compile(r"(?i)(\.env|config|settings|database|application\.(yml|yaml|properties)|web\.config|appsettings\.json)")
RISKY_RUNTIME_RE = re.compile(r"(?i)(upload|export|import|read|include|debug|trace|admin)")


def run(target: str, context: dict | None = None) -> ModuleResult:
    started = now_iso()
    followup_inputs = extract_followup_inputs("config_audit", context)

    if not is_local_or_lab_target(target):
        return ModuleResult(
            module="config_audit",
            target=target,
            status="skipped",
            findings=[],
            logs=["配置审计仅允许用于本地或课程实验目标。"],
            started_at=started,
            finished_at=now_iso(),
            error="only localhost or course lab targets are allowed",
        )

    if not followup_inputs:
        return ModuleResult(
            module="config_audit",
            target=target,
            status="skipped",
            findings=[],
            logs=["config_audit 未收到备份链路提供的配置上下文。"],
            started_at=started,
            finished_at=now_iso(),
            error="config audit requires backup-derived follow-up context",
        )

    return _run_followup(target, followup_inputs, started)


def _run_followup(target: str, followup_inputs: dict[str, Any], started: str) -> ModuleResult:
    logs = [
        f"目标范围：{target_scope_label(target)}",
        "配置审计已消费 backup_audit_extended 的 followup_context。",
    ]
    findings: list[Finding] = []

    config_paths = _string_list(
        followup_inputs.get("config_entrypoints", []),
        followup_inputs.get("source_paths", []),
        followup_inputs.get("artifact_name_hints", []),
        followup_inputs.get("relationship_followup_seeds", []),
        followup_inputs.get("download_export_paths", []),
        followup_inputs.get("upload_import_paths", []),
    )
    fallback_paths = _string_list(
        followup_inputs.get("exposed_artifacts", []),
        followup_inputs.get("downloaded_artifacts", []),
    )
    for value in fallback_paths:
        normalized = _normalize_backup_artifact_hint(value)
        if normalized and normalized not in config_paths:
            config_paths.append(normalized)
    frameworks = _string_list(followup_inputs.get("frameworks", []))
    db_hosts = _string_list(followup_inputs.get("db_hosts", []))
    include_paths = _string_list(followup_inputs.get("include_paths", []))
    relationship_items = followup_inputs.get("relationship_followup_items", [])

    matched_config_paths = [value for value in config_paths if CONFIG_FILE_RE.search(value)]
    secret_like_paths = [value for value in config_paths if SECRET_NAME_RE.search(value)]
    debug_like_hints = [value for value in config_paths if DEBUG_FLAG_RE.search(value)]
    default_cred_hints = [value for value in config_paths if DEFAULT_CRED_RE.search(value)]
    risky_runtime_hints = [value for value in config_paths if RISKY_RUNTIME_RE.search(value)]

    confirmed_count = 0

    if matched_config_paths or include_paths:
        evidence_parts = []
        if matched_config_paths:
            evidence_parts.append("config-oriented paths: " + ", ".join(matched_config_paths[:8]))
        if include_paths:
            evidence_parts.append("include-path hints: " + ", ".join(include_paths[:6]))
        findings.append(
            Finding(
                title="Backup-derived configuration exposure candidates",
                severity="medium",
                location=", ".join((matched_config_paths or include_paths)[:6]),
                evidence="; ".join(evidence_parts),
                kind="candidate",
                verification_status="unconfirmed",
                verified=False,
                recommendation="Review these config and include paths for exposed secrets, weak defaults, and unsafe runtime toggles.",
            )
        )

    publicly_exposed_config_paths = [value for value in matched_config_paths if "/" in value or value.startswith(".")]
    if publicly_exposed_config_paths:
        findings.append(
            Finding(
                title="Confirmed publicly exposed configuration path",
                severity="high",
                location=", ".join(publicly_exposed_config_paths[:6]),
                evidence="publicly reachable configuration-oriented paths: " + ", ".join(publicly_exposed_config_paths[:8]),
                kind="vulnerability",
                verification_status="confirmed",
                verified=True,
                recommendation="Remove public access to configuration files and keep deployment configuration outside the web root.",
                metadata={
                    "config_context": {
                        "path": publicly_exposed_config_paths[0],
                        "evidence_kind": "public_config_path",
                        "frameworks": frameworks[:6],
                        "db_hosts": db_hosts[:6],
                        "producer": "backup_audit_extended",
                    }
                },
            )
        )
        confirmed_count += 1

    secret_config_paths = [value for value in matched_config_paths if SECRET_NAME_RE.search(value)]
    debug_config_paths = [value for value in matched_config_paths if DEBUG_FLAG_RE.search(value)]

    if secret_config_paths or (secret_like_paths and db_hosts):
        evidence_parts = []
        if secret_config_paths:
            evidence_parts.append("publicly reachable secret-bearing config paths: " + ", ".join(secret_config_paths[:6]))
        elif secret_like_paths:
            evidence_parts.append("secret-like config references: " + ", ".join(secret_like_paths[:6]))
        if db_hosts:
            evidence_parts.append("database host hints: " + ", ".join(db_hosts[:6]))
        findings.append(
            Finding(
                title="Confirmed configuration exposure with secret-bearing indicators",
                severity="high",
                location=", ".join((secret_config_paths or secret_like_paths or db_hosts)[:6]),
                evidence="; ".join(evidence_parts),
                kind="vulnerability",
                verification_status="confirmed",
                verified=True,
                recommendation="Restrict public access to configuration files, rotate exposed credentials, and move secrets to protected secret storage.",
                metadata={
                    "config_context": {
                        "path": (secret_config_paths or secret_like_paths or db_hosts)[0] if (secret_config_paths or secret_like_paths or db_hosts) else "",
                        "evidence_kind": "secret_bearing_config",
                        "frameworks": frameworks[:6],
                        "db_hosts": db_hosts[:6],
                        "producer": "backup_audit_extended",
                    }
                },
            )
        )
        confirmed_count += 1
    elif secret_like_paths or db_hosts:
        evidence_parts = []
        if secret_like_paths:
            evidence_parts.append("secret-like config references: " + ", ".join(secret_like_paths[:6]))
        if db_hosts:
            evidence_parts.append("database host hints: " + ", ".join(db_hosts[:6]))
        findings.append(
            Finding(
                title="Possible secret-bearing configuration path",
                severity="high",
                location=", ".join((secret_like_paths or db_hosts)[:6]),
                evidence="; ".join(evidence_parts),
                kind="candidate",
                verification_status="unconfirmed",
                verified=False,
                recommendation="Validate whether credentials or connection secrets are hard-coded and rotate any leaked values.",
                metadata={
                    "config_context": {
                        "path": (secret_like_paths or db_hosts)[0] if (secret_like_paths or db_hosts) else "",
                        "evidence_kind": "secret_path_hint",
                        "frameworks": frameworks[:6],
                        "db_hosts": db_hosts[:6],
                        "producer": "backup_audit_extended",
                    }
                },
            )
        )

    if debug_config_paths or default_cred_hints:
        evidence_parts = []
        if debug_config_paths:
            evidence_parts.append("debug-oriented config paths: " + ", ".join(debug_config_paths[:6]))
        if default_cred_hints:
            evidence_parts.append("default-credential hints: " + ", ".join(default_cred_hints[:6]))
        findings.append(
            Finding(
                title="Confirmed weak configuration exposure",
                severity="medium",
                location=", ".join((debug_config_paths or default_cred_hints)[:6]),
                evidence="; ".join(evidence_parts),
                kind="vulnerability",
                verification_status="confirmed",
                verified=True,
                recommendation="Disable debug and trace toggles in public deployments, and remove weak default credentials from configuration assets.",
                metadata={
                    "config_context": {
                        "path": (debug_config_paths or default_cred_hints)[0] if (debug_config_paths or default_cred_hints) else "",
                        "evidence_kind": "weak_runtime_config",
                        "frameworks": frameworks[:6],
                        "db_hosts": db_hosts[:6],
                        "producer": "backup_audit_extended",
                    }
                },
            )
        )
        confirmed_count += 1
    elif debug_like_hints or default_cred_hints or risky_runtime_hints:
        evidence_parts = []
        if debug_like_hints:
            evidence_parts.append("debug-like hints: " + ", ".join(debug_like_hints[:6]))
        if default_cred_hints:
            evidence_parts.append("default-credential hints: " + ", ".join(default_cred_hints[:6]))
        if risky_runtime_hints:
            evidence_parts.append("risky runtime/file-handling hints: " + ", ".join(risky_runtime_hints[:6]))
        findings.append(
            Finding(
                title="Risky runtime or weak-default configuration hint",
                severity="medium",
                location=", ".join((debug_like_hints or default_cred_hints or risky_runtime_hints)[:6]),
                evidence="; ".join(evidence_parts),
                kind="candidate",
                verification_status="unconfirmed",
                verified=False,
                recommendation="Check debug mode, upload/export/file-read controls, and weak defaults before deployment.",
                metadata={
                    "config_context": {
                        "path": (debug_like_hints or default_cred_hints or risky_runtime_hints)[0] if (debug_like_hints or default_cred_hints or risky_runtime_hints) else "",
                        "evidence_kind": "runtime_config_hint",
                        "frameworks": frameworks[:6],
                        "db_hosts": db_hosts[:6],
                        "producer": "backup_audit_extended",
                    }
                },
            )
        )

    if frameworks:
        findings.append(
            Finding(
                title="Framework-aware configuration review handoff",
                severity="info",
                location=", ".join(frameworks[:4]),
                evidence="Framework hints available for targeted config review: " + ", ".join(frameworks[:6]),
                kind="scope",
                verification_status="informational",
                verified=False,
                recommendation="Prioritize framework-specific config files, environment toggles, and secret-loading paths.",
            )
        )

    rendered_items = _render_relationship_items(relationship_items)
    if rendered_items:
        findings.append(
            Finding(
                title="Relationship-backed configuration follow-up item",
                severity="info",
                location="relationship_followup_items",
                evidence="Structured config-relevant relationship items: " + ", ".join(rendered_items[:6]),
                kind="scope",
                verification_status="informational",
                verified=False,
                recommendation="Trace these relationships when reviewing config includes, route toggles, and secret-bearing files.",
            )
        )

    logs.append(f"config_audit consumed {len(config_paths)} config-like hints and confirmed {confirmed_count} findings.")

    if not findings:
        findings.append(
            Finding(
                title="配置审计检查清单",
                severity="low",
                location="backup-derived config context",
                evidence="在当前受限的备份后续输入中，未确认高置信度配置问题模式。",
                kind="scope",
                verification_status="informational",
                verified=False,
                recommendation="请人工复核恢复到的配置文件，重点关注密钥、调试开关、上传/导出控制与弱默认值。",
            )
        )

    return ModuleResult(
        module="config_audit",
        target=target,
        status="ok",
        findings=findings[:6],
        logs=logs,
        followup_context={
            "producer": "config_audit",
            "consumers": {
                "poc_verify": {
                    "high_risk_findings": [item.to_dict() for item in findings if item.verification_status == "confirmed"],
                    "config_findings": [item.to_dict() for item in findings],
                }
            },
            "high_risk_findings": [item.to_dict() for item in findings if item.verification_status == "confirmed"],
        },
        started_at=started,
        finished_at=now_iso(),
    )


def _string_list(*values: Any) -> list[str]:
    collected: list[str] = []
    for value in values:
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    text = item.strip()
                    if text and text not in collected:
                        collected.append(text)
    return collected


def _normalize_backup_artifact_hint(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "; Accessible " in text:
        text = text.split("; Accessible ", 1)[1]
    if "entries=" in text:
        text = text.split("entries=", 1)[1]
    if "members:" in text:
        member_block = text.split("members:", 1)[1]
        parts = [item.strip() for item in member_block.split("|")]
        for part in parts:
            candidate = part.split(":HTTP", 1)[0].strip()
            if CONFIG_FILE_RE.search(candidate):
                return candidate
        return ""
    return text


def _render_relationship_items(values: object) -> list[str]:
    rendered: list[str] = []
    if not isinstance(values, list):
        return rendered
    for item in values:
        if isinstance(item, dict):
            seed = str(item.get("seed", "")).strip()
            priority = str(item.get("priority", "low")).strip() or "low"
            traits = str(item.get("traits", "generic")).strip() or "generic"
            if seed:
                rendered.append(f"{seed}:{priority}:{traits}")
        elif isinstance(item, str):
            text = item.strip()
            if text:
                rendered.append(text)
    return rendered
