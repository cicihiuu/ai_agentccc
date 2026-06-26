from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ai_security_agent.schemas import Finding, ModuleResult


ANNOTATION_RE = re.compile(r"^\[category=(?P<category>[^\]]+)\]\[consumers=(?P<consumers>[^\]]+)\]\s*")
STATUS_CODE_RE = re.compile(r"HTTP\s+(\d{3})")
DOWNLOAD_SIZE_RE = re.compile(r"downloaded_size=(\d+)\s+bytes")
SOURCE_RE = re.compile(r"source=([^;]+)")
ARCHIVE_RE = re.compile(r"archive=([^;]+)")
EXTRACTED_COUNT_RE = re.compile(r"extracted_files=(\d+)")
ARCHIVE_TYPE_RE = re.compile(r"archive_type=([^;]+)")
WEAK_PASSWORD_RE = re.compile(r"weak_password=([^;]+)")
OUTCOME_RE = re.compile(r"outcome=([^;]+)")
PASSWORD_ATTEMPT_COUNT_RE = re.compile(r"password_attempt_count=(\d+)")
STRATEGY_SUPPORTED_RE = re.compile(r"strategy_supported=([^;]+)")
RETRY_CLASS_RE = re.compile(r"retry_class=([^;]+)")
RETRY_REQUIRES_NEW_INPUT_RE = re.compile(r"retry_requires_new_input=([^;]+)")
RETRY_BLOCKED_BY_POLICY_RE = re.compile(r"retry_blocked_by_policy=([^;]+)")
NEXT_STEP_RE = re.compile(r"next_step=([^;]+)")
RETRY_READINESS_RE = re.compile(r"retry_readiness=([^;]+)")
RETRY_READY_NOW_RE = re.compile(r"retry_ready_now=([^;]+)")
RETRY_PREREQUISITES_RE = re.compile(r"retry_prerequisites=([^;]+)")


@dataclass(slots=True)
class BackupFollowupContext:
    target: str
    source_module: str = "backup_audit_extended"
    version: int = 11
    finding_count: int = 0
    categories: list[str] = field(default_factory=list)
    recommended_consumers: list[str] = field(default_factory=list)
    exposed_artifacts: list[dict[str, Any]] = field(default_factory=list)
    downloaded_artifacts: list[dict[str, Any]] = field(default_factory=list)
    archive_outcomes: dict[str, list[dict[str, Any]]] = field(
        default_factory=lambda: {
            "extracted": [],
            "manual_followup": [],
            "weak_password": [],
            "tooling_gap": [],
            "strategy_unsupported": [],
            "password_exhausted": [],
        }
    )
    source_hints: dict[str, list[str]] = field(
        default_factory=lambda: {
            "api_paths": [],
            "auth_paths": [],
            "framework_routes": [],
            "route_prefixes": [],
            "controller_hints": [],
            "config_entrypoints": [],
            "download_export_paths": [],
            "upload_import_paths": [],
            "artifact_name_hints": [],
            "middleware_hints": [],
            "js_assets": [],
            "internal_urls": [],
            "db_hosts": [],
            "include_paths": [],
            "frameworks": [],
            "source_paths": [],
            "correlated_discovery_seeds": [],
            "relationship_followup_seeds": [],
            "relationship_followup_items": [],
        }
    )
    consumers: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "producer": self.source_module,
            "version": self.version,
            "target": self.target,
            "source_module": self.source_module,
            "finding_count": self.finding_count,
            "categories": list(self.categories),
            "recommended_consumers": list(self.recommended_consumers),
            "exposed_artifacts": list(self.exposed_artifacts),
            "downloaded_artifacts": list(self.downloaded_artifacts),
            "archive_outcomes": {
                "extracted": list(self.archive_outcomes["extracted"]),
                "manual_followup": list(self.archive_outcomes["manual_followup"]),
                "weak_password": list(self.archive_outcomes["weak_password"]),
                "tooling_gap": list(self.archive_outcomes["tooling_gap"]),
                "strategy_unsupported": list(self.archive_outcomes["strategy_unsupported"]),
                "password_exhausted": list(self.archive_outcomes["password_exhausted"]),
            },
            "source_hints": {
                "api_paths": list(self.source_hints["api_paths"]),
                "auth_paths": list(self.source_hints["auth_paths"]),
                "framework_routes": list(self.source_hints["framework_routes"]),
                "route_prefixes": list(self.source_hints["route_prefixes"]),
                "controller_hints": list(self.source_hints["controller_hints"]),
                "config_entrypoints": list(self.source_hints["config_entrypoints"]),
                "download_export_paths": list(self.source_hints["download_export_paths"]),
                "upload_import_paths": list(self.source_hints["upload_import_paths"]),
                "artifact_name_hints": list(self.source_hints["artifact_name_hints"]),
                "middleware_hints": list(self.source_hints["middleware_hints"]),
                "js_assets": list(self.source_hints["js_assets"]),
                "internal_urls": list(self.source_hints["internal_urls"]),
                "db_hosts": list(self.source_hints["db_hosts"]),
                "include_paths": list(self.source_hints["include_paths"]),
                "frameworks": list(self.source_hints["frameworks"]),
                "source_paths": list(self.source_hints["source_paths"]),
                "correlated_discovery_seeds": list(self.source_hints["correlated_discovery_seeds"]),
                "relationship_followup_seeds": list(self.source_hints["relationship_followup_seeds"]),
                "relationship_followup_items": _parse_relationship_item_labels(
                    self.source_hints["relationship_followup_items"]
                ),
            },
            "consumers": dict(self.consumers),
        }


def build_backup_audit_followup_context(result: ModuleResult | dict[str, Any]) -> dict[str, Any]:
    module_result = result if isinstance(result, ModuleResult) else ModuleResult.from_dict(result)
    if module_result.module != "backup_audit_extended":
        raise ValueError("backup follow-up context requires a backup_audit_extended module result")

    summary = BackupFollowupContext(
        target=module_result.target,
        source_module=module_result.module,
        finding_count=len(module_result.findings),
    )
    categories: list[str] = []
    consumers: list[str] = []
    for finding in module_result.findings:
        category, finding_consumers, detail = _split_annotation(finding.evidence)
        _append_many_unique(categories, [category] if category else [])
        _append_many_unique(consumers, finding_consumers)
        _consume_finding(summary, finding, category, detail)
    summary.categories = categories
    summary.recommended_consumers = consumers
    summary.consumers = {
        "sql_scan": {
            "exposed_artifacts": [item["path"] for item in summary.exposed_artifacts],
            "api_paths": list(summary.source_hints["api_paths"]),
            "auth_paths": list(summary.source_hints["auth_paths"]),
            "framework_routes": list(summary.source_hints["framework_routes"]),
            "route_prefixes": list(summary.source_hints["route_prefixes"]),
            "controller_hints": list(summary.source_hints["controller_hints"]),
            "config_entrypoints": list(summary.source_hints["config_entrypoints"]),
            "download_export_paths": list(summary.source_hints["download_export_paths"]),
            "upload_import_paths": list(summary.source_hints["upload_import_paths"]),
            "artifact_name_hints": list(summary.source_hints["artifact_name_hints"]),
            "middleware_hints": list(summary.source_hints["middleware_hints"]),
            "db_hosts": list(summary.source_hints["db_hosts"]),
            "include_paths": list(summary.source_hints["include_paths"]),
            "frameworks": list(summary.source_hints["frameworks"]),
            "source_paths": list(summary.source_hints["source_paths"]),
            "correlated_discovery_seeds": list(summary.source_hints["correlated_discovery_seeds"]),
            "relationship_followup_seeds": list(summary.source_hints["relationship_followup_seeds"]),
            "relationship_followup_items": _parse_relationship_item_labels(summary.source_hints["relationship_followup_items"]),
        },
        "js_audit": {
            "exposed_artifacts": [item["path"] for item in summary.exposed_artifacts],
            "downloaded_artifacts": [item["source_path"] for item in summary.downloaded_artifacts],
            "api_paths": list(summary.source_hints["api_paths"]),
            "framework_routes": list(summary.source_hints["framework_routes"]),
            "route_prefixes": list(summary.source_hints["route_prefixes"]),
            "controller_hints": list(summary.source_hints["controller_hints"]),
            "config_entrypoints": list(summary.source_hints["config_entrypoints"]),
            "download_export_paths": list(summary.source_hints["download_export_paths"]),
            "upload_import_paths": list(summary.source_hints["upload_import_paths"]),
            "artifact_name_hints": list(summary.source_hints["artifact_name_hints"]),
            "js_assets": list(summary.source_hints["js_assets"]),
            "include_paths": list(summary.source_hints["include_paths"]),
            "frameworks": list(summary.source_hints["frameworks"]),
            "source_paths": list(summary.source_hints["source_paths"]),
            "correlated_discovery_seeds": list(summary.source_hints["correlated_discovery_seeds"]),
            "relationship_followup_seeds": list(summary.source_hints["relationship_followup_seeds"]),
            "relationship_followup_items": _parse_relationship_item_labels(summary.source_hints["relationship_followup_items"]),
        },
        "xss_triage": {
            "downloaded_artifacts": [item["source_path"] for item in summary.downloaded_artifacts],
            "api_paths": list(summary.source_hints["api_paths"]),
            "framework_routes": list(summary.source_hints["framework_routes"]),
            "route_prefixes": list(summary.source_hints["route_prefixes"]),
            "controller_hints": list(summary.source_hints["controller_hints"]),
            "upload_import_paths": list(summary.source_hints["upload_import_paths"]),
            "download_export_paths": list(summary.source_hints["download_export_paths"]),
            "js_assets": list(summary.source_hints["js_assets"]),
            "frameworks": list(summary.source_hints["frameworks"]),
            "source_paths": list(summary.source_hints["source_paths"]),
        },
        "ssrf_triage": {
            "api_paths": list(summary.source_hints["api_paths"]),
            "auth_paths": list(summary.source_hints["auth_paths"]),
            "route_prefixes": list(summary.source_hints["route_prefixes"]),
            "controller_hints": list(summary.source_hints["controller_hints"]),
            "config_entrypoints": list(summary.source_hints["config_entrypoints"]),
            "download_export_paths": list(summary.source_hints["download_export_paths"]),
            "upload_import_paths": list(summary.source_hints["upload_import_paths"]),
            "internal_urls": list(summary.source_hints["internal_urls"]),
            "frameworks": list(summary.source_hints["frameworks"]),
        },
        "config_audit": {
            "exposed_artifacts": [item["path"] for item in summary.exposed_artifacts],
            "downloaded_artifacts": [item["source_path"] for item in summary.downloaded_artifacts],
            "config_entrypoints": list(summary.source_hints["config_entrypoints"]),
            "download_export_paths": list(summary.source_hints["download_export_paths"]),
            "upload_import_paths": list(summary.source_hints["upload_import_paths"]),
            "artifact_name_hints": list(summary.source_hints["artifact_name_hints"]),
            "db_hosts": list(summary.source_hints["db_hosts"]),
            "include_paths": list(summary.source_hints["include_paths"]),
            "frameworks": list(summary.source_hints["frameworks"]),
            "source_paths": list(summary.source_hints["source_paths"]),
            "relationship_followup_seeds": list(summary.source_hints["relationship_followup_seeds"]),
            "relationship_followup_items": _parse_relationship_item_labels(summary.source_hints["relationship_followup_items"]),
        },
        "permission_bypass": {
            "api_paths": list(summary.source_hints["api_paths"]),
            "auth_paths": list(summary.source_hints["auth_paths"]),
            "route_prefixes": list(summary.source_hints["route_prefixes"]),
            "controller_hints": list(summary.source_hints["controller_hints"]),
            "config_entrypoints": list(summary.source_hints["config_entrypoints"]),
            "middleware_hints": list(summary.source_hints["middleware_hints"]),
            "internal_urls": list(summary.source_hints["internal_urls"]),
            "frameworks": list(summary.source_hints["frameworks"]),
            "correlated_discovery_seeds": list(summary.source_hints["correlated_discovery_seeds"]),
            "relationship_followup_seeds": list(summary.source_hints["relationship_followup_seeds"]),
            "relationship_followup_items": _parse_relationship_item_labels(summary.source_hints["relationship_followup_items"]),
        },
        "poc_verify": {
            "exposed_artifacts": [item["path"] for item in summary.exposed_artifacts],
            "manual_followup_archives": [item["archive"] for item in summary.archive_outcomes["manual_followup"]],
            "weak_password_archives": [item["archive"] for item in summary.archive_outcomes["weak_password"]],
            "tooling_gap_archives": [item["archive"] for item in summary.archive_outcomes["tooling_gap"]],
            "strategy_unsupported_archives": [item["archive"] for item in summary.archive_outcomes["strategy_unsupported"]],
            "password_exhausted_archives": [item["archive"] for item in summary.archive_outcomes["password_exhausted"]],
            "auth_paths": list(summary.source_hints["auth_paths"]),
            "framework_routes": list(summary.source_hints["framework_routes"]),
            "route_prefixes": list(summary.source_hints["route_prefixes"]),
            "controller_hints": list(summary.source_hints["controller_hints"]),
            "config_entrypoints": list(summary.source_hints["config_entrypoints"]),
            "download_export_paths": list(summary.source_hints["download_export_paths"]),
            "upload_import_paths": list(summary.source_hints["upload_import_paths"]),
            "artifact_name_hints": list(summary.source_hints["artifact_name_hints"]),
            "middleware_hints": list(summary.source_hints["middleware_hints"]),
            "internal_urls": list(summary.source_hints["internal_urls"]),
            "db_hosts": list(summary.source_hints["db_hosts"]),
            "frameworks": list(summary.source_hints["frameworks"]),
            "correlated_discovery_seeds": list(summary.source_hints["correlated_discovery_seeds"]),
            "relationship_followup_seeds": list(summary.source_hints["relationship_followup_seeds"]),
            "relationship_followup_items": _parse_relationship_item_labels(summary.source_hints["relationship_followup_items"]),
            "archive_followup_items": _build_archive_followup_items(summary),
            "archive_action_queue": _build_archive_action_queue(summary),
            "archive_retry_queue": _build_archive_retry_queue(summary),
            "archive_manual_review_queue": _build_archive_manual_review_queue(summary),
            "archive_actionable_retry_queue": _build_archive_actionable_retry_queue(summary),
            "archive_deferred_retry_queue": _build_archive_deferred_retry_queue(summary),
            "archive_policy_blocked_queue": _build_archive_policy_blocked_queue(summary),
            "archive_retry_items": _build_archive_retry_items(summary),
            "archive_manual_review_items": _build_archive_manual_review_items(summary),
        },
    }
    return summary.to_dict()


def build_sql_scan_followup_context(result: ModuleResult | list[Finding]) -> dict[str, Any]:
    findings = result.findings if isinstance(result, ModuleResult) else result
    high_risk_findings = [finding.to_dict() for finding in findings if finding.severity in {"critical", "high"}]
    sql_bypass_findings = [_sql_bypass_candidate_from_finding(finding) for finding in findings]
    sql_bypass_findings = [item for item in sql_bypass_findings if item]
    return {
        "producer": "sql_scan",
        "high_risk_findings": high_risk_findings,
        "sql_bypass_findings": sql_bypass_findings,
        "consumers": {
            "sql_bypass": {
                "sql_findings": list(sql_bypass_findings),
                "high_risk_findings": list(high_risk_findings),
            },
            "poc_verify": {
                "high_risk_findings": list(high_risk_findings),
            }
        },
    }


def build_sql_bypass_followup_context(result: ModuleResult | list[Finding] | list[dict[str, Any]]) -> dict[str, Any]:
    if isinstance(result, ModuleResult):
        assessments = _extract_sql_bypass_assessments_from_findings(result.findings)
    elif isinstance(result, list) and result and isinstance(result[0], Finding):
        assessments = _extract_sql_bypass_assessments_from_findings(result)
    else:
        assessments = [dict(item) for item in result if isinstance(item, dict)] if isinstance(result, list) else []
    return {
        "producer": "sql_bypass",
        "sql_bypass_assessments": list(assessments),
        "consumers": {
            "poc_verify": {
                "sql_bypass_assessments": list(assessments),
            }
        },
    }


def _sql_bypass_candidate_from_finding(finding: Finding) -> dict[str, Any]:
    evidence = finding.evidence or ""
    parsed = _parse_sql_finding_evidence(evidence)
    page_url = parsed.get("Page", "")
    parameter = parsed.get("Parameter", "")
    if not page_url or not parameter:
        return {}
    return {
        "page_url": page_url,
        "parameter": parameter,
        "method": parsed.get("Method", "GET").upper(),
        "baseline_url": parsed.get("Baseline URL", ""),
        "baseline_body": parsed.get("Baseline body", ""),
        "confirmed_strategies": _split_csv(parsed.get("Confirmed strategies", "")),
        "strategy_lengths": _parse_strategy_lengths(parsed.get("Strategy lengths", "")),
        "basis": parsed.get("Decision basis", ""),
        "source_title": finding.title,
        "source_location": finding.location,
        "source_verified": finding.verified,
    }


def _extract_sql_bypass_assessments_from_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    assessments: list[dict[str, Any]] = []
    for finding in findings:
        if "Assessment conclusion:" not in (finding.evidence or ""):
            continue
        parsed = _parse_sql_finding_evidence(finding.evidence)
        assessments.append(
            {
                "title": finding.title,
                "severity": finding.severity,
                "location": finding.location,
                "verified": finding.verified,
                "waf_profile": parsed.get("type", ""),
                "tested_strategies": _extract_observation_names(finding.evidence),
                "tamper_recommendations": _split_csv(parsed.get("Tamper recommendations", "")),
                "assessment_conclusion": parsed.get("Assessment conclusion", ""),
            }
        )
    return assessments


def _parse_sql_finding_evidence(evidence: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw_line in (evidence or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        key, sep, value = line.partition(":")
        if not sep:
            continue
        parsed[key.strip()] = value.strip()
    return parsed


def _split_csv(value: str) -> list[str]:
    if not value or value.lower() in {"none", "none recorded", "n/a"}:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_strategy_lengths(value: str) -> dict[str, int]:
    lengths: dict[str, int] = {}
    for item in _split_csv(value):
        name, sep, raw_length = item.partition("=")
        if not sep:
            continue
        try:
            lengths[name.strip()] = int(raw_length.strip())
        except ValueError:
            continue
    return lengths


def _extract_observation_names(evidence: str) -> list[str]:
    names: list[str] = []
    for line in (evidence or "").splitlines():
        stripped = line.strip()
        if not stripped.startswith("- "):
            continue
        name, sep, _rest = stripped[2:].partition(":")
        if sep and name and name not in names:
            names.append(name)
    return names


def extract_followup_inputs(module_name: str, context: dict[str, Any] | None) -> dict[str, Any]:
    context = context or {}
    upstream = context.get("upstream_followup_context")
    if not isinstance(upstream, dict):
        return {}
    allowed_producers = _followup_producers_for(module_name)
    merged: dict[str, Any] = {}
    for candidate in upstream.values():
        if not isinstance(candidate, dict):
            continue
        producer = str(candidate.get("producer", "")).strip()
        if producer not in allowed_producers:
            continue
        payload = _consumer_payload(candidate, module_name)
        if payload:
            merged = _merge_dicts(merged, payload)
    return merged


def extract_high_risk_findings(context: dict[str, Any] | None) -> list[dict[str, Any]]:
    context = context or {}
    upstream = context.get("upstream_followup_context")
    if not isinstance(upstream, dict):
        return []
    findings: list[dict[str, Any]] = []
    for candidate in upstream.values():
        if not isinstance(candidate, dict):
            continue
        direct_high = candidate.get("high_risk_findings")
        if isinstance(direct_high, list):
            _append_finding_dicts(findings, direct_high)
        payload = _consumer_payload(candidate, "poc_verify")
        high = payload.get("high_risk_findings")
        if isinstance(high, list):
            _append_finding_dicts(findings, high)
    return findings


def extract_sql_bypass_assessments(context: dict[str, Any] | None) -> list[dict[str, Any]]:
    context = context or {}
    upstream = context.get("upstream_followup_context")
    if not isinstance(upstream, dict):
        return []
    assessments: list[dict[str, Any]] = []
    for candidate in upstream.values():
        if not isinstance(candidate, dict):
            continue
        direct = candidate.get("sql_bypass_assessments")
        if isinstance(direct, list):
            _append_dicts(assessments, direct)
        payload = _consumer_payload(candidate, "poc_verify")
        nested = payload.get("sql_bypass_assessments")
        if isinstance(nested, list):
            _append_dicts(assessments, nested)
    return assessments


def _consumer_payload(followup_context: dict[str, Any], module_name: str) -> dict[str, Any]:
    consumers = followup_context.get("consumers")
    if not isinstance(consumers, dict):
        return {}
    value = consumers.get(module_name)
    return dict(value) if isinstance(value, dict) else {}


def _followup_producers_for(module_name: str) -> set[str]:
    producers = {"backup_audit_extended"}
    if module_name in {"recon", "js_audit", "sql_scan", "xss_triage", "ssrf_triage", "permission_bypass", "weak_password", "poc_verify"}:
        producers.add("state_bootstrap")
    if module_name in {"js_audit", "sql_scan", "xss_triage", "ssrf_triage", "permission_bypass", "weak_password"}:
        producers.add("recon")
    if module_name in {"xss_triage", "ssrf_triage", "permission_bypass", "poc_verify"}:
        producers.add("js_audit")
    return producers


def _merge_dicts(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    merged = dict(left)
    for key, value in right.items():
        if key not in merged:
            merged[key] = value
            continue
        if isinstance(merged[key], list) and isinstance(value, list):
            items = list(merged[key])
            for item in value:
                if item not in items:
                    items.append(item)
            merged[key] = items
            continue
        if isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _merge_dicts(merged[key], value)
            continue
        merged[key] = value
    return merged


def _append_finding_dicts(target: list[dict[str, Any]], values: list[Any]) -> None:
    seen = {
        (
            str(item.get("title", "")),
            str(item.get("severity", "")),
            str(item.get("location", "")),
            str(item.get("evidence", "")),
        )
        for item in target
    }
    for value in values:
        if not isinstance(value, dict):
            continue
        key = (
            str(value.get("title", "")),
            str(value.get("severity", "")),
            str(value.get("location", "")),
            str(value.get("evidence", "")),
        )
        if key in seen:
            continue
        target.append(dict(value))
        seen.add(key)


def _append_dicts(target: list[dict[str, Any]], values: list[Any]) -> None:
    seen = {repr(sorted(item.items())) for item in target}
    for value in values:
        if not isinstance(value, dict):
            continue
        item = dict(value)
        key = repr(sorted(item.items()))
        if key in seen:
            continue
        target.append(item)
        seen.add(key)


def _consume_finding(summary: BackupFollowupContext, finding: Finding, category: str, detail: str) -> None:
    if category == "exposure":
        path = detail.split("->", 1)[0].strip()
        item: dict[str, Any] = {
            "path": path,
            "title": finding.title,
            "severity": finding.severity,
            "url": finding.location,
        }
        status_code = _match_int(STATUS_CODE_RE, detail)
        if status_code is not None:
            item["status_code"] = status_code
        _append_unique(summary.exposed_artifacts, item)
        return
    if category == "artifact_download":
        source_path = _match_text(SOURCE_RE, detail)
        item = {
            "source_path": source_path or finding.location.rsplit("/", 1)[-1],
            "url": finding.location,
            "title": finding.title,
        }
        size = _match_int(DOWNLOAD_SIZE_RE, detail)
        if size is not None:
            item["size_bytes"] = size
        _append_unique(summary.downloaded_artifacts, item)
        return
    if category == "archive_extracted":
        item = {
            "archive": _match_text(ARCHIVE_RE, detail) or finding.location.rsplit("/", 1)[-1],
            "url": finding.location,
            "title": finding.title,
        }
        extracted_count = _match_int(EXTRACTED_COUNT_RE, detail)
        if extracted_count is not None:
            item["extracted_files"] = extracted_count
        archive_type = _match_text(ARCHIVE_TYPE_RE, detail)
        if archive_type:
            item["archive_type"] = archive_type
        _append_unique(summary.archive_outcomes["extracted"], item)
        return
    if category == "archive_followup":
        item = {
            "archive": _match_text(ARCHIVE_RE, detail) or finding.location.rsplit("/", 1)[-1],
            "url": finding.location,
            "title": finding.title,
            "severity": finding.severity,
        }
        archive_type = _match_text(ARCHIVE_TYPE_RE, detail)
        if archive_type:
            item["archive_type"] = archive_type
        outcome = _match_text(OUTCOME_RE, detail)
        if outcome:
            item["outcome"] = outcome
        password_attempt_count = _match_int(PASSWORD_ATTEMPT_COUNT_RE, detail)
        if password_attempt_count is not None:
            item["password_attempt_count"] = password_attempt_count
        strategy_supported = _match_text(STRATEGY_SUPPORTED_RE, detail)
        if strategy_supported:
            item["strategy_supported"] = strategy_supported
        item["blocker_class"] = _blocker_class_for_archive_title(title=finding.title, outcome=item.get("outcome", ""))
        retry_profile = _build_archive_retry_profile(item["blocker_class"])
        retry_class = _match_text(RETRY_CLASS_RE, detail)
        if retry_class:
            retry_profile["retry_class"] = retry_class
        retry_readiness = _match_text(RETRY_READINESS_RE, detail)
        if retry_readiness:
            retry_profile["retry_readiness"] = retry_readiness
        retry_requires_new_input = _match_text(RETRY_REQUIRES_NEW_INPUT_RE, detail)
        if retry_requires_new_input:
            retry_profile["retry_requires_new_input"] = retry_requires_new_input.lower() == "true"
        retry_ready_now = _match_text(RETRY_READY_NOW_RE, detail)
        if retry_ready_now:
            retry_profile["retry_ready_now"] = retry_ready_now.lower() == "true"
        retry_prerequisites = _match_text(RETRY_PREREQUISITES_RE, detail)
        if retry_prerequisites:
            retry_profile["retry_prerequisites"] = [item.strip() for item in retry_prerequisites.split(",") if item.strip()]
        retry_blocked_by_policy = _match_text(RETRY_BLOCKED_BY_POLICY_RE, detail)
        if retry_blocked_by_policy:
            retry_profile["retry_blocked_by_policy"] = retry_blocked_by_policy.lower() == "true"
        next_step = _match_text(NEXT_STEP_RE, detail)
        if next_step:
            retry_profile["next_step"] = next_step
        item.update(retry_profile)
        _append_unique(summary.archive_outcomes["manual_followup"], item)
        _classify_archive_followup_item(summary, item, finding.title)
        return
    if category == "weak_archive_password":
        item = {
            "archive": _match_text(ARCHIVE_RE, detail) or finding.location.rsplit("/", 1)[-1],
            "url": finding.location,
            "title": finding.title,
        }
        weak_password = _match_text(WEAK_PASSWORD_RE, detail)
        if weak_password:
            item["weak_password"] = weak_password
        _append_unique(summary.archive_outcomes["weak_password"], item)
        return

    title_to_bucket = {
        "Recovered API or route references from backup": "api_paths",
        "Recovered authentication or admin entrypoint hint from backup": "auth_paths",
        "Recovered framework route definition hint from backup": "framework_routes",
        "Recovered route prefix hint from backup": "route_prefixes",
        "Recovered structure-derived route prefix hint from backup": "route_prefixes",
        "Recovered controller or handler hint from backup": "controller_hints",
        "Recovered structure-derived controller hint from backup": "controller_hints",
        "Recovered config-defined entrypoint hint from backup": "config_entrypoints",
        "Recovered structure-derived config entrypoint hint from backup": "config_entrypoints",
        "Recovered download or export entrypoint hint from backup": "download_export_paths",
        "Recovered structure-derived download or export hint from backup": "download_export_paths",
        "Recovered upload or import entrypoint hint from backup": "upload_import_paths",
        "Recovered structure-derived upload or import hint from backup": "upload_import_paths",
        "Recovered backup artifact naming hint from backup": "artifact_name_hints",
        "Recovered structure-derived artifact naming hint from backup": "artifact_name_hints",
        "Recovered authentication or middleware guard hint from backup": "middleware_hints",
        "Recovered JavaScript asset reference from backup": "js_assets",
        "Recovered internal service URL from backup": "internal_urls",
        "Recovered database host hint from backup": "db_hosts",
        "Recovered source include or require path hint from backup": "include_paths",
        "Recovered framework fingerprint from backup": "frameworks",
        "Recovered high-value source path hint from backup": "source_paths",
        "Recovered correlated backup follow-up seed from source relationships": "correlated_discovery_seeds",
        "Recovered high-confidence relationship follow-up seed from backup": "relationship_followup_seeds",
        "Recovered structure-derived relationship follow-up seed from backup": "relationship_followup_seeds",
        "Recovered structured relationship follow-up item from backup": "relationship_followup_items",
        "Recovered structured structure-derived relationship item from backup": "relationship_followup_items",
    }
    bucket = title_to_bucket.get(finding.title)
    if bucket:
        _append_many_unique(summary.source_hints[bucket], _extract_hint_values(detail))


def _split_annotation(evidence: str) -> tuple[str, list[str], str]:
    match = ANNOTATION_RE.match((evidence or "").strip())
    if not match:
        return "", [], (evidence or "").strip()
    return (
        match.group("category").strip(),
        [item.strip() for item in match.group("consumers").split(",") if item.strip()],
        evidence[match.end() :].strip(),
    )


def _extract_hint_values(detail: str) -> list[str]:
    hint_block = detail.split(":", 1)[1] if ":" in detail else detail
    return [item.strip() for item in hint_block.split(",") if item.strip()]


def _parse_relationship_item_labels(values: list[str]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for value in values:
        parts = [part.strip() for part in value.split(":")]
        if not parts or not parts[0]:
            continue
        items.append(
            {
                "seed": parts[0],
                "priority": parts[1] if len(parts) > 1 else "low",
                "traits": parts[2] if len(parts) > 2 else "generic",
                "components": parts[3] if len(parts) > 3 else parts[0],
            }
        )
    return items


def _classify_archive_followup_item(summary: BackupFollowupContext, item: dict[str, Any], title: str) -> None:
    if title == "Non-zip archive handling is limited by missing optional unpacker":
        _append_unique(summary.archive_outcomes["tooling_gap"], item)
        return
    if title == "Protected non-zip archive format is outside the controlled password strategy":
        _append_unique(summary.archive_outcomes["strategy_unsupported"], item)
        return
    if title == "Protected non-zip archive resisted controlled password candidates":
        _append_unique(summary.archive_outcomes["password_exhausted"], item)


def _build_archive_followup_items(summary: BackupFollowupContext) -> list[dict[str, Any]]:
    return [dict(item) for item in summary.archive_outcomes["manual_followup"]]


def _build_archive_action_queue(summary: BackupFollowupContext) -> list[str]:
    actions: list[str] = []
    if summary.archive_outcomes["weak_password"]:
        actions.append("rotate_and_review_weak_password_archives")
    if summary.archive_outcomes["tooling_gap"]:
        actions.append("validate_optional_unpacker_support_before_retry")
    if summary.archive_outcomes["strategy_unsupported"]:
        actions.append("respect_format_boundary_and_require_manual_review")
    if summary.archive_outcomes["password_exhausted"]:
        actions.append("record_candidate_exhaustion_and_escalate_manually_if_authorized")
    if any(item.get("retry_requires_new_input") for item in summary.archive_outcomes["manual_followup"]):
        actions.append("retry_only_after_authorized_password_recovery")
    if summary.archive_outcomes["manual_followup"]:
        actions.append("keep_manual_followup_queue_for_remaining_archives")
    return actions


def _build_archive_retry_queue(summary: BackupFollowupContext) -> list[str]:
    return [item["archive"] for item in summary.archive_outcomes["manual_followup"] if item.get("retry_recommended")]


def _build_archive_manual_review_queue(summary: BackupFollowupContext) -> list[str]:
    return [item["archive"] for item in summary.archive_outcomes["manual_followup"] if not item.get("retry_recommended")]


def _build_archive_actionable_retry_queue(summary: BackupFollowupContext) -> list[str]:
    return [item["archive"] for item in summary.archive_outcomes["manual_followup"] if item.get("retry_readiness") == "actionable"]


def _build_archive_deferred_retry_queue(summary: BackupFollowupContext) -> list[str]:
    return [item["archive"] for item in summary.archive_outcomes["manual_followup"] if item.get("retry_readiness") == "deferred"]


def _build_archive_policy_blocked_queue(summary: BackupFollowupContext) -> list[str]:
    return [item["archive"] for item in summary.archive_outcomes["manual_followup"] if item.get("retry_readiness") == "policy_blocked"]


def _build_archive_retry_items(summary: BackupFollowupContext) -> list[dict[str, Any]]:
    return [dict(item) for item in summary.archive_outcomes["manual_followup"] if item.get("retry_recommended")]


def _build_archive_manual_review_items(summary: BackupFollowupContext) -> list[dict[str, Any]]:
    return [dict(item) for item in summary.archive_outcomes["manual_followup"] if not item.get("retry_recommended")]


def _blocker_class_for_archive_title(*, title: str, outcome: str) -> str:
    if title == "Non-zip archive handling is limited by missing optional unpacker" or outcome == "missing_optional_unpacker":
        return "tooling_gap"
    if title == "Protected non-zip archive format is outside the controlled password strategy" or outcome == "password_strategy_unsupported":
        return "strategy_unsupported"
    if title == "Protected non-zip archive resisted controlled password candidates" or outcome == "password_attempts_exhausted":
        return "password_exhausted"
    if outcome == "password_candidates_unavailable":
        return "candidate_set_gap"
    if outcome == "password_required":
        return "password_protected"
    if "weak password" in title.lower():
        return "weak_password"
    return "manual_followup"


def _build_archive_retry_profile(blocker_class: str) -> dict[str, Any]:
    if blocker_class == "tooling_gap":
        return {
            "retry_recommended": True,
            "retry_class": "environment_retry",
            "retry_readiness": "actionable",
            "retry_ready_now": True,
            "retry_prerequisites": ["optional_unpacker_support"],
            "retry_requires_new_input": False,
            "retry_blocked_by_policy": False,
            "next_step": "validate_optional_unpacker_support_then_retry",
        }
    if blocker_class in {"password_exhausted", "candidate_set_gap"}:
        return {
            "retry_recommended": True,
            "retry_class": "credential_retry",
            "retry_readiness": "deferred",
            "retry_ready_now": False,
            "retry_prerequisites": ["authorized_password_material"],
            "retry_requires_new_input": True,
            "retry_blocked_by_policy": False,
            "next_step": "retry_only_with_new_authorized_password_material",
        }
    if blocker_class == "strategy_unsupported":
        return {
            "retry_recommended": False,
            "retry_class": "policy_boundary",
            "retry_readiness": "policy_blocked",
            "retry_ready_now": False,
            "retry_prerequisites": ["manual_review_only"],
            "retry_requires_new_input": False,
            "retry_blocked_by_policy": True,
            "next_step": "respect_format_boundary_and_require_manual_review",
        }
    if blocker_class == "password_protected":
        return {
            "retry_recommended": False,
            "retry_class": "manual_review",
            "retry_readiness": "manual_only",
            "retry_ready_now": False,
            "retry_prerequisites": ["manual_archive_review"],
            "retry_requires_new_input": True,
            "retry_blocked_by_policy": False,
            "next_step": "review_archive_access_and_authorized_password_material_manually",
        }
    return {
        "retry_recommended": False,
        "retry_class": "manual_review",
        "retry_readiness": "manual_only",
        "retry_ready_now": False,
        "retry_prerequisites": ["manual_archive_review"],
        "retry_requires_new_input": False,
        "retry_blocked_by_policy": False,
        "next_step": "keep_manual_review_handoff_visible",
    }


def _append_unique(items: list[Any], value: Any) -> None:
    if value not in items:
        items.append(value)


def _append_many_unique(items: list[str], values: list[str]) -> None:
    for value in values:
        if value and value not in items:
            items.append(value)


def _match_int(pattern: re.Pattern[str], text: str) -> int | None:
    match = pattern.search(text)
    return int(match.group(1)) if match else None


def _match_text(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1).strip() if match else ""

