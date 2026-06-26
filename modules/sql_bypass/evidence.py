from __future__ import annotations

from ai_security_agent.schemas import Finding

from .models import BypassAssessmentRecord


def build_findings(target: str, records: list[BypassAssessmentRecord]) -> list[Finding]:
    if not records:
        return []
    return [_finding_from_record(target, record) for record in records[:6]]


def build_sql_bypass_followup_context(records: list[BypassAssessmentRecord]) -> dict[str, object]:
    assessments = [record.to_dict(redacted=True) for record in records]
    return {
        "producer": "sql_bypass",
        "sql_bypass_assessments": assessments,
        "assessment_summary": {
            "candidate_count": len(records),
            "records_with_signal": sum(1 for record in records if record.has_assessment_signal),
            "attempted_strategy_count": sum(len(record.observations) for record in records),
        },
        "consumers": {
            "poc_verify": {
                "sql_bypass_assessments": assessments,
            }
        },
    }


def _finding_from_record(target: str, record: BypassAssessmentRecord) -> Finding:
    candidate = record.candidate
    signal_observations = [item for item in record.observations if item.assessment_signal]
    severity = "medium" if signal_observations else "info"
    redacted_record = record.to_dict(redacted=True)
    signal_summary = redacted_record.get("signal_summary", {}) if isinstance(redacted_record.get("signal_summary", {}), dict) else {}
    best_observation = redacted_record.get("best_observation", {}) if isinstance(redacted_record.get("best_observation", {}), dict) else {}
    sqlmap_command = redacted_record.get("sqlmap_command", {}) if isinstance(redacted_record.get("sqlmap_command", {}), dict) else {}
    sqlmap_execution = record.sqlmap_command.get("execution_result", {}) if isinstance(record.sqlmap_command, dict) else {}
    tamper_lines = []
    for recommendation in record.tamper_recommendations[:5]:
        tamper_lines.append(
            f"- {recommendation.rank}. {recommendation.name} | source={recommendation.source} | scope={recommendation.dbms_scope or 'generic'} | {recommendation.reason}"
        )
    evidence = [
        "Assessment only; not a standalone confirmed vulnerability.",
        f"Target: {target}",
        f"Source SQL finding: {candidate.source_title or 'sql_scan finding'}",
        f"Page: {_redact_url(candidate.page_url, candidate.parameter)}",
        f"Parameter: {candidate.parameter}",
        f"Method: {candidate.method}",
        f"Baseline URL: {_redact_url(candidate.baseline_url, candidate.parameter) if candidate.baseline_url else 'derived from sql_scan page context'}",
        f"Baseline body: {_mask_body(candidate.baseline_body) or 'N/A'}",
        f"Source confirmed strategies: {', '.join(candidate.confirmed_strategies) or 'none recorded'}",
        f"Source basis: {candidate.basis or 'not recorded'}",
        f"DBMS hint: {record.dbms_hint or 'generic/unknown'}",
        "WAF profile:",
        f"- type: {record.waf_profile.waf_type}",
        f"- vendor: {record.waf_profile.vendor or 'generic'}",
        f"- detected: {record.waf_profile.detected}",
        f"- confidence: {record.waf_profile.confidence}",
        f"- matched_by: {', '.join(record.waf_profile.matched_by) or 'none'}",
        f"- recommendation_basis: {record.waf_profile.recommendation_basis or 'generic fallback'}",
        f"- signatures: {', '.join(record.waf_profile.signatures) or 'none'}",
        f"- blocked indicators: {', '.join(record.waf_profile.blocked_indicators) or 'none'}",
        "Tamper recommendations:",
        *(tamper_lines or ["- none"]),
        "Signal summary:",
        f"- signal_count: {signal_summary.get('signal_count', 0)}",
        f"- signal_types: {', '.join(signal_summary.get('signal_types', [])) or 'none'}",
        f"- attempted_strategies: {', '.join(signal_summary.get('attempted_strategy_names', [])) or 'none'}",
        f"- best_strategy: {signal_summary.get('best_strategy', '') or 'none'}",
        f"- best_signal_type: {signal_summary.get('best_signal_type', '') or 'none'}",
        f"sqlmap adapter: {sqlmap_command.get('execution_mode', 'generated_only')} | {sqlmap_command.get('primary_display', '')}",
        (
            "sqlmap execution: "
            f"returncode={sqlmap_execution.get('returncode', 'n/a')}, "
            f"timed_out={sqlmap_execution.get('timed_out', False)}, "
            f"confirmed={bool((sqlmap_execution.get('parsed', {}) or {}).get('injection_confirmed', False))}"
            if sqlmap_execution
            else "sqlmap execution: not run"
        ),
        "Bounded observations:",
    ]
    if best_observation:
        strategy = best_observation.get("strategy", {}) if isinstance(best_observation.get("strategy", {}), dict) else {}
        evidence.extend(
            [
                "Best bounded observation:",
                "- "
                f"strategy={strategy.get('name', 'unknown')}, "
                f"signal_type={best_observation.get('signal_type', 'none')}, "
                f"status={best_observation.get('status_code', 'n/a')}, "
                f"blocked={best_observation.get('blocked', False)}, "
                f"basis={best_observation.get('basis', 'not recorded')}",
            ]
        )
    for observation in record.observations[:8]:
        evidence.append(
            "- "
            f"{observation.strategy.name}: status={observation.status_code}, len={observation.response_length}, "
            f"blocked={observation.blocked}, delta={observation.delta_from_baseline}, "
            f"true_false_delta={observation.true_false_delta}, sql_error={observation.sql_error_marker}, "
            f"signal={observation.assessment_signal}, signal_type={observation.signal_type}; "
            f"control=baseline:{observation.control_probe.normal_baseline.status_code}/"
            f"basic:{observation.control_probe.basic_attack.status_code}/"
            f"bypass:{observation.control_probe.bypass_attack.status_code}; "
            f"basis={observation.basis}"
        )
    evidence.append(f"Assessment conclusion: {record.conclusion}")
    return Finding(
        title=f"SQL 绕过评估参数：{candidate.parameter}",
        severity=severity,
        location=candidate.source_location or candidate.page_url or target,
        evidence="\n".join(evidence),
        verified=False,
        recommendation=(
            "Treat bypass output as auxiliary assessment evidence only. Confirm SQL injection through sql_scan/poc_verify, "
            "then fix with parameterized queries and normalize WAF rules as defense-in-depth."
        ),
    )


def _mask_body(body: str) -> str:
    if not body:
        return ""
    import re

    masked = re.sub(r"(?i)(password|pass|pwd)=[^&]*", r"\1=[masked]", body)
    if masked == body and "=" in body:
        keys = [part.split("=", 1)[0] for part in body.split("&") if part]
        return "params=[redacted:" + ",".join(keys[:6]) + "]"
    return masked


def _redact_url(url: str, parameter: str) -> str:
    if not url:
        return ""
    from urllib.parse import parse_qs, urlparse

    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return url
    if parsed.query:
        query = parse_qs(parsed.query)
        if parameter in query:
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{parameter}=[redacted]"
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?params=[redacted]"
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
