from __future__ import annotations

import ipaddress
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from ai_security_agent.integrations.docker_sandbox import run_poc_in_docker
from ai_security_agent.schemas import Finding, ModuleResult

from .common import is_local_or_lab_target, now_iso, safe_fetch_text, target_scope_label
from .followup_bridge import extract_followup_inputs, extract_high_risk_findings, extract_sql_bypass_assessments


URL_RE = re.compile(r"https?://[^\s)\]>\"']+")
KV_LINE_RE = re.compile(r"^\s*-?\s*([^:\n]+):\s*(.*)$")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
LOCAL_EXP_ALLOWLIST = {"127.0.0.1", "localhost", "::1"}
PROJECT_ROOT = Path(__file__).resolve().parents[3]
POC_TEMPLATE_DIR = PROJECT_ROOT / "templates" / "poc_verify"
_POC_TEMPLATE_CACHE: dict[str, dict[str, object]] = {}


@dataclass(frozen=True, slots=True)
class CveTemplate:
    cve_id: str
    name: str
    category: str
    replay_mode: str
    safe_path: str = "/"
    method: str = "GET"
    marker: str = ""
    recommendation: str = ""


@dataclass(slots=True)
class PocReplay:
    vulnerability_type: str
    cve_id: str
    cve_template: str
    replay_mode: str
    url: str
    method: str
    parameter: str
    baseline_url: str
    confirmed_strategies: str
    reachability: str
    replay_result: str
    replay_basis: str
    backup_seed_url: str = ""
    backup_scope_summary: str = ""


CVE_TEMPLATES: dict[str, CveTemplate] = {
    "CVE-2021-41773": CveTemplate(
        cve_id="CVE-2021-41773",
        name="Apache HTTP Server path traversal / file disclosure check",
        category="path_traversal",
        replay_mode="safe-get",
        safe_path="/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/echo",
        marker="echo",
        recommendation="Upgrade Apache HTTP Server to a fixed version and disable unsafe path traversal handling.",
    ),
    "CVE-2021-42013": CveTemplate(
        cve_id="CVE-2021-42013",
        name="Apache HTTP Server path traversal / possible RCE check",
        category="path_traversal",
        replay_mode="manual-only",
        recommendation="Upgrade Apache HTTP Server to a fixed version; do not run RCE payloads automatically.",
    ),
    "CVE-2022-1388": CveTemplate(
        cve_id="CVE-2022-1388",
        name="F5 BIG-IP iControl REST auth bypass",
        category="auth_bypass",
        replay_mode="fingerprint",
        safe_path="/mgmt/tm/util/bash",
        recommendation="Restrict management interface access and apply vendor fixes for CVE-2022-1388.",
    ),
    "CVE-2022-22965": CveTemplate(
        cve_id="CVE-2022-22965",
        name="Spring4Shell",
        category="rce",
        replay_mode="manual-only",
        recommendation="Upgrade Spring Framework / Spring Boot and apply vendor hardening guidance.",
    ),
    "CVE-2017-5638": CveTemplate(
        cve_id="CVE-2017-5638",
        name="Apache Struts2 S2-045",
        category="rce",
        replay_mode="manual-only",
        recommendation="Upgrade Struts2 and block dangerous content-type OGNL evaluation.",
    ),
    "CVE-2023-3519": CveTemplate(
        cve_id="CVE-2023-3519",
        name="Citrix ADC/Gateway unauthenticated RCE",
        category="rce",
        replay_mode="manual-only",
        recommendation="Apply Citrix security updates and restrict management/service exposure.",
    ),
}


def run(target: str, context: dict | None = None) -> ModuleResult:
    started = now_iso()
    context = context or {}
    logs: list[str] = []
    followup_inputs = extract_followup_inputs("poc_verify", context)

    if not is_local_or_lab_target(target):
        return ModuleResult(
            module="poc_verify",
            target=target,
            status="skipped",
            findings=[],
            logs=["POC verification is restricted to local or course-lab targets."],
            started_at=started,
            finished_at=now_iso(),
            error="only localhost or course lab targets are allowed",
        )

    logs.append(f"Target scope: {target_scope_label(target)}")
    high_findings = [item for item in extract_high_risk_findings(context) if _severity_of(item) in {"critical", "high"}]
    sql_bypass_assessments = extract_sql_bypass_assessments(context)
    if not high_findings:
        if followup_inputs:
            followup_logs = ["No high-risk finding is available; generated backup-derived POC follow-up scope instead."]
            return ModuleResult(
                module="poc_verify",
                target=target,
                status="ok",
                findings=[_followup_scope_finding(target, followup_inputs)],
                logs=followup_logs + ["Generated POC follow-up scope from upstream followup_context."],
                started_at=started,
                finished_at=now_iso(),
            )
        logs.append("No high-risk finding is available; POC verification skipped.")
        return ModuleResult(
            module="poc_verify",
            target=target,
            status="skipped",
            findings=[],
            logs=logs,
            started_at=started,
            finished_at=now_iso(),
            error="POC verification requires at least one high-risk finding.",
        )

    logs.append(f"Building controlled POC verification records for {len(high_findings)} high-risk finding(s).")
    findings = [
        _verification_finding(target, item, index, followup_inputs, sql_bypass_assessments, context)
        for index, item in enumerate(high_findings, start=1)
    ]
    if followup_inputs:
        findings.append(_followup_scope_finding(target, followup_inputs))
        logs.append("Generated POC follow-up scope from upstream followup_context.")

    return ModuleResult(
        module="poc_verify",
        target=target,
        status="ok",
        findings=findings,
        logs=logs,
        started_at=started,
        finished_at=now_iso(),
    )


def _verification_finding(
    target: str,
    finding_data,
    index: int,
    followup_inputs: dict[str, object],
    sql_bypass_assessments: list[dict[str, object]] | None = None,
    context: dict | None = None,
) -> Finding:
    title = _field(finding_data, "title", "Untitled high-risk finding")
    severity = _field(finding_data, "severity", "high")
    location = _field(finding_data, "location", target)
    evidence = _field(finding_data, "evidence", "")
    recommendation = _field(finding_data, "recommendation", "")
    parsed_evidence = _parse_evidence_fields(evidence)
    replay = _build_replay(target, location, evidence, parsed_evidence, followup_inputs)
    sandbox_record = _run_sandbox_replay_if_enabled(replay, context)

    verification_record = "\n".join(
        [
            "POC verification record",
            f"Record ID: POC-{index:02d}",
            f"Original finding: {title}",
            f"Original severity: {severity}",
            f"Vulnerability type: {replay.vulnerability_type.upper()}",
            f"CVE ID: {replay.cve_id or 'not detected'}",
            f"CVE template: {replay.cve_template or 'not matched'}",
            f"Replay mode: {replay.replay_mode or 'standard'}",
            f"Original location: {location or target}",
            "",
            "Verification method:",
            f"- Use the {replay.vulnerability_type.upper()} controlled verification template.",
            "- Parse the original finding evidence for page, parameter, method, baseline URL, and confirmed strategies where available.",
            "- Re-check the referenced lab URL inside the authorized local/course environment.",
            "- Run only conservative local-lab replay checks when the vulnerability type supports safe replay.",
            "- Compare replay evidence with the original SQL finding evidence and final report.",
            "",
            "Reachability check:",
            f"- URL: {replay.url}",
            f"- Result: {replay.reachability}",
            "",
            "Backup-derived scope:",
            f"- Seed URL: {replay.backup_seed_url or 'not needed'}",
            f"- Scope hints: {replay.backup_scope_summary or 'none'}",
            "",
            "SQL bypass auxiliary assessment:",
            *_sql_bypass_assessment_lines(sql_bypass_assessments or [], replay.parameter, replay.url),
            "",
            "Controlled replay:",
            f"- Method: {replay.method}",
            f"- Parameter: {replay.parameter or 'not parsed'}",
            f"- Baseline URL: {replay.baseline_url or 'not parsed'}",
            f"- Confirmed strategies: {replay.confirmed_strategies or 'not parsed'}",
            f"- Replay result: {replay.replay_result}",
            f"- Replay basis: {replay.replay_basis}",
            (
                f"- Docker sandbox: rc={sandbox_record.get('returncode', 'n/a')}, "
                f"timed_out={sandbox_record.get('timed_out', False)}, "
                f"status={sandbox_record.get('parsed', {}).get('status', 'n/a')}"
                if sandbox_record
                else "- Docker sandbox: not run"
            ),
            "",
            "Manual reproduction steps:",
            *_manual_steps(replay),
            "",
            "Verification conclusion:",
            _conclusion_for(finding_data, replay),
            "",
            "Evidence carried forward:",
            _trim(evidence, 1200) or "No original evidence text was provided.",
            "",
            "Risk statement:",
            _risk_statement(replay.vulnerability_type),
            "",
            "Recommended next steps:",
            recommendation or _default_recommendation(replay.vulnerability_type),
        ]
    )

    verification_status = _verification_status_for_replay_result(replay.replay_result)
    return Finding(
        title=f"POC verification record: {_trim(title, 60)}",
        severity="high",
        location=location or target,
        evidence=verification_record,
        kind="verification_record",
        verification_status=verification_status,
        verified=verification_status == "confirmed",
        recommendation="Keep the screenshot trail: SQL pending approval, SQL approved result, and final report POC record.",
        metadata={
            "source_title": title,
            "source_location": location or target,
            "source_severity": severity,
            "source_module": str(_field(finding_data, "module", "unknown") or "unknown"),
            "replay_result": replay.replay_result,
            "replay_mode": replay.replay_mode or "standard",
            "vulnerability_type": replay.vulnerability_type,
            "reachability": replay.reachability,
            "source_was_verified": _verified_of(finding_data),
            "counts_as_confirmed_vulnerability": False,
            "sandbox_record": sandbox_record,
        },
    )


def _sql_bypass_assessment_lines(assessments: list[dict[str, object]], parameter: str, url: str) -> list[str]:
    if not assessments:
        return ["- No sql_bypass assessment context was provided."]
    matched: list[dict[str, object]] = []
    for item in assessments:
        candidate = item.get("candidate")
        if isinstance(candidate, dict):
            item_param = str(candidate.get("parameter", ""))
            item_url = str(candidate.get("page_url", "") or candidate.get("baseline_url", ""))
        else:
            item_param = str(item.get("parameter", ""))
            item_url = str(item.get("location", ""))
        if parameter and item_param == parameter:
            matched.append(item)
            continue
        if url and item_url and item_url.split("?", 1)[0] in url:
            matched.append(item)
    selected = matched or assessments[:3]
    lines = ["- Assessment is auxiliary only; it does not change the POC verification result by itself."]
    for item in selected[:3]:
        candidate = item.get("candidate") if isinstance(item.get("candidate"), dict) else {}
        waf_profile = item.get("waf_profile") if isinstance(item.get("waf_profile"), dict) else {}
        item_param = str(candidate.get("parameter", item.get("parameter", parameter)) if isinstance(candidate, dict) else item.get("parameter", parameter))
        waf_type = str(waf_profile.get("waf_type", item.get("waf_profile", "generic")) if isinstance(waf_profile, dict) else "generic")
        conclusion = str(item.get("assessment_conclusion", item.get("conclusion", ""))).strip()
        recommendations = item.get("tamper_recommendations", [])
        recommendation_label = _format_tamper_recommendations(recommendations)
        lines.append(
            f"- parameter={item_param or 'unknown'}, waf={waf_type or 'generic'}, "
            f"tamper={recommendation_label or 'none'}, conclusion={_trim(conclusion, 180) or 'not recorded'}"
        )
    return lines


def _format_tamper_recommendations(recommendations: object) -> str:
    if not isinstance(recommendations, list):
        return str(recommendations)
    labels: list[str] = []
    for value in recommendations[:5]:
        if isinstance(value, dict):
            name = str(value.get("name", "")).strip()
            source = str(value.get("source", "")).strip()
            reason = str(value.get("reason", "")).strip()
            label = name
            if source:
                label = f"{label}<{source}>"
            if reason:
                label = f"{label}:{reason}"
            labels.append(label)
            continue
        labels.append(str(value))
    return ", ".join(label for label in labels if label)


def _build_replay(
    target: str,
    location: str,
    evidence: str,
    parsed_evidence: dict[str, str],
    followup_inputs: dict[str, object],
) -> PocReplay:
    vulnerability_type = _detect_vulnerability_type(location, evidence)
    cve_id = _extract_cve_id(location, evidence)
    cve_template = CVE_TEMPLATES.get(cve_id.upper()) if cve_id else None
    if cve_template:
        vulnerability_type = "cve"
    page_url = parsed_evidence.get("Page", "")
    baseline_url = parsed_evidence.get("Baseline URL", "")
    backup_seed_url = _followup_seed_url(target, followup_inputs)
    candidate_url = page_url or _extract_url(location) or _extract_url(evidence) or backup_seed_url or target
    method = parsed_evidence.get("Method", "GET").upper()
    parameter = parsed_evidence.get("Parameter", "") or _guess_parameter(location, evidence, vulnerability_type)
    confirmed_strategies = parsed_evidence.get("Confirmed strategies", "")
    reachability = _safe_reachability(candidate_url)
    replay_result, replay_basis = _safe_replay_by_type(vulnerability_type, baseline_url or candidate_url, parameter, method, target, cve_template)
    return PocReplay(
        vulnerability_type=vulnerability_type,
        cve_id=cve_id.upper() if cve_id else "",
        cve_template=cve_template.name if cve_template else "",
        replay_mode=cve_template.replay_mode if cve_template else "",
        url=candidate_url,
        method=method,
        parameter=parameter,
        baseline_url=baseline_url,
        confirmed_strategies=confirmed_strategies,
        reachability=reachability,
        replay_result=replay_result,
        replay_basis=replay_basis,
        backup_seed_url=backup_seed_url,
        backup_scope_summary=_followup_scope_summary(followup_inputs),
    )


def _detect_vulnerability_type(location: str, evidence: str) -> str:
    text = f"{location}\n{evidence}".lower()
    if CVE_RE.search(text):
        return "cve"
    if "xxe" in text or "external entity" in text or "<!entity" in text:
        return "xxe"
    if "ssrf" in text or "server-side request" in text or "/ssrf/" in text:
        return "ssrf"
    if "csrf" in text or "cross-site request forgery" in text or "/csrf/" in text:
        return "csrf"
    if "xss" in text or "cross-site scripting" in text or "innerhtml" in text or "/xss/" in text:
        return "xss"
    if "sql" in text or "sqli" in text or "database" in text:
        return "sql"
    return "generic"


def _safe_replay_by_type(
    vulnerability_type: str,
    url: str,
    parameter: str,
    method: str,
    target: str,
    cve_template: CveTemplate | None = None,
) -> tuple[str, str]:
    if vulnerability_type == "cve":
        return _safe_cve_replay(url, target, cve_template)
    if vulnerability_type == "sql":
        return _safe_sql_replay(url, parameter, method)
    if vulnerability_type == "ssrf":
        return _safe_ssrf_replay(url, parameter, method, target)
    if vulnerability_type == "xss":
        return _safe_xss_replay(url, parameter, method)
    if vulnerability_type == "csrf":
        return _safe_csrf_review(url, method)
    if vulnerability_type == "xxe":
        return _safe_xxe_review(url, method)
    return "manual-only", "No type-specific replay template matched; preserve the finding as a manual POC record."


def _safe_reachability(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc or not is_local_or_lab_target(url):
        return "not fetched; no local/course-lab URL was available"
    response = safe_fetch_text(url, timeout_seconds=1.5, max_bytes=4096)
    if response.ok:
        return f"reachable, HTTP {response.status_code}, body_sample_bytes={len(response.text)}"
    return f"not reachable during short check: {response.error or response.status_code or 'no response'}"


def _safe_sql_replay(url: str, parameter: str, method: str) -> tuple[str, str]:
    if method != "GET":
        return "manual-only", "POST replay is recorded from the source finding; automated POC replay is intentionally limited to safe GET checks."
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc or not is_local_or_lab_target(url):
        return "not-run", "No local/course-lab GET URL was available for replay."
    if not parameter:
        return "not-run", "No parameter was parsed from the source finding evidence."

    baseline = safe_fetch_text(url, timeout_seconds=1.2, max_bytes=60_000)
    query = parse_qs(parsed.query)
    query[parameter] = ["1'"]
    quote_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
    quote = safe_fetch_text(quote_url, timeout_seconds=1.2, max_bytes=60_000)
    if not baseline.ok or not quote.ok:
        return "not-confirmed", f"Replay fetch issue: baseline={baseline.error or baseline.status_code}, quote={quote.error or quote.status_code}"
    delta = abs(len(baseline.text) - len(quote.text))
    error_hit = bool(re.search(r"mysql|sql syntax|database error|warning.*mysqli|pdoexception", quote.text or "", re.IGNORECASE))
    if error_hit or delta > 120:
        return "confirmed", f"quote replay status={quote.status_code}, baseline_len={len(baseline.text)}, quote_len={len(quote.text)}, delta={delta}, sql_error={error_hit}"
    return "not-confirmed", f"quote replay did not reproduce a strong signal: baseline_len={len(baseline.text)}, quote_len={len(quote.text)}, delta={delta}"


def _safe_cve_replay(url: str, target: str, template: CveTemplate | None) -> tuple[str, str]:
    if not template:
        return "manual-only", "CVE ID was detected but no local template is registered; preserve as manual-only record."
    if not _is_exp_allowed_target(url or target):
        return "blocked", "CVE replay blocked by exploit allowlist; only localhost is enabled by default."
    if template.replay_mode == "manual-only":
        return "manual-only", f"{template.cve_id} is classified as {template.category}; automated EXP replay is disabled by policy."
    if template.replay_mode == "active-exp" and not _active_exp_enabled():
        return "blocked", "active EXP execution requires POC_ALLOW_ACTIVE_EXP=1 and an allowlisted target."
    parsed = urlparse(url or target)
    if not parsed.scheme or not parsed.netloc:
        return "not-run", "No usable target URL was available for CVE replay."

    replay_url = urljoin(f"{parsed.scheme}://{parsed.netloc}", template.safe_path or "/")
    response = safe_fetch_text(replay_url, timeout_seconds=1.5, max_bytes=60_000)
    if not response.ok:
        return "not-confirmed", f"{template.cve_id} {template.replay_mode} check failed to fetch {replay_url}: {response.error or response.status_code}"
    marker_hit = bool(template.marker and template.marker.lower() in response.text.lower())
    if template.replay_mode == "fingerprint":
        return "needs-review", f"{template.cve_id} fingerprint endpoint reachable at {replay_url}; HTTP {response.status_code}, marker={marker_hit}"
    if marker_hit:
        return "confirmed", f"{template.cve_id} safe replay reached {replay_url} and matched marker {template.marker!r}"
    return "needs-review", f"{template.cve_id} safe replay reached {replay_url}; HTTP {response.status_code}, marker not found"


def _safe_ssrf_replay(url: str, parameter: str, method: str, target: str) -> tuple[str, str]:
    if method != "GET":
        return "manual-only", "SSRF POST replay is recorded as manual-only to avoid submitting complex forms automatically."
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc or not is_local_or_lab_target(url):
        return "not-run", "No local/course-lab GET URL was available for SSRF replay."
    if not parameter:
        return "not-run", "No SSRF URL parameter was parsed from the source finding evidence."
    lab_url = _lab_probe_url(target)
    baseline = safe_fetch_text(url, timeout_seconds=1.5, max_bytes=60_000)
    direct = safe_fetch_text(lab_url, timeout_seconds=1.5, max_bytes=60_000)
    query = parse_qs(parsed.query)
    query[parameter] = [lab_url]
    replay_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
    response = safe_fetch_text(replay_url, timeout_seconds=1.5, max_bytes=60_000)
    if not response.ok:
        return "not-confirmed", f"SSRF replay fetch issue: {response.error or response.status_code}"
    signal = _ssrf_replay_signal(baseline.text if baseline.ok else "", response.text, direct.text if direct.ok else "")
    if signal["confirmed"]:
        return (
            "confirmed",
            f"server fetched controlled local-lab URL {lab_url}; basis={signal['basis']}; "
            f"delta={signal['delta']}; overlap={signal['overlap']}",
        )
    return f"needs-review", f"server replayed controlled local-lab URL {lab_url}; response length={len(response.text)}; basis={signal['basis']}"


def _safe_xss_replay(url: str, parameter: str, method: str) -> tuple[str, str]:
    if method != "GET":
        return "manual-only", "XSS POST replay is recorded as manual-only; use browser screenshots for confirmation."
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc or not is_local_or_lab_target(url):
        return "not-run", "No local/course-lab GET URL was available for XSS replay."
    if not parameter:
        return "not-run", "No reflected parameter was parsed from the source finding evidence."
    marker = "poc_xss_marker_123"
    query = parse_qs(parsed.query)
    query[parameter] = [marker]
    replay_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
    response = safe_fetch_text(replay_url, timeout_seconds=1.2, max_bytes=60_000)
    if response.ok and marker in response.text:
        return "needs-browser-confirmation", "marker was reflected in the HTML response; confirm execution context manually in the browser."
    return "not-confirmed", f"marker reflection was not observed in short replay: {response.error or response.status_code or len(response.text)}"


def _safe_csrf_review(url: str, method: str) -> tuple[str, str]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc or not is_local_or_lab_target(url):
        return "not-run", "No local/course-lab URL was available for CSRF review."
    response = safe_fetch_text(url, timeout_seconds=1.2, max_bytes=60_000)
    if not response.ok:
        return "not-confirmed", f"CSRF page fetch issue: {response.error or response.status_code}"
    text = response.text or ""
    headers = response.headers or {}
    cookie_header = str(headers.get("set-cookie", ""))
    has_form = "<form" in text.lower()
    has_token = bool(re.search(r"csrf|token|nonce", text, re.IGNORECASE))
    has_samesite = "samesite" in cookie_header.lower()
    has_origin_or_referer = bool(re.search(r"origin|referer", text, re.IGNORECASE))
    if has_form and not has_token and not has_samesite and not has_origin_or_referer:
        return (
            "needs-manual-confirmation",
            "form was found without obvious csrf/token/nonce marker, SameSite cookie hint, or Origin/Referer validation clue; verify state-changing action manually.",
        )
    if has_form and (has_token or has_samesite or has_origin_or_referer):
        observed_controls: list[str] = []
        if has_token:
            observed_controls.append("token/nonce marker")
        if has_samesite:
            observed_controls.append("SameSite cookie attribute")
        if has_origin_or_referer:
            observed_controls.append("Origin/Referer-related hint")
        return "not-confirmed", "observed CSRF control hints: " + ", ".join(observed_controls)
    return "needs-review", f"no form marker found in fetched page; method={method}"


def _safe_xxe_review(url: str, method: str) -> tuple[str, str]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc or not is_local_or_lab_target(url):
        return "not-run", "No local/course-lab URL was available for XXE review."
    response = safe_fetch_text(url, timeout_seconds=1.2, max_bytes=60_000)
    if not response.ok:
        return "not-confirmed", f"XXE page fetch issue: {response.error or response.status_code}"
    text = response.text.lower()
    if "<textarea" in text or "xml" in text:
        return "manual-only", "XML input surface was found; use safe local-lab external entity payload manually and capture screenshots."
    return "manual-only", "XXE requires a controlled XML submission; automated file/entity payload replay is intentionally disabled."


def _run_sandbox_replay_if_enabled(replay: PocReplay, context: dict | None) -> dict[str, object]:
    profile_config = dict((context or {}).get("profile_config", {})) if isinstance((context or {}).get("profile_config", {}), dict) else {}
    sandbox = dict(profile_config.get("sandbox", {})) if isinstance(profile_config.get("sandbox", {}), dict) else {}
    if not sandbox.get("enabled"):
        return {}
    if replay.method.upper() != "GET":
        return {}
    if not replay.url or not is_local_or_lab_target(replay.url):
        return {}
    if replay.replay_mode in {"manual-only", "active-exp"}:
        return {}

    script = "\n".join(
        [
            "import json",
            "import requests",
            f"url = {replay.url!r}",
            "resp = requests.get(url, timeout=6, allow_redirects=True)",
            "print(json.dumps({",
            "  'status': resp.status_code,",
            "  'url': resp.url,",
            "  'length': len(resp.text),",
            "  'body_length': len(resp.text),",
            "  'title_present': ('<title' in resp.text.lower()),",
            "}, ensure_ascii=False))",
        ]
    )
    with tempfile.TemporaryDirectory(prefix='poc_sandbox_') as tmp_dir:
        script_path = Path(tmp_dir) / "poc.py"
        artifacts_dir = Path(tmp_dir) / "artifacts"
        script_path.write_text(script, encoding="utf-8")
        result = run_poc_in_docker(
            docker_binary="docker",
            image=str(sandbox.get("image", "python:3.12-slim")),
            script_path=script_path,
            artifacts_dir=artifacts_dir,
            timeout_seconds=float(sandbox.get("timeout_seconds", 20.0) or 20.0),
            network_mode=str(sandbox.get("network_mode", "bridge") or "bridge"),
            cpu_limit=str(sandbox.get("cpu_limit", "1.0") or "1.0"),
            mem_limit=str(sandbox.get("mem_limit", "512m") or "512m"),
        )
        return {
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "parsed": dict(result.parsed or {}),
            "stdout": (result.stdout or "")[:1200],
            "stderr": (result.stderr or "")[:800],
        }


def _conclusion_for(finding_data, replay: PocReplay) -> str:
    if _verified_of(finding_data) and replay.replay_result == "confirmed":
        return f"Confirmed for reporting: the source finding was verified and the controlled replay reproduced a {replay.vulnerability_type.upper()} signal."
    if replay.replay_result == "confirmed":
        return f"Controlled replay reproduced a {replay.vulnerability_type.upper()} signal, but this verification record still requires analyst correlation with the source finding."
    if replay.reachability.startswith("reachable"):
        return "Needs human confirmation: the target URL was reachable, but the original finding was not marked verified."
    return "Needs manual follow-up: preserve this record as a controlled verification checklist item."


def _verification_status_for_replay_result(replay_result: str) -> str:
    mapping = {
        "confirmed": "confirmed",
        "manual-only": "manual_required",
        "needs-review": "manual_required",
        "needs-manual-confirmation": "manual_required",
        "needs-browser-confirmation": "manual_required",
        "blocked": "manual_required",
        "not-run": "not_run",
        "not-confirmed": "unconfirmed",
    }
    return mapping.get(replay_result, "manual_required")


def _manual_steps(replay: PocReplay) -> list[str]:
    if replay.vulnerability_type == "cve":
        cve_env = _cve_active_exploit_env()
        return [
            f"1. Confirm the CVE ID and affected component: {replay.cve_id or 'see source finding'}",
            f"2. Confirm the target is in the exploit allowlist before any replay: {replay.url}",
            f"3. Use the registered template only: {replay.cve_template or 'manual template required'}",
            "4. Prefer version, banner, metadata, or harmless marker checks over exploit execution.",
            "5. Keep RCE, file-write, command-execution, auth-bypass, and destructive CVEs in manual-only mode unless the local template explicitly allows a safe check.",
            f"6. Respect replay mode: {replay.replay_mode or 'manual-only'}; active EXP requires explicit approval and {cve_env}=1.",
            "7. Capture version/banner evidence, safe replay output, and vendor patch guidance.",
            "8. Do not run data-dump, shell, file-read, or destructive payloads as part of automated POC.",
        ]
    if replay.vulnerability_type == "ssrf":
        return [
            f"1. Open the affected page: {replay.url}",
            f"2. Locate the URL-like parameter: {replay.parameter or 'see original finding evidence'}",
            "3. Submit a controlled local-lab URL such as http://127.0.0.1/.",
            "4. Confirm whether the response contains content from the fetched lab URL.",
            "5. Save screenshots of the baseline request, controlled URL request, and response evidence.",
        ]
    if replay.vulnerability_type == "xxe":
        return [
            f"1. Open the affected page: {replay.url}",
            "2. Locate the XML input field or request body.",
            "3. Submit only a safe local-lab external entity reference, not a file-read payload.",
            "4. Confirm whether the response includes content fetched from the local lab URL.",
            "5. Save screenshots of the XML payload, response, and final POC record.",
        ]
    if replay.vulnerability_type == "xss":
        return [
            f"1. Open the affected page: {replay.url}",
            f"2. Locate the reflected/stored input parameter: {replay.parameter or 'see original finding evidence'}",
            "3. Submit a harmless marker first, then a safe alert-style payload only in the local lab.",
            "4. Confirm whether the marker is reflected and whether browser execution occurs.",
            "5. Save screenshots of reflection/execution and note the DOM or response context.",
        ]
    if replay.vulnerability_type == "csrf":
        return [
            f"1. Open the affected page: {replay.url}",
            "2. Identify the state-changing form or request.",
            "3. Check whether a CSRF token, SameSite cookie policy, Origin check, or Referer check is present.",
            "4. Do not automatically execute destructive requests.",
            "5. Mark POST replay as manual-only unless the request is explicitly safe in the local lab target.",
            "6. Re-submit from a controlled test page only in the lab if manual approval allows.",
            "7. Save screenshots of the form, token/header evidence, and state-change result.",
        ]
    return [
        f"1. Open the affected page: {replay.url}",
        f"2. Locate the parameter: {replay.parameter or 'see original finding evidence'}",
        "3. Submit the baseline request and capture the normal response.",
        "4. Submit a single-quote or recorded confirmed-strategy probe in the authorized lab.",
        "5. Capture the response difference, SQL error marker, or strategy-specific evidence.",
        "6. Save screenshots for pending approval, approved SQL result, POC record, and final report.",
    ]


def _field(finding_data, name: str, default: str = "") -> str:
    if hasattr(finding_data, name):
        return str(getattr(finding_data, name) or default)
    if isinstance(finding_data, dict):
        return str(finding_data.get(name) or default)
    return default


def _severity_of(finding_data) -> str:
    return _field(finding_data, "severity", "info").lower()


def _verified_of(finding_data) -> bool:
    if hasattr(finding_data, "verified"):
        return bool(getattr(finding_data, "verified"))
    if isinstance(finding_data, dict):
        return bool(finding_data.get("verified", False))
    return False


def _extract_url(text: str) -> str:
    match = URL_RE.search(text or "")
    return match.group(0) if match else ""


def _extract_cve_id(location: str, evidence: str) -> str:
    match = CVE_RE.search(f"{location}\n{evidence}")
    return match.group(0) if match else ""


def _guess_parameter(location: str, evidence: str, vulnerability_type: str) -> str:
    text = f"{location}\n{evidence}"
    explicit = re.search(r"(?im)^\s*-?\s*Parameter:\s*([A-Za-z0-9_:-]+)", text)
    if explicit:
        return explicit.group(1)
    url = _extract_url(text)
    query = parse_qs(urlparse(url).query) if url else {}
    preferred = {
        "ssrf": ("url", "uri", "path", "file", "target", "link"),
        "xss": ("message", "name", "keyword", "search", "q", "text", "content"),
        "csrf": ("id", "uid", "action", "submit"),
        "xxe": ("xml", "data", "payload"),
        "sql": ("id", "name", "uid", "keyword", "search", "q"),
    }.get(vulnerability_type, ())
    for name in preferred:
        if name in query:
            return name
    return next(iter(query), "")


def _lab_probe_url(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        return urlunparse(parsed._replace(path="/", query="", fragment=""))
    return "http://127.0.0.1/"


def _ssrf_replay_signal(baseline_text: str, replay_text: str, direct_text: str) -> dict[str, object]:
    delta = len(replay_text or "") - len(baseline_text or "")
    overlap = _text_token_overlap(direct_text, replay_text)
    baseline_overlap = _text_token_overlap(direct_text, baseline_text)
    title = _html_title(direct_text)
    title_signal = bool(title and title.lower() in (replay_text or "").lower() and title.lower() not in (baseline_text or "").lower())
    html_signal = bool(re.search(r"(?is)<html\b|<body\b|<!doctype\s+html", replay_text or "") and delta > 800 and baseline_overlap < 0.08)
    overlap_signal = bool(overlap >= 0.18 and overlap > baseline_overlap + 0.06 and delta > 200)
    basis = []
    if title_signal:
        basis.append("direct_title_reflected")
    if html_signal:
        basis.append("loopback_response_delta")
    if overlap_signal:
        basis.append("direct_content_overlap")
    return {
        "confirmed": bool(title_signal or html_signal or overlap_signal),
        "basis": ",".join(basis) or "none",
        "delta": delta,
        "overlap": round(overlap, 3),
        "baseline_overlap": round(baseline_overlap, 3),
    }


def _html_title(text: str) -> str:
    match = re.search(r"(?is)<title\b[^>]*>(.*?)</title>", text or "")
    if not match:
        return ""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", match.group(1))).strip()[:80]


def _text_token_overlap(left: str, right: str) -> float:
    left_tokens = _content_tokens(left)
    right_tokens = _content_tokens(right)
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / max(len(left_tokens), 1)


def _content_tokens(text: str) -> set[str]:
    stripped = re.sub(r"(?is)<script\b.*?</script>|<style\b.*?</style>", " ", text or "")
    stripped = re.sub(r"(?is)<[^>]+>", " ", stripped)
    return {
        token.lower()
        for token in re.findall(r"[A-Za-z0-9_\-\u4e00-\u9fff]{3,}", stripped)
        if token.lower() not in {"html", "body", "script", "style", "div", "span", "class"}
    }


def _followup_seed_url(target: str, followup_inputs: dict[str, object]) -> str:
    seed_keys = (
        "auth_paths",
        "internal_urls",
        "framework_routes",
        "route_prefixes",
        "config_entrypoints",
        "download_export_paths",
        "upload_import_paths",
        "correlated_discovery_seeds",
        "relationship_followup_seeds",
    )
    for key in seed_keys:
        values = followup_inputs.get(key, [])
        if not isinstance(values, list):
            continue
        for raw_value in values[:12]:
            path = _normalize_followup_seed(raw_value)
            if not path:
                continue
            candidate = urljoin(target, path)
            if is_local_or_lab_target(candidate):
                return candidate
    return ""


def _followup_scope_summary(followup_inputs: dict[str, object]) -> str:
    parts: list[str] = []
    for key in ("auth_paths", "internal_urls", "manual_followup_archives", "weak_password_archives", "tooling_gap_archives"):
        values = followup_inputs.get(key, [])
        if not isinstance(values, list) or not values:
            continue
        label = ",".join(str(value) for value in values[:3])
        parts.append(f"{key}={label}")
    return "; ".join(parts[:4])


def _normalize_followup_seed(raw_value: object) -> str:
    text = str(raw_value or "").strip()
    if not text:
        return ""
    route_match = re.search(r"(?i)\b(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(\S+)", text)
    if route_match:
        text = route_match.group(1)
    if "->" in text:
        text = text.split("->", 1)[0].strip()
    text = re.sub(r"\{[^}]+\}", "1", text)
    text = re.sub(r":[A-Za-z_][A-Za-z0-9_]*", "1", text)
    if text.startswith(("http://", "https://")):
        return text
    return text if text.startswith("/") else f"/{text.lstrip('/')}"


def _risk_statement(vulnerability_type: str) -> str:
    statements = {
        "sql": "The finding may allow database-backed behavior to be influenced through user-controlled input in the lab target.",
        "xss": "The finding may allow attacker-controlled script or markup to execute in a user's browser context.",
        "csrf": "The finding may allow unintended state-changing requests to be triggered without a valid user intent check.",
        "ssrf": "The finding may allow the server to fetch attacker-controlled URLs, including internal or local-lab resources.",
        "xxe": "The finding may allow XML parsers to resolve external entities, which can expose server-side resources or trigger outbound requests.",
        "cve": "The finding maps to a known CVE and may require version-specific or product-specific validation in an authorized lab.",
    }
    return statements.get(vulnerability_type, "The finding may expose a security-relevant behavior that requires controlled manual validation.")


def _default_recommendation(vulnerability_type: str) -> str:
    recommendations = {
        "sql": "Use prepared statements, strict input validation, and generic database error handling.",
        "xss": "Encode output by context, sanitize rich text, use CSP, and avoid unsafe DOM sinks.",
        "csrf": _template_recommendation(
            "csrf",
            "Require per-request CSRF tokens, SameSite cookies, and server-side intent validation for state-changing actions.",
        ),
        "ssrf": "Allowlist URL schemes and hosts, block localhost/internal ranges, disable redirects where possible, and isolate outbound fetchers.",
        "xxe": "Disable external entity resolution and DTD processing in XML parsers; prefer safe parser defaults.",
        "cve": _template_recommendation(
            "cve_template",
            "Apply vendor patches, follow the CVE-specific mitigation guidance, and restrict exposure of affected services.",
        ),
    }
    return recommendations.get(vulnerability_type, "Validate inputs, constrain risky behavior, and preserve clear audit evidence.")


def _parse_evidence_fields(evidence: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in (evidence or "").splitlines():
        match = KV_LINE_RE.match(line)
        if not match:
            continue
        key = match.group(1).strip().lstrip("-").strip()
        value = match.group(2).strip()
        if key in {"Page", "Parameter", "Method", "Baseline URL", "Confirmed strategies"} and value:
            parsed[key] = value
    return parsed


def _trim(text: str, limit: int) -> str:
    compact = re.sub(r"\s+", " ", text or "").strip()
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def _is_exp_allowed_target(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host in LOCAL_EXP_ALLOWLIST:
        return True
    for allowed in _configured_exp_allowlist():
        if _host_matches_allow_entry(host, allowed):
            return True
    return False


def _configured_exp_allowlist() -> set[str]:
    raw = os.environ.get("POC_EXP_ALLOWLIST", "")
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def _host_matches_allow_entry(host: str, entry: str) -> bool:
    if not host or not entry:
        return False
    if host == entry:
        return True
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False


def _active_exp_enabled() -> bool:
    return os.environ.get(_cve_active_exploit_env(), "").strip().lower() in {"1", "true", "yes", "on"}


def _template_recommendation(template_name: str, fallback: str) -> str:
    template = _load_poc_template_yaml(template_name)
    recommendation = str(template.get("recommendation", "")).strip()
    return recommendation or fallback


def _cve_active_exploit_env() -> str:
    template = _load_poc_template_yaml("cve_template")
    policy = template.get("policy", {})
    if isinstance(policy, dict):
        value = str(policy.get("active_exploit_env", "")).strip()
        if value:
            return value
    return "POC_ALLOW_ACTIVE_EXP"


def _load_poc_template_yaml(template_name: str) -> dict[str, object]:
    cached = _POC_TEMPLATE_CACHE.get(template_name)
    if cached is not None:
        return cached
    path = POC_TEMPLATE_DIR / f"{template_name}.yaml"
    if not path.exists():
        _POC_TEMPLATE_CACHE[template_name] = {}
        return {}

    data: dict[str, object] = {}
    current_key: str | None = None
    current_nested_key: str | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if stripped.startswith("- "):
            item = _strip_yaml_quotes(stripped[2:].strip())
            if current_key is None:
                continue
            if current_nested_key is not None:
                parent = data.setdefault(current_key, {})
                if isinstance(parent, dict):
                    value = parent.setdefault(current_nested_key, [])
                    if isinstance(value, list):
                        value.append(item)
                continue
            existing = data.get(current_key)
            if existing == {}:
                data[current_key] = []
                existing = data[current_key]
            if isinstance(existing, list):
                existing.append(item)
            continue

        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()
        if indent == 0:
            current_key = key if not value else None
            current_nested_key = None
            data[key] = _strip_yaml_quotes(value) if value else {}
            continue
        if current_key is None:
            continue
        parent = data.setdefault(current_key, {})
        if not isinstance(parent, dict):
            continue
        if value:
            parent[key] = _strip_yaml_quotes(value)
            current_nested_key = None
        else:
            parent[key] = []
            current_nested_key = key

    _POC_TEMPLATE_CACHE[template_name] = data
    return data


def _strip_yaml_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _followup_scope_finding(target: str, followup_inputs: dict[str, object]) -> Finding:
    archive_checklist = _build_archive_followup_checklist(followup_inputs)
    return Finding(
        title="Backup-derived controlled POC follow-up scope",
        severity="info",
        location=target,
        evidence=_join_evidence(
            "This follow-up module was seeded from upstream backup_audit_extended verification hints.",
            _format_values("manual_followup_archives", followup_inputs.get("manual_followup_archives", [])),
            _format_values("weak_password_archives", followup_inputs.get("weak_password_archives", [])),
            _format_values("tooling_gap_archives", followup_inputs.get("tooling_gap_archives", [])),
            _format_values("strategy_unsupported_archives", followup_inputs.get("strategy_unsupported_archives", [])),
            _format_values("password_exhausted_archives", followup_inputs.get("password_exhausted_archives", [])),
            _format_values("auth_paths", followup_inputs.get("auth_paths", [])),
            _format_values("framework_routes", followup_inputs.get("framework_routes", [])),
            _format_values("route_prefixes", followup_inputs.get("route_prefixes", [])),
            _format_values("controller_hints", followup_inputs.get("controller_hints", [])),
            _format_values("config_entrypoints", followup_inputs.get("config_entrypoints", [])),
            _format_values("download_export_paths", followup_inputs.get("download_export_paths", [])),
            _format_values("upload_import_paths", followup_inputs.get("upload_import_paths", [])),
            _format_values("artifact_name_hints", followup_inputs.get("artifact_name_hints", [])),
            _format_values("middleware_hints", followup_inputs.get("middleware_hints", [])),
            _format_values("internal_urls", followup_inputs.get("internal_urls", [])),
            _format_values("db_hosts", followup_inputs.get("db_hosts", [])),
            _format_values("frameworks", followup_inputs.get("frameworks", [])),
            _format_values("correlated_discovery_seeds", followup_inputs.get("correlated_discovery_seeds", [])),
            _format_values("relationship_followup_seeds", followup_inputs.get("relationship_followup_seeds", [])),
            _format_values("archive_checklist", archive_checklist),
            _format_values("archive_action_queue", followup_inputs.get("archive_action_queue", [])),
            _format_values("archive_retry_queue", followup_inputs.get("archive_retry_queue", [])),
            _format_values("archive_manual_review_queue", followup_inputs.get("archive_manual_review_queue", [])),
            _format_values("archive_actionable_retry_queue", followup_inputs.get("archive_actionable_retry_queue", [])),
            _format_values("archive_deferred_retry_queue", followup_inputs.get("archive_deferred_retry_queue", [])),
            _format_values("archive_policy_blocked_queue", followup_inputs.get("archive_policy_blocked_queue", [])),
            _format_values("archive_retry_items", _format_archive_queue_items(followup_inputs.get("archive_retry_items", []))),
            _format_values(
                "archive_manual_review_items",
                _format_archive_queue_items(followup_inputs.get("archive_manual_review_items", [])),
            ),
        ),
        kind="scope",
        verification_status="informational",
        verified=False,
        recommendation="Use archive outcomes and leaked internal/auth hints to scope later controlled verification work.",
    )


def _build_archive_followup_checklist(followup_inputs: dict[str, object]) -> list[str]:
    checklist: list[str] = []
    if followup_inputs.get("weak_password_archives"):
        checklist.append("rotate_and_review_weak_password_archives")
    if followup_inputs.get("tooling_gap_archives"):
        checklist.append("validate_optional_unpacker_support_before_retry")
    if followup_inputs.get("strategy_unsupported_archives"):
        checklist.append("respect_format_boundary_and_require_manual_review")
    if followup_inputs.get("password_exhausted_archives"):
        checklist.append("record_candidate_exhaustion_and_escalate_manually_if_authorized")
    archive_retry_items = followup_inputs.get("archive_retry_items", [])
    if isinstance(archive_retry_items, list) and any(
        isinstance(item, dict) and item.get("retry_requires_new_input") for item in archive_retry_items
    ):
        checklist.append("retry_only_after_authorized_password_recovery")
    if followup_inputs.get("manual_followup_archives"):
        checklist.append("keep_manual_followup_queue_for_remaining_archives")
    return checklist


def _format_values(label: str, values: object) -> str:
    if not isinstance(values, list) or not values:
        return ""
    return f"{label}={', '.join(str(value) for value in values[:6])}"


def _join_evidence(*parts: str) -> str:
    return "; ".join(part for part in parts if part)


def _format_archive_queue_items(items: object) -> list[str]:
    if not isinstance(items, list):
        return []
    labels: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        archive = str(item.get("archive", "")).strip()
        retry_class = str(item.get("retry_class", "")).strip()
        retry_readiness = str(item.get("retry_readiness", "")).strip()
        prerequisites = item.get("retry_prerequisites", [])
        prerequisite_label = ""
        if isinstance(prerequisites, list) and prerequisites:
            prerequisite_label = f":{'|'.join(str(value).strip() for value in prerequisites if str(value).strip())}"
        if archive and retry_class and retry_readiness:
            labels.append(f"{archive}:{retry_class}:{retry_readiness}{prerequisite_label}")
        elif archive and retry_class:
            labels.append(f"{archive}:{retry_class}")
        elif archive:
            labels.append(archive)
    return labels
