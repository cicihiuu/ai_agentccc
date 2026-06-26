from __future__ import annotations

import re
from dataclasses import dataclass, field
from hashlib import sha1
from html import unescape
from urllib.parse import parse_qs, quote_plus, urlencode, urljoin, urlparse, urlunparse

import requests

from ai_security_agent.integrations.http import fetch_text as http_fetch_text
from ai_security_agent.schemas import Finding, ModuleResult

from .common import (
    FetchResult,
    compress_text,
    get_report_contract,
    get_skill_bundle,
    get_support_skills,
    is_local_or_lab_target,
    now_iso,
    safe_fetch_text,
    target_scope_label,
)
from .followup_bridge import extract_followup_inputs


FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
INPUT_TAG_RE = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
TEXTAREA_TAG_RE = re.compile(r"<textarea\b([^>]*)>", re.IGNORECASE)
ACTION_RE = re.compile(r"\baction\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
METHOD_RE = re.compile(r"\bmethod\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
LINK_RE = re.compile(r"<a\b[^>]*href\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
ATTR_RE = re.compile(r"\b(?P<name>[a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(['\"])(?P<value>.*?)\2", re.IGNORECASE | re.DOTALL)
SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
DANGEROUS_SINK_RE = re.compile(
    r"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval|new Function|dangerouslySetInnerHTML|v-html)\b",
    re.IGNORECASE,
)
CLIENT_SOURCE_RE = re.compile(
    r"\b(window\.location(?:\.search|\.hash|\.href)?|location\.(?:hash|search|href)|document\.(?:URL|documentURI|referrer)|window\.name|event\.data|localStorage|getItem|sessionStorage|getItem|getElementById\([^)]*\)\.value)\b",
    re.IGNORECASE,
)

SKIP_URL_SUFFIXES = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
)
LOW_VALUE_PARAMS = {"csrf", "token", "user_token", "submit", "button", "viewport", "callback", "_", "seclev_submit", "help_button", "source_button", "phpids"}
INTERESTING_PARAM_NAMES = {
    "message",
    "text",
    "content",
    "comment",
    "name",
    "keyword",
    "search",
    "q",
    "title",
    "url",
    "href",
    "callback",
}


@dataclass(slots=True)
class XSSCandidate:
    page_url: str
    parameter: str
    method: str
    source: str
    reason: str
    extra_params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    baseline_body: str = ""
    sink: str = ""
    source_signal: str = ""
    context_hint: str = ""


@dataclass(frozen=True, slots=True)
class XSSPayload:
    strategy: str
    value: str
    expected_context: str


PAYLOADS = [
    XSSPayload("html_body", "<svg/onload=alert(1)>XSS_MARKER", "html_body"),
    XSSPayload("attribute_breakout", "'><svg/onload=alert(1)>XSS_MARKER", "attribute"),
    XSSPayload("double_quote_attribute_breakout", "\"><svg/onload=alert(1)>XSS_MARKER", "attribute"),
    XSSPayload("javascript_href", "javascript:alert(1)//XSS_MARKER", "href"),
    XSSPayload("js_string_breakout", "';alert(1);//XSS_MARKER", "script"),
    XSSPayload("dom_href_breakout", "' onclick='alert(1)' XSS_MARKER", "dom_attribute"),
]
COMMON_LAB_CREDENTIALS = (
    ("admin", "123456"),
    ("admin", "admin"),
    ("admin", "password"),
    ("test", "test"),
    ("user", "password"),
)


def run(target: str, context: dict | None = None) -> ModuleResult:
    started = now_iso()
    logs: list[str] = []
    if not is_local_or_lab_target(target):
        return ModuleResult(
            module="xss_triage",
            target=target,
            status="skipped",
            findings=[],
            logs=["Target is outside the local/course-lab allowlist; XSS triage skipped."],
            started_at=started,
            finished_at=now_iso(),
            error="only localhost or course lab targets are allowed",
        )

    skill_bundle = get_skill_bundle(context)
    support_skills = get_support_skills(context)
    report_contract = get_report_contract(context)
    followup_inputs = extract_followup_inputs("xss_triage", context)
    request_headers = _request_headers_from_followup(followup_inputs, context)
    page = safe_fetch_text(target, timeout_seconds=2.0, max_bytes=180_000, headers=request_headers or None)
    logs.append(f"Analyzed target entrypoint: {target}")
    logs.append(f"Target scope: {target_scope_label(target)}")
    if request_headers:
        logs.append("Using upstream authenticated request context.")
    logs.append(f"Entrypoint fetch: HTTP {page.status_code}" if page.ok else f"Entrypoint fetch unavailable: {page.error or 'no response'}")

    seed_urls = _followup_seed_urls(target, followup_inputs)
    crawled_pages = _crawl_same_origin_pages(target, page, extra_seeds=seed_urls, request_headers=request_headers)
    logs.append(f"Crawled same-origin pages for XSS: {len(crawled_pages)}")

    candidates: list[XSSCandidate] = []
    auxiliary_pages: list[dict[str, str]] = []
    for page_url, crawled, request_headers in crawled_pages:
        text = str(getattr(crawled, "text", ""))
        candidates.extend(_discover_candidates(page_url, text, request_headers=request_headers))
        auxiliary_pages.extend(_classify_auxiliary_pages_generic(page_url, text))
    candidates = _prioritize_candidates(_dedupe_candidates(candidates))
    logs.append(f"Candidate XSS inputs: {len(candidates)}")

    probes = [_probe_candidate(candidate) for candidate in candidates[:40]]
    confirmed = [probe for probe in probes if probe.get("confirmed")]
    findings: list[Finding] = [_inventory_finding(target, candidates, probes, auxiliary_pages)]
    findings.extend(_confirmed_finding(target, probe, probes, page) for probe in confirmed[:12])
    findings.extend(_auxiliary_finding(target, item) for item in auxiliary_pages[:6])

    if followup_inputs:
        findings.append(_followup_scope_finding(target, followup_inputs))
        logs.append("Generated XSS follow-up scope from upstream followup_context.")
    if not confirmed:
        findings.append(_candidate_finding(target, candidates, probes, page))

    if skill_bundle:
        logs.append(f"Skill guidance loaded: {skill_bundle.get('name', 'xss-triage')}")
    if support_skills:
        logs.append("Support skills: " + ", ".join(item.get("name", "support") for item in support_skills))
    if report_contract:
        logs.append("Report contract section: " + ", ".join(str(item) for item in report_contract.get("sections", [])))

    return ModuleResult(
        module="xss_triage",
        target=target,
        status="ok",
        findings=findings[:18],
        logs=logs or ["XSS triage completed."],
        followup_context=_build_xss_followup_context(findings, candidates, probes, auxiliary_pages),
        started_at=started,
        finished_at=now_iso(),
    )


def _discover_candidates(page_url: str, html: str, *, request_headers: dict[str, str] | None = None) -> list[XSSCandidate]:
    candidates: list[XSSCandidate] = []
    candidate_headers = dict(request_headers or {})
    parsed = urlparse(page_url)
    for name in parse_qs(parsed.query, keep_blank_values=True):
        if _is_low_value_param(name):
            continue
        candidates.append(
            XSSCandidate(
                page_url=page_url,
                parameter=name,
                method="GET",
                source="query",
                reason="Parameter is present in the page URL query string.",
                headers=candidate_headers,
            )
        )

    for attrs, body in FORM_RE.findall(html or ""):
        action_match = ACTION_RE.search(attrs)
        method_match = METHOD_RE.search(attrs)
        method = method_match.group(1).upper() if method_match else "GET"
        if action_match:
            action_url = urljoin(page_url, action_match.group(1))
        else:
            action_url = urlunparse(urlparse(page_url)._replace(query="", fragment=""))
        fields, extras = _extract_form_fields(body)
        if _is_auth_form(action_url, fields):
            continue
        for name in fields:
            if _is_low_value_param(name):
                continue
            candidates.append(
                XSSCandidate(
                    page_url=action_url,
                    parameter=name,
                    method=method,
                    source=f"form:{method}",
                    reason="Form field can carry browser-rendered user input.",
                    extra_params=dict(extras),
                    headers=candidate_headers,
                    baseline_body=urlencode({**extras, name: "1"}),
                )
            )

    for href in LINK_RE.findall(html or ""):
        href_url = urljoin(page_url, href)
        if not _is_crawlable_same_origin(href_url, _origin(page_url)):
            continue
        for name in parse_qs(urlparse(href_url).query, keep_blank_values=True):
            if _is_low_value_param(name):
                continue
            candidates.append(
                XSSCandidate(
                    page_url=href_url,
                    parameter=name,
                    method="GET",
                    source="linked-query",
                    reason="Linked URL contains a parameter that can be reflected or rendered.",
                    headers=candidate_headers,
                )
            )

    source_sink = _source_sink_context(html)
    if source_sink:
        names = _input_names(html) or ["text", "message"]
        for name in names:
            if _is_low_value_param(name):
                continue
            candidates.append(
                XSSCandidate(
                    page_url=page_url,
                    parameter=name,
                    method="GET",
                    source="dom-source-sink",
                    reason="Page script connects a browser-controlled source or input to a dangerous sink.",
                    headers=candidate_headers,
                    sink=source_sink.get("sink", ""),
                    source_signal=source_sink.get("source", ""),
                    context_hint=source_sink.get("snippet", ""),
                )
            )
    return candidates


def _crawl_same_origin_pages(
    target: str,
    first_page: FetchResult,
    *,
    extra_seeds: list[str] | None = None,
    request_headers: dict[str, str] | None = None,
    max_pages: int = 80,
    max_depth: int = 3,
) -> list[tuple[str, FetchResult, dict[str, str]]]:
    origin = _origin(target)
    visited: set[str] = set()
    results: list[tuple[str, FetchResult, dict[str, str]]] = []
    base_headers = dict(request_headers or {})
    queue: list[tuple[str, int, FetchResult | None, dict[str, str]]] = [(target, 0, first_page, base_headers)]
    for seed in extra_seeds or []:
        queue.append((seed, 1, None, dict(base_headers)))

    while queue and len(results) < max_pages:
        url, depth, prefetched, request_headers = queue.pop(0)
        normalized = _normalize_url(url)
        if normalized in visited or not _is_crawlable_same_origin(normalized, origin):
            continue
        visited.add(normalized)
        fetch = prefetched or _fetch_crawl_page(normalized, request_headers)
        results.append((normalized, fetch, dict(request_headers)))
        for auth_url, auth_fetch, auth_headers in _attempt_auth_bootstrap(normalized, fetch.text if fetch.ok else ""):
            auth_normalized = _normalize_url(auth_url)
            if auth_normalized not in visited and _is_crawlable_same_origin(auth_normalized, origin):
                queue.append((auth_normalized, depth + 1, auth_fetch, auth_headers))
        if depth >= max_depth or not fetch.ok or not fetch.text:
            continue
        for href in LINK_RE.findall(fetch.text):
            absolute = _normalize_url(urljoin(normalized, href))
            if absolute not in visited and _is_crawlable_same_origin(absolute, origin):
                queue.append((absolute, depth + 1, None, dict(request_headers)))
    return results


def _fetch_crawl_page(url: str, request_headers: dict[str, str]) -> FetchResult:
    if not request_headers:
        return safe_fetch_text(url, timeout_seconds=1.0, max_bytes=180_000)
    exchange = http_fetch_text(url, headers=request_headers, timeout_seconds=1.0, max_bytes=180_000)
    return FetchResult(
        url=exchange.url,
        status_code=exchange.status_code,
        headers=exchange.headers,
        text=exchange.text,
        error=exchange.error,
        elapsed_ms=exchange.elapsed_ms,
    )


def _attempt_auth_bootstrap(page_url: str, html: str) -> list[tuple[str, FetchResult, dict[str, str]]]:
    if not html:
        return []
    bootstrapped: list[tuple[str, FetchResult, dict[str, str]]] = []
    for attrs, body in FORM_RE.findall(html or ""):
        fields, extras = _extract_form_fields(body)
        field_set = {item.lower() for item in fields}
        if "username" not in field_set or "password" not in field_set:
            continue
        action_match = ACTION_RE.search(attrs)
        method_match = METHOD_RE.search(attrs)
        method = method_match.group(1).upper() if method_match else "GET"
        if method != "POST":
            continue
        action_url = urljoin(page_url, action_match.group(1) if action_match else page_url)
        for username, password in COMMON_LAB_CREDENTIALS:
            response, cookie_header = _submit_login_form(action_url, fields, extras, username=username, password=password)
            if not response.ok or not cookie_header:
                continue
            if _looks_like_authenticated_form(response.text):
                bootstrapped.append((response.url, response, {"Cookie": cookie_header}))
                break
    return bootstrapped[:2]


def _submit_login_form(
    action_url: str,
    fields: list[str],
    extras: dict[str, str],
    *,
    username: str,
    password: str,
) -> tuple[FetchResult, str]:
    session = requests.Session()
    data = dict(extras)
    for field in fields:
        lowered = field.lower()
        if lowered == "username":
            data[field] = username
        elif lowered == "password":
            data[field] = password
        else:
            data.setdefault(field, "")
    try:
        response = session.post(action_url, data=data, timeout=4.0, allow_redirects=True)
    except requests.RequestException as exc:
        return FetchResult(url=action_url, error=str(exc)), ""
    cookie_header = "; ".join(f"{cookie.name}={cookie.value}" for cookie in session.cookies)
    return (
        FetchResult(
            url=str(response.url),
            status_code=int(response.status_code),
            headers={str(key).lower(): str(value) for key, value in response.headers.items()},
            text=response.text,
            error="" if response.ok else f"HTTP {response.status_code}",
            elapsed_ms=int(response.elapsed.total_seconds() * 1000),
        ),
        cookie_header,
    )


def _looks_like_authenticated_form(html: str) -> bool:
    lowered = (html or "").lower()
    if "password" in lowered and "username" in lowered:
        return False
    for attrs, body in FORM_RE.findall(html or ""):
        fields, _extras = _extract_form_fields(body)
        if any(field.lower() in INTERESTING_PARAM_NAMES for field in fields):
            return True
    return False


def _probe_candidate(candidate: XSSCandidate) -> dict[str, object]:
    baseline = _send_request(_request_for(candidate, "xss_baseline"))
    attempts = []
    for payload in PAYLOADS:
        marker = _probe_marker(candidate, payload.strategy)
        payload_value = payload.value.replace("XSS_MARKER", marker)
        request = _request_for(candidate, payload_value)
        response = _send_request(request)
        context = _classify_reflection(response.text, payload_value, marker)
        source_sink = bool(candidate.source_signal and candidate.sink)
        if source_sink and not context and _dom_source_sink_is_confirmable(candidate, response):
            context = "dom_source_sink"
        reflected = bool(context)
        confirmed = reflected and _context_matches_strategy(context, payload, source_sink)
        if confirmed:
            attempts.append(_attempt_payload(payload, request, response, context, confirmed=True, marker=marker))
            return {
                "confirmed": True,
                "candidate": _candidate_dict(candidate),
                "strategy": payload.strategy,
                "context": context,
                "request": request,
                "status_code": response.status_code,
                "elapsed_ms": response.elapsed_ms,
                "baseline_status": baseline.status_code,
                "basis": _basis(candidate, payload, context, response, baseline),
                "attempts": attempts,
            }
        attempts.append(_attempt_payload(payload, request, response, context, confirmed=False, marker=marker))
    return {
        "confirmed": False,
        "candidate": _candidate_dict(candidate),
        "status_code": baseline.status_code,
        "basis": "No reflected or source-to-sink XSS signal confirmed with bounded payloads.",
        "attempts": attempts[:4],
    }


def _attempt_payload(payload: XSSPayload, request: dict[str, str], response: FetchResult, context: str, *, confirmed: bool, marker: str) -> dict[str, object]:
    return {
        "strategy": payload.strategy,
        "context": context,
        "confirmed": confirmed,
        "url": request["url"],
        "method": request["method"],
        "body": request.get("body", ""),
        "status_code": response.status_code,
        "marker": marker,
        "excerpt": _reflection_excerpt(response.text, payload.value.replace("XSS_MARKER", marker), marker),
    }


def _request_for(candidate: XSSCandidate, value: str) -> dict[str, str]:
    method = candidate.method.upper()
    params = dict(candidate.extra_params or {})
    params.setdefault("submit", "submit")
    params[candidate.parameter] = value
    if method == "POST":
        return {
            "url": candidate.page_url,
            "method": "POST",
            "body": urlencode(params, doseq=True),
            "headers": dict(candidate.headers or {}),
        }
    parsed = urlparse(candidate.page_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key, item_value in params.items():
        query[key] = [item_value]
    return {
        "url": urlunparse(parsed._replace(query=urlencode(query, doseq=True))),
        "method": "GET",
        "body": "",
        "headers": dict(candidate.headers or {}),
    }


def _send_request(request: dict[str, str]) -> FetchResult:
    headers = dict(request.get("headers", {}) if isinstance(request.get("headers", {}), dict) else {})
    if request.get("method", "GET").upper() == "POST":
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    return http_fetch_text(
        request["url"],
        method=request.get("method", "GET"),
        body=request.get("body", ""),
        headers=headers or None,
        timeout_seconds=8.0,
        max_bytes=180_000,
    )


def _classify_reflection(body: str, payload: str, marker: str) -> str:
    if not body:
        return ""
    decoded = unescape(body)
    lower = decoded.lower()
    payload_lower = payload.lower()
    if payload_lower not in lower and marker.lower() not in lower:
        return ""
    index = lower.find(payload_lower)
    if index < 0:
        index = lower.find(marker.lower())
    excerpt = decoded[max(0, index - 180) : index + len(payload) + 220]
    prefix = decoded[max(0, index - 120) : index].lower()
    suffix = decoded[index : index + len(payload) + 160].lower()
    if "<script" in prefix or "</script" in suffix or "alert(1)" in suffix and "$" in prefix:
        return "script"
    if re.search(r"\bhref\s*=\s*['\"][^'\"]*(javascript:|xss_marker|alert\(1\))", excerpt, re.I):
        return "href"
    if "<svg" in suffix or "onload=" in suffix or "onerror=" in suffix:
        return "html_body"
    if "onclick=" in suffix or "onmouseover=" in suffix:
        return "attribute"
    return "text_reflection"


def _context_matches_strategy(context: str, payload: XSSPayload, source_sink: bool) -> bool:
    if source_sink and context == "dom_source_sink":
        return True
    if context in {"html_body", "href", "script", "attribute"}:
        return True
    if source_sink and context in {"text_reflection", "html_body", "attribute", "href"}:
        return True
    return False


def _dom_source_sink_is_confirmable(candidate: XSSCandidate, response: FetchResult) -> bool:
    if not response.ok:
        return False
    source = candidate.source_signal.lower()
    sink = candidate.sink.lower()
    parameter = candidate.parameter.lower()
    if not source or not sink or not parameter:
        return False
    if any(marker in source for marker in ("location.search", "location.href", "location.hash", "window.location")):
        return True
    if "getelementbyid" in source:
        return parameter in candidate.context_hint.lower()
    if any(marker in source for marker in ("document.url", "documenturi", "referrer", "window.name")):
        return True
    return False


def _confirmed_finding(target: str, probe: dict[str, object], probes: list[dict[str, object]], first_page: FetchResult) -> Finding:
    candidate = probe.get("candidate", {}) if isinstance(probe.get("candidate", {}), dict) else {}
    title = f"XSS evidence candidate: {candidate.get('parameter', 'input')}"
    evidence = "\n".join(
        [
            f"Target: {target}",
            f"Page: {candidate.get('page_url', '')}",
            f"Method: {candidate.get('method', '')}",
            f"Parameter: {candidate.get('parameter', '')}",
            f"Context: {probe.get('context', '')}",
            f"Confirmed strategies: {probe.get('strategy', '')}",
            f"Basis: {probe.get('basis', '')}",
        ]
    )
    return Finding(
        title=title,
        severity="high",
        location=f"{candidate.get('page_url', '')}?{candidate.get('parameter', '')}=[controlled-test]",
        evidence=evidence,
        kind="vulnerability",
        verification_status="confirmed",
        verified=True,
        recommendation="Apply contextual output encoding, sanitize active markup, and avoid writing attacker-controlled values into executable browser contexts.",
        metadata={
            "xss_candidate": {
                **candidate,
                "context": str(probe.get("context", "")),
                "confirmed_strategies": [str(probe.get("strategy", ""))],
                "basis": str(probe.get("basis", "")),
                "request_url": str((probe.get("request", {}) if isinstance(probe.get("request"), dict) else {}).get("url", "")),
                "request_body": str((probe.get("request", {}) if isinstance(probe.get("request"), dict) else {}).get("body", "")),
            },
            "probe_attempts": probe.get("attempts", []),
        },
    )


def _inventory_finding(target: str, candidates: list[XSSCandidate], probes: list[dict[str, object]], auxiliary_pages: list[dict[str, str]]) -> Finding:
    confirmed = [probe for probe in probes if probe.get("confirmed")]
    candidate_lines = []
    for candidate in candidates[:40]:
        candidate_lines.append(
            f"- {candidate.parameter} at {candidate.page_url} method={candidate.method} source={candidate.source}"
        )
    return Finding(
        title="XSS candidate inventory",
        severity="info",
        location=target,
        evidence="\n".join(
            [
                f"Discovered XSS candidates: {len(candidates)}",
                f"Confirmed XSS candidates: {len(confirmed)}",
                f"Auxiliary XSS pages: {len(auxiliary_pages)}",
                *candidate_lines,
            ]
        ),
        kind="evidence",
        verification_status="informational",
        verified=False,
        recommendation="Review candidate inventory and use confirmed findings for reportable XSS vulnerabilities.",
        metadata={
            "candidate_count": len(candidates),
            "confirmed_count": len(confirmed),
            "auxiliary_count": len(auxiliary_pages),
        },
    )


def _candidate_finding(target: str, candidates: list[XSSCandidate], probes: list[dict[str, object]], first_page: FetchResult) -> Finding:
    return Finding(
        title="XSS triage checklist",
        severity="low",
        location=target,
        evidence=f"No XSS candidate was confirmed in the current bounded fetch window; candidates={len(candidates)}; probes={len(probes)}; entry_status={first_page.status_code}.",
        kind="scope",
        verification_status="informational",
        verified=False,
        recommendation="Review client-side routing, DOM writes, templating sinks, and server-side reflection points before release.",
    )


def _auxiliary_finding(target: str, item: dict[str, str]) -> Finding:
    return Finding(
        title=f"Auxiliary XSS surface: {item.get('type', 'review')}",
        severity="info",
        location=item.get("url", target),
        evidence=item.get("evidence", ""),
        kind="scope",
        verification_status="informational",
        verified=False,
        recommendation="Treat this as a follow-up XSS surface; do not count it as confirmed without browser/OOB proof.",
        metadata={"auxiliary_type": item.get("type", ""), "source": "xss_triage", "auxiliary": True},
    )


def _followup_scope_finding(target: str, followup_inputs: dict[str, object]) -> Finding:
    evidence_parts = [
        "This XSS triage step consumed upstream route and frontend artifact hints.",
        _format_values("js_assets", followup_inputs.get("js_assets", [])),
        _format_values("api_paths", followup_inputs.get("api_paths", [])),
        _format_values("upload_import_paths", followup_inputs.get("upload_import_paths", [])),
        _format_values("download_export_paths", followup_inputs.get("download_export_paths", [])),
        _format_values("route_prefixes", followup_inputs.get("route_prefixes", [])),
        _format_values("framework_routes", followup_inputs.get("framework_routes", [])),
    ]
    return Finding(
        title="Backup-derived XSS follow-up scope",
        severity="info",
        location=target,
        evidence="; ".join(part for part in evidence_parts if part),
        kind="scope",
        verification_status="informational",
        verified=False,
        recommendation="Prioritize routes and script assets recovered from upstream artifacts when confirming DOM or reflected XSS behavior.",
    )


def _build_xss_followup_context(
    findings: list[Finding],
    candidates: list[XSSCandidate],
    probes: list[dict[str, object]],
    auxiliary_pages: list[dict[str, str]],
) -> dict[str, object]:
    confirmed_findings = [item for item in findings if item.verified and item.metadata.get("xss_candidate")]
    return {
        "producer": "xss_triage",
        "consumers": {
            "poc_verify": {
                "xss_findings": [item.metadata.get("xss_candidate", {}) for item in confirmed_findings],
                "high_risk_findings": [item.to_dict() for item in confirmed_findings],
            },
            "xss_triage": {
                "xss_candidates": [_candidate_dict(item) for item in candidates[:20]],
                "auxiliary_surfaces": auxiliary_pages[:10],
            },
        },
    }


def _extract_form_fields(form_body: str) -> tuple[list[str], dict[str, str]]:
    names: list[str] = []
    extras: dict[str, str] = {}
    for attrs in INPUT_TAG_RE.findall(form_body or ""):
        values = _attrs(attrs)
        name = values.get("name", "").strip()
        if not name:
            continue
        field_type = values.get("type", "text").lower()
        value = values.get("value", "")
        if field_type in {"submit", "hidden"}:
            extras[name] = value or ("submit" if field_type == "submit" else "")
            continue
        names.append(name)
        if value:
            extras.setdefault(name, value)
    for attrs in TEXTAREA_TAG_RE.findall(form_body or ""):
        values = _attrs(attrs)
        name = values.get("name", "").strip()
        if name:
            names.append(name)
    return sorted(set(names)), extras


def _input_names(html: str) -> list[str]:
    names = []
    for attrs in INPUT_TAG_RE.findall(html or ""):
        values = _attrs(attrs)
        if values.get("name"):
            names.append(values["name"])
        elif values.get("id"):
            names.append(values["id"])
    for attrs in TEXTAREA_TAG_RE.findall(html or ""):
        values = _attrs(attrs)
        if values.get("name"):
            names.append(values["name"])
    return sorted(set(names))


def _attrs(raw_attrs: str) -> dict[str, str]:
    return {match.group("name").lower(): unescape(match.group("value")) for match in ATTR_RE.finditer(raw_attrs or "")}


def _source_sink_context(html: str) -> dict[str, str]:
    for script in SCRIPT_RE.findall(html or ""):
        source = next((match.group(1) for match in CLIENT_SOURCE_RE.finditer(script)), "")
        sink = next((match.group(1) for match in DANGEROUS_SINK_RE.finditer(script)), "")
        if source and sink:
            snippet = re.sub(r"\s+", " ", script.strip())[:600]
            return {"source": source, "sink": sink, "snippet": snippet}
    return {}


def _classify_auxiliary_pages(page_url: str, html: str) -> list[dict[str, str]]:
    text = f"{page_url}\n{html[:2000]}".lower()
    items = []
    if "blind" in text or "cookie" in text:
        items.append(
            {
                "url": page_url,
                "type": "blind_or_oob_xss",
                "evidence": "Page appears to require blind/OOB or backend cookie collection before confirmation.",
            }
        )
    if any(marker in text for marker in ("xss platform", "xss平台", "collector", "backend panel", "admin console")):
        items.append(
            {
                "url": page_url,
                "type": "xss_platform",
                "evidence": "Page is an XSS platform/admin surface and should not be counted as a target vulnerability by itself.",
            }
        )
    return items


def _classify_auxiliary_pages_generic(page_url: str, html: str) -> list[dict[str, str]]:
    text = f"{page_url}\n{html[:2000]}".lower()
    items = []
    if "blind" in text or "cookie" in text:
        items.append(
            {
                "url": page_url,
                "type": "blind_or_oob_xss",
                "evidence": "Page appears to require blind/OOB or backend cookie collection before confirmation.",
            }
        )
    if any(marker in text for marker in ("xss platform", "collector", "backend panel", "admin console")):
        items.append(
            {
                "url": page_url,
                "type": "xss_platform",
                "evidence": "Page is an XSS platform/admin surface and should not be counted as a target vulnerability by itself.",
            }
        )
    return items


def _basis(candidate: XSSCandidate, payload: XSSPayload, context: str, response: FetchResult, baseline: FetchResult) -> str:
    parts = [
        f"{payload.strategy}: payload reached {context} context",
        f"status={response.status_code}",
    ]
    if candidate.source_signal and candidate.sink:
        parts.append(f"source_sink={candidate.source_signal}->{candidate.sink}")
    if response.status_code != baseline.status_code:
        parts.append(f"baseline_status={baseline.status_code}")
    return "; ".join(parts)


def _reflection_excerpt(body: str, payload: str, marker: str) -> str:
    decoded = unescape(body or "")
    index = decoded.lower().find(payload.lower())
    if index < 0:
        index = decoded.lower().find(marker.lower())
    if index < 0:
        return ""
    return re.sub(r"\s+", " ", decoded[max(0, index - 160) : index + len(payload) + 180])[:700]


def _probe_marker(candidate: XSSCandidate, strategy: str) -> str:
    seed = f"{candidate.method}|{candidate.page_url}|{candidate.parameter}|{strategy}"
    return "XSS_MARKER_" + sha1(seed.encode("utf-8", errors="ignore")).hexdigest()[:10]


def _candidate_dict(candidate: XSSCandidate) -> dict[str, object]:
    return {
        "page_url": candidate.page_url,
        "method": candidate.method,
        "parameter": candidate.parameter,
        "source": candidate.source,
        "reason": candidate.reason,
        "baseline_body": candidate.baseline_body,
        "sink": candidate.sink,
        "source_signal": candidate.source_signal,
        "context_hint": candidate.context_hint,
    }


def _dedupe_candidates(candidates: list[XSSCandidate]) -> list[XSSCandidate]:
    best: dict[tuple[str, str, str], XSSCandidate] = {}
    for candidate in candidates:
        key = (_normalize_url(candidate.page_url), candidate.method.upper(), candidate.parameter.lower())
        existing = best.get(key)
        if existing is None or _candidate_score_generic(candidate) > _candidate_score_generic(existing):
            best[key] = candidate
            continue
    return list(best.values())


def _prioritize_candidates(candidates: list[XSSCandidate]) -> list[XSSCandidate]:
    return sorted(candidates, key=_candidate_score_generic, reverse=True)


def _candidate_score(candidate: XSSCandidate) -> int:
    text = f"{candidate.page_url} {candidate.parameter} {candidate.source}".lower()
    score = 0
    if "dom-source-sink" in candidate.source:
        score += 90
    if candidate.source_signal and candidate.sink:
        score += 80
    if candidate.method.upper() == "POST":
        score += 35
    if any(name in candidate.parameter.lower() for name in ("message", "text", "content", "comment", "name", "q", "search")):
        score += 25
    if any(marker in text for marker in ("xss", "reflect", "stored", "dom")):
        score += 15
    if any(marker in text for marker in ("blind", "collector", "backend panel", "admin console")):
        score -= 80
    return score


def _candidate_score_generic(candidate: XSSCandidate) -> int:
    text = f"{candidate.page_url} {candidate.parameter} {candidate.source}".lower()
    score = 0
    if "dom-source-sink" in candidate.source:
        score += 90
    if candidate.source_signal and candidate.sink:
        score += 80
    if candidate.method.upper() == "POST":
        score += 35
    if candidate.method.upper() == "GET" and "xss" in text:
        score += 55
    if any(name in candidate.parameter.lower() for name in ("message", "text", "content", "comment", "name", "q", "search")):
        score += 25
    if any(marker in text for marker in ("xss", "reflect", "stored", "dom")):
        score += 15
    if any(marker in text for marker in ("blind", "collector", "backend panel", "admin console")):
        score -= 80
    return score


def _followup_seed_urls(target: str, followup_inputs: dict[str, object]) -> list[str]:
    seeds: list[str] = []
    for key in ("api_paths", "framework_routes", "route_prefixes", "xss_candidates", "js_assets", "authenticated_urls", "seed_urls", "discovered_urls"):
        value = followup_inputs.get(key, [])
        if isinstance(value, list):
            for item in value:
                text = str(item).strip()
                if text:
                    seeds.append(urljoin(target, text))
    return sorted(set(seeds))


def _request_headers_from_followup(followup_inputs: dict[str, object], context: dict | None) -> dict[str, str]:
    headers = followup_inputs.get("request_headers", {}) if isinstance(followup_inputs, dict) else {}
    if not isinstance(headers, dict):
        request_context = followup_inputs.get("request_context", {}) if isinstance(followup_inputs, dict) else {}
        headers = request_context.get("request_headers", {}) if isinstance(request_context, dict) else {}
    if not isinstance(headers, dict):
        headers = {}
    direct = (context or {}).get("request_headers", {}) if isinstance(context, dict) else {}
    merged = dict(headers)
    if isinstance(direct, dict):
        merged.update(direct)
    return {str(key): str(value) for key, value in merged.items() if str(key).strip() and str(value).strip()}


def _format_values(label: str, values: object) -> str:
    if not isinstance(values, list) or not values:
        return ""
    return f"{label}={', '.join(compress_text(str(item)) for item in values[:6])}"


def _is_low_value_param(name: str) -> bool:
    lowered = name.strip().lower()
    if not lowered:
        return True
    if lowered in LOW_VALUE_PARAMS:
        return True
    return any(token in lowered for token in ("csrf", "token", "submit", "button"))


def _is_auth_form(action_url: str, fields: list[str]) -> bool:
    lowered_url = action_url.lower()
    lowered_fields = {field.lower() for field in fields}
    if "logout" in lowered_url:
        return True
    if "login" in lowered_url and ({"username", "user", "email"} & lowered_fields or {"password", "pass", "passwd", "pwd"} & lowered_fields):
        return True
    return bool({"username", "user", "email"} & lowered_fields and {"password", "pass", "passwd", "pwd"} & lowered_fields)


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    return parsed.scheme, parsed.hostname or "", parsed.port


def _is_crawlable_same_origin(url: str, origin: tuple[str, str, int | None]) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    if (parsed.scheme, parsed.hostname or "", parsed.port) != origin:
        return False
    path = parsed.path.lower()
    if "logout" in path:
        return False
    query_keys = {key.lower() for key in parse_qs(parsed.query, keep_blank_values=True)}
    if path.endswith("security.php") and query_keys & {"phpids", "test", "security", "seclev_submit", "user_token"}:
        return False
    return not any(path.endswith(suffix) for suffix in SKIP_URL_SUFFIXES)


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))
