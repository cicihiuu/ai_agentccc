from __future__ import annotations

import re
from html import unescape
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from ai_security_agent.schemas import Finding, ModuleResult

from .common import (
    compress_text,
    get_report_contract,
    get_skill_bundle,
    get_support_skills,
    is_local_or_lab_target,
    now_iso,
    safe_fetch_text,
)
from .followup_bridge import extract_followup_inputs


URL_PARAMETER_NAMES = {
    "url",
    "uri",
    "target",
    "dest",
    "destination",
    "redirect",
    "next",
    "file",
    "path",
    "link",
    "feed",
    "callback",
    "webhook",
    "image",
    "img",
    "avatar",
    "src",
    "fetch",
    "proxy",
    "preview",
    "oembed",
}
SSRF_FEATURE_RE = re.compile(
    r"\b(fetch|download|import|proxy|webhook|avatar|image|url|uri|callback|redirect|oembed|preview|remote|ssrf)\b",
    re.IGNORECASE,
)
INTERNAL_HOST_RE = re.compile(r"(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|metadata|internal|docker\.internal)", re.IGNORECASE)
LINK_RE = re.compile(r'''\b(?:href|src|action)\s*=\s*["'](?P<url>[^"'#>]+)["']''', re.IGNORECASE)
FORM_RE = re.compile(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", re.IGNORECASE | re.DOTALL)
ACTION_RE = re.compile(r'''action\s*=\s*["'](?P<value>[^"']+)["']''', re.IGNORECASE)
METHOD_RE = re.compile(r'''method\s*=\s*["'](?P<value>[^"']+)["']''', re.IGNORECASE)
INPUT_RE = re.compile(r"<(?:input|textarea|select)\b(?P<attrs>[^>]*)>", re.IGNORECASE)
NAME_RE = re.compile(r'''name\s*=\s*["'](?P<value>[^"']+)["']''', re.IGNORECASE)
TITLE_RE = re.compile(r"(?is)<title\b[^>]*>(?P<title>.*?)</title>")
HTML_DOCUMENT_RE = re.compile(r"(?is)<html\b|<body\b|<!doctype\s+html")

MAX_SEED_PAGES = 80
MAX_CANDIDATES = 20
MAX_FINDINGS = 12


def run(target: str, context: dict | None = None) -> ModuleResult:
    started = now_iso()
    if not is_local_or_lab_target(target):
        return ModuleResult(
            module="ssrf_triage",
            target=target,
            status="skipped",
            findings=[],
            logs=["Target is outside the local/course-lab allowlist; SSRF triage skipped."],
            started_at=started,
            finished_at=now_iso(),
            error="only localhost or course lab targets are allowed",
        )

    context = context or {}
    skill_bundle = get_skill_bundle(context)
    support_skills = get_support_skills(context)
    report_contract = get_report_contract(context)
    followup_inputs = extract_followup_inputs("ssrf_triage", context)

    findings: list[Finding] = []
    logs: list[str] = []
    pages = _collect_pages(target, followup_inputs, logs)
    candidates = _discover_candidates(target, pages, followup_inputs)
    logs.append(f"SSRF candidate inventory: pages={len(pages)}, candidates={len(candidates)}")

    if candidates:
        findings.append(_inventory_finding(candidates))
    elif pages and (feature_hits := _feature_hits("\n".join(pages.values()))):
        findings.append(
            Finding(
                title="SSRF feature surface requires follow-up",
                severity="medium",
                location=target,
                evidence=f"Detected fetch-like feature words: {', '.join(feature_hits[:10])}",
                kind="candidate",
                verification_status="unconfirmed",
                verified=False,
                recommendation="Review whether the server fetches attacker-controlled URLs and blocks loopback/link-local/internal destinations.",
            )
        )

    for candidate in candidates[:MAX_CANDIDATES]:
        finding = _probe_candidate(target, candidate)
        if finding is not None:
            findings.append(finding)

    if followup_inputs:
        findings.append(_followup_scope_finding(target, followup_inputs))
        logs.append("Generated SSRF follow-up scope from upstream followup_context.")

    if not findings:
        findings.append(
            Finding(
                title="SSRF triage checklist",
                severity="low",
                location=target,
                evidence="No SSRF candidate was confirmed in the current bounded fetch window.",
                kind="scope",
                verification_status="informational",
                verified=False,
                recommendation="Review server-side HTTP clients, remote importers, image fetchers, previewers, and webhook handlers before release.",
            )
        )

    if skill_bundle:
        logs.append(f"Skill guidance loaded: {skill_bundle.get('name', 'ssrf-triage')}")
    if support_skills:
        logs.append("Support skills: " + ", ".join(item.get("name", "support") for item in support_skills))
    if report_contract:
        logs.append("Report contract section: " + ", ".join(str(item) for item in report_contract.get("sections", [])))

    deduped = _dedupe_findings(findings)
    return ModuleResult(
        module="ssrf_triage",
        target=target,
        status="ok",
        findings=deduped[:MAX_FINDINGS],
        followup_context=_build_ssrf_followup_context(deduped, candidates),
        logs=logs or ["SSRF triage completed."],
        started_at=started,
        finished_at=now_iso(),
    )


def _collect_pages(target: str, followup_inputs: dict[str, object], logs: list[str]) -> dict[str, str]:
    pages: dict[str, str] = {}
    queue = [target]
    for value in _context_seed_urls(followup_inputs):
        _append_same_origin_url(queue, target, value)

    index = 0
    while index < len(queue) and len(pages) < MAX_SEED_PAGES:
        url = queue[index]
        index += 1
        if url in pages:
            continue
        if _looks_like_static_asset(url):
            continue
        response = safe_fetch_text(url, timeout_seconds=2.0, max_bytes=180_000)
        if not response.ok:
            logs.append(f"SSRF page fetch unavailable: {url} ({response.error or response.status_code})")
            continue
        pages[url] = response.text
        for link in sorted(_extract_links(response.text), key=lambda item: _url_interest_score(urljoin(url, item)), reverse=True):
            _append_same_origin_url(queue, url, link)
    return pages


def _discover_candidates(target: str, pages: dict[str, str], followup_inputs: dict[str, object]) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    for page_url, html in pages.items():
        _append_query_candidates(candidates, page_url, page_url, "page_query")
        for link in _extract_links(html):
            absolute = urljoin(page_url, link)
            if _same_origin(target, absolute):
                _append_query_candidates(candidates, page_url, absolute, "link_query")
        _append_form_candidates(candidates, page_url, html)

    for value in _context_seed_urls(followup_inputs):
        absolute = urljoin(target, value)
        if _same_origin(target, absolute):
            _append_query_candidates(candidates, target, absolute, "followup_query")
    return _dedupe_candidates(candidates)


def _append_query_candidates(candidates: list[dict[str, str]], page_url: str, request_url: str, source: str) -> None:
    parsed = urlparse(request_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for parameter, values in query.items():
        if not _looks_like_url_parameter(parameter, values):
            continue
        candidates.append(
            {
                "page_url": page_url,
                "request_url": request_url,
                "method": "GET",
                "parameter": parameter,
                "source": source,
                "reason": "URL-bearing query parameter discovered from same-origin route inventory.",
                "baseline_value": values[0] if values else "",
            }
        )


def _append_form_candidates(candidates: list[dict[str, str]], page_url: str, html: str) -> None:
    for form in FORM_RE.finditer(html or ""):
        attrs = form.group("attrs") or ""
        body = form.group("body") or ""
        action_match = ACTION_RE.search(attrs)
        method_match = METHOD_RE.search(attrs)
        action = urljoin(page_url, action_match.group("value")) if action_match else page_url
        method = str(method_match.group("value") if method_match else "GET").upper()
        inputs = _input_names(body)
        for name in inputs:
            if name.lower() not in URL_PARAMETER_NAMES:
                continue
            candidates.append(
                {
                    "page_url": page_url,
                    "request_url": action,
                    "method": method,
                    "parameter": name,
                    "source": f"form:{method}",
                    "reason": "Form input name suggests server-side URL fetching or callback handling.",
                    "baseline_value": "",
                }
            )


def _probe_candidate(target: str, candidate: dict[str, str]) -> Finding | None:
    method = str(candidate.get("method", "GET")).upper()
    if method != "GET":
        return Finding(
            title=f"SSRF form parameter candidate: {candidate.get('parameter', 'url')}",
            severity="medium",
            location=str(candidate.get("request_url", "")),
            evidence=f"Non-GET form requires authenticated/manual replay. parameter={candidate.get('parameter', '')}; source={candidate.get('source', '')}",
            kind="candidate",
            verification_status="manual_required",
            verified=False,
            recommendation="Replay the form with a controlled callback or loopback target and verify outbound allowlist enforcement.",
            metadata={"ssrf_context": _ssrf_context(candidate, probe_url="", baseline=None, mutated=None, direct=None, probe_value="", basis="manual_form")},
        )

    request_url = str(candidate.get("request_url", "")).strip()
    parameter = str(candidate.get("parameter", "")).strip()
    if not request_url or not parameter:
        return None

    baseline = safe_fetch_text(request_url, timeout_seconds=1.5, max_bytes=100_000)
    best_candidate: tuple[str, object, object, dict[str, object]] | None = None
    for probe_value in _controlled_probe_values(target, request_url):
        probe_url = _mutated_url(request_url, parameter, probe_value)
        direct = safe_fetch_text(probe_value, timeout_seconds=1.5, max_bytes=100_000)
        mutated = safe_fetch_text(probe_url, timeout_seconds=1.5, max_bytes=140_000)
        assessment = _assess_ssrf_reflection(baseline, mutated, direct, probe_value)
        if assessment["confirmed"]:
            context = _ssrf_context(candidate, probe_url=probe_url, baseline=baseline, mutated=mutated, direct=direct, probe_value=probe_value, basis=str(assessment["basis"]))
            return Finding(
                title=f"Confirmed SSRF loopback fetch via {parameter}",
                severity="high",
                location=probe_url,
                evidence=_confirmed_evidence(candidate, baseline, mutated, direct, probe_value, assessment),
                kind="vulnerability",
                verification_status="confirmed",
                verified=True,
                recommendation="Allowlist outbound schemes and hosts, block loopback/link-local/internal ranges, and isolate server-side fetchers.",
                metadata={"ssrf_context": context, "verification_source": "ssrf_triage"},
            )
        if assessment["suspicious"] and best_candidate is None:
            best_candidate = (probe_value, mutated, direct, assessment)

    if best_candidate is not None:
        probe_value, mutated, direct, assessment = best_candidate
        probe_url = _mutated_url(request_url, parameter, probe_value)
        context = _ssrf_context(candidate, probe_url=probe_url, baseline=baseline, mutated=mutated, direct=direct, probe_value=probe_value, basis=str(assessment["basis"]))
        return Finding(
            title=f"SSRF candidate parameter: {parameter}",
            severity="medium",
            location=probe_url,
            evidence=_candidate_evidence(candidate, baseline, mutated, direct, probe_value, assessment),
            kind="candidate",
            verification_status="unconfirmed",
            verified=False,
            recommendation="Confirm whether this endpoint performs a server-side fetch and rejects internal destinations after URL normalization and redirects.",
            metadata={"ssrf_context": context, "verification_source": "ssrf_triage"},
        )
    return None


def _assess_ssrf_reflection(baseline, mutated, direct, probe_value: str) -> dict[str, object]:
    if not getattr(mutated, "ok", False):
        return {"confirmed": False, "suspicious": False, "basis": "probe_not_reachable", "overlap": 0.0, "delta": 0}
    if _final_url_is_probe_redirect(str(getattr(mutated, "url", "") or ""), probe_value):
        return {"confirmed": False, "suspicious": True, "basis": "redirect_followed", "overlap": 0.0, "delta": 0}
    baseline_text = str(getattr(baseline, "text", "") or "")
    mutated_text = str(getattr(mutated, "text", "") or "")
    direct_text = str(getattr(direct, "text", "") or "")
    delta = len(mutated_text) - len(baseline_text)
    title = _html_title(direct_text)
    overlap = _token_overlap(direct_text, mutated_text)
    baseline_overlap = _token_overlap(direct_text, baseline_text)
    internal_probe = bool(INTERNAL_HOST_RE.search(probe_value))
    title_signal = bool(title and title.lower() in mutated_text.lower() and title.lower() not in baseline_text.lower())
    html_reflection = bool(HTML_DOCUMENT_RE.search(direct_text) and HTML_DOCUMENT_RE.search(mutated_text) and delta > 600)
    loopback_delta_signal = bool(HTML_DOCUMENT_RE.search(mutated_text) and delta > 800 and baseline_overlap < 0.08)
    overlap_signal = bool(overlap >= 0.18 and overlap > baseline_overlap + 0.06 and delta > 200)
    direct_ok = bool(getattr(direct, "ok", False))
    confirmed = bool(internal_probe and ((direct_ok and (title_signal or html_reflection or overlap_signal)) or loopback_delta_signal))
    suspicious = bool(internal_probe and (delta > 200 or overlap > baseline_overlap + 0.03 or title_signal))
    basis_parts = []
    if title_signal:
        basis_parts.append("direct_title_reflected")
    if html_reflection:
        basis_parts.append("loopback_html_embedded")
    if overlap_signal:
        basis_parts.append("direct_content_overlap")
    if loopback_delta_signal:
        basis_parts.append("loopback_response_delta")
    if not basis_parts and suspicious:
        basis_parts.append("response_delta")
    return {
        "confirmed": confirmed,
        "suspicious": suspicious,
        "basis": ",".join(basis_parts) or "none",
        "overlap": round(overlap, 3),
        "baseline_overlap": round(baseline_overlap, 3),
        "delta": delta,
        "direct_status": int(getattr(direct, "status_code", 0) or 0),
    }


def _final_url_is_probe_redirect(final_url: str, probe_value: str) -> bool:
    final = urlparse(final_url)
    probe = urlparse(probe_value)
    if not final.scheme or not final.netloc or not probe.scheme or not probe.netloc:
        return False
    return (final.scheme, final.netloc) == (probe.scheme, probe.netloc)


def _inventory_finding(candidates: list[dict[str, str]]) -> Finding:
    preview = [
        f"{item.get('method', 'GET')} {item.get('parameter', '')} @ {item.get('request_url', '')}"
        for item in candidates[:8]
    ]
    return Finding(
        title="SSRF candidate inventory",
        severity="info",
        location=", ".join(str(item.get("request_url", "")) for item in candidates[:4]),
        evidence=f"Discovered URL-bearing inputs for bounded SSRF review. count={len(candidates)}; preview=" + "; ".join(preview),
        kind="scope",
        verification_status="informational",
        verified=False,
        recommendation="Use confirmed findings for remediation and keep remaining URL-bearing candidates for manual replay with authentication if needed.",
        metadata={"ssrf_inventory": {"candidates": [dict(item) for item in candidates[:20]]}},
    )


def _confirmed_evidence(candidate: dict[str, str], baseline, mutated, direct, probe_value: str, assessment: dict[str, object]) -> str:
    return "\n".join(
        [
            f"Page: {candidate.get('page_url', '')}",
            f"Method: {candidate.get('method', 'GET')}",
            f"Parameter: {candidate.get('parameter', '')}",
            f"Baseline URL: {candidate.get('request_url', '')}",
            f"Probe URL: {mutated.url}",
            f"Probe value: {probe_value}",
            f"Baseline status: {getattr(baseline, 'status_code', 0)}",
            f"Probe status: {getattr(mutated, 'status_code', 0)}",
            f"Direct status: {getattr(direct, 'status_code', 0)}",
            f"Basis: {assessment.get('basis', 'none')}",
            f"Delta length: {assessment.get('delta', 0)}",
            f"Direct overlap: {assessment.get('overlap', 0)}",
        ]
    )


def _candidate_evidence(candidate: dict[str, str], baseline, mutated, direct, probe_value: str, assessment: dict[str, object]) -> str:
    return "\n".join(
        [
            f"Page: {candidate.get('page_url', '')}",
            f"Method: {candidate.get('method', 'GET')}",
            f"Parameter: {candidate.get('parameter', '')}",
            f"Baseline URL: {candidate.get('request_url', '')}",
            f"Probe URL: {getattr(mutated, 'url', '')}",
            f"Probe value: {probe_value}",
            f"Baseline status: {getattr(baseline, 'status_code', 0)}",
            f"Probe status: {getattr(mutated, 'status_code', 0)}",
            f"Direct status: {getattr(direct, 'status_code', 0)}",
            f"Basis: {assessment.get('basis', 'none')}",
            f"Delta length: {assessment.get('delta', 0)}",
        ]
    )


def _controlled_probe_values(target: str, request_url: str) -> list[str]:
    parsed_target = urlparse(target)
    values = ["http://127.0.0.1/", "http://localhost/"]
    if parsed_target.scheme and parsed_target.netloc:
        values.append(f"{parsed_target.scheme}://{parsed_target.netloc}/")
    parsed_request = urlparse(request_url)
    if parsed_request.scheme and parsed_request.netloc and parsed_request.netloc != parsed_target.netloc:
        values.append(f"{parsed_request.scheme}://{parsed_request.netloc}/")
    deduped: list[str] = []
    for value in values:
        if value not in deduped:
            deduped.append(value)
    return deduped


def _mutated_url(request_url: str, parameter: str, value: str) -> str:
    parsed = urlparse(request_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[parameter] = [value]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def _ssrf_context(candidate: dict[str, str], *, probe_url: str, baseline, mutated, direct, probe_value: str, basis: str) -> dict[str, object]:
    return {
        "page_url": str(candidate.get("page_url", "")).strip(),
        "request_url": str(candidate.get("request_url", "")).strip(),
        "method": str(candidate.get("method", "GET")).strip(),
        "parameter": str(candidate.get("parameter", "")).strip(),
        "source": str(candidate.get("source", "")).strip(),
        "reason": str(candidate.get("reason", "")).strip(),
        "probe_type": "loopback_content_reflection",
        "probe_value": probe_value,
        "probe_url": probe_url,
        "baseline_status": int(getattr(baseline, "status_code", 0) or 0),
        "probe_status": int(getattr(mutated, "status_code", 0) or 0),
        "direct_status": int(getattr(direct, "status_code", 0) or 0),
        "matched_markers": [basis] if basis and basis != "none" else [],
    }


def _followup_scope_finding(target: str, followup_inputs: dict[str, object]) -> Finding:
    evidence_parts = [
        "This SSRF triage step consumed upstream route and artifact hints.",
        _format_values("api_paths", followup_inputs.get("api_paths", [])),
        _format_values("auth_paths", followup_inputs.get("auth_paths", [])),
        _format_values("download_export_paths", followup_inputs.get("download_export_paths", [])),
        _format_values("upload_import_paths", followup_inputs.get("upload_import_paths", [])),
        _format_values("config_entrypoints", followup_inputs.get("config_entrypoints", [])),
        _format_values("controller_hints", followup_inputs.get("controller_hints", [])),
        _format_values("internal_urls", followup_inputs.get("internal_urls", [])),
    ]
    return Finding(
        title="Backup/JS-derived SSRF follow-up scope",
        severity="info",
        location=target,
        evidence="; ".join(part for part in evidence_parts if part),
        kind="scope",
        verification_status="informational",
        verified=False,
        recommendation="Prioritize import, preview, fetch, and webhook-like paths recovered from upstream artifacts and JS inventory.",
    )


def _build_ssrf_followup_context(findings: list[Finding], candidates: list[dict[str, str]]) -> dict[str, object]:
    high_risk_findings = [item.to_dict() for item in findings if item.verified and item.severity in {"critical", "high"}]
    confirmed_contexts = [
        dict(item.metadata.get("ssrf_context", {}))
        for item in findings
        if item.verified and isinstance(item.metadata.get("ssrf_context", {}), dict)
    ]
    return {
        "producer": "ssrf_triage",
        "high_risk_findings": high_risk_findings,
        "consumers": {
            "poc_verify": {
                "high_risk_findings": high_risk_findings,
                "ssrf_findings": confirmed_contexts,
            },
            "ssrf_triage": {
                "ssrf_candidates": [dict(item) for item in candidates[:20]],
            },
        },
    }


def _context_seed_urls(followup_inputs: dict[str, object]) -> list[str]:
    return _string_list(
        followup_inputs.get("api_paths", []),
        followup_inputs.get("auth_paths", []),
        followup_inputs.get("route_prefixes", []),
        followup_inputs.get("controller_hints", []),
        followup_inputs.get("config_entrypoints", []),
        followup_inputs.get("download_export_paths", []),
        followup_inputs.get("upload_import_paths", []),
        followup_inputs.get("internal_urls", []),
        followup_inputs.get("correlated_discovery_seeds", []),
        followup_inputs.get("relationship_followup_seeds", []),
    )


def _looks_like_url_parameter(parameter: str, values: list[str]) -> bool:
    lowered = parameter.lower()
    if lowered in URL_PARAMETER_NAMES:
        return True
    return any(
        value.lower().startswith(("http://", "https://", "ftp://", "gopher://")) or INTERNAL_HOST_RE.search(value or "")
        for value in values
    )


def _extract_links(html: str) -> list[str]:
    links: list[str] = []
    for match in LINK_RE.finditer(html or ""):
        value = unescape(match.group("url")).strip()
        if value and not value.startswith(("javascript:", "mailto:", "tel:")) and value not in links:
            links.append(value)
    return links


def _input_names(html: str) -> list[str]:
    names: list[str] = []
    for match in INPUT_RE.finditer(html or ""):
        attrs = match.group("attrs") or ""
        name_match = NAME_RE.search(attrs)
        if not name_match:
            continue
        names.append(unescape(name_match.group("value")).strip())
    return sorted({item for item in names if item})


def _append_same_origin_url(items: list[str], base_url: str, value: str) -> None:
    raw = str(value or "").strip()
    if not raw:
        return
    candidate = urljoin(base_url, raw)
    if not _same_origin(base_url, candidate):
        return
    if not is_local_or_lab_target(candidate):
        return
    if _looks_like_static_asset(candidate):
        return
    if candidate not in items:
        items.append(candidate)


def _url_interest_score(value: str) -> int:
    parsed = urlparse(value)
    text = f"{parsed.path}?{parsed.query}".lower()
    score = 0
    if any(term in text for term in ("ssrf", "fetch", "proxy", "webhook", "callback", "redirect", "remote", "import", "file", "include", "download", "avatar", "image", "preview", "oembed", "url", "uri")):
        score += 50
    query = parse_qs(parsed.query, keep_blank_values=True)
    if query:
        score += 20
    if any(name.lower() in URL_PARAMETER_NAMES for name in query):
        score += 80
    return score


def _looks_like_static_asset(value: str) -> bool:
    parsed = urlparse(value)
    path = parsed.path.lower()
    static_suffixes = (
        ".css",
        ".js",
        ".mjs",
        ".map",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
    )
    return not parsed.query and path.endswith(static_suffixes)


def _same_origin(left: str, right: str) -> bool:
    left_parsed = urlparse(left)
    right_parsed = urlparse(right)
    return (left_parsed.scheme, left_parsed.netloc) == (right_parsed.scheme, right_parsed.netloc)


def _html_title(text: str) -> str:
    match = TITLE_RE.search(text or "")
    if not match:
        return ""
    return compress_text(re.sub(r"<[^>]+>", " ", match.group("title")))


def _token_overlap(left: str, right: str) -> float:
    left_tokens = _content_tokens(left)
    right_tokens = _content_tokens(right)
    if not left_tokens or not right_tokens:
        return 0.0
    shared = left_tokens & right_tokens
    return len(shared) / max(len(left_tokens), 1)


def _content_tokens(text: str) -> set[str]:
    stripped = re.sub(r"(?is)<script\b.*?</script>|<style\b.*?</style>", " ", text or "")
    stripped = re.sub(r"(?is)<[^>]+>", " ", stripped)
    return {
        token.lower()
        for token in re.findall(r"[A-Za-z0-9_\-\u4e00-\u9fff]{3,}", stripped)
        if token.lower() not in {"html", "body", "script", "style", "div", "span", "class"}
    }


def _feature_hits(text: str) -> list[str]:
    return sorted(set(match.group(1).lower() for match in SSRF_FEATURE_RE.finditer(text or "")))


def _dedupe_candidates(candidates: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[dict[str, str]] = []
    for item in candidates:
        key = (
            str(item.get("request_url", "")).strip(),
            str(item.get("method", "GET")).strip().upper(),
            str(item.get("parameter", "")).strip(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    deduped: list[Finding] = []
    for item in findings:
        key = (item.title, item.location)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _string_list(*values: object) -> list[str]:
    collected: list[str] = []
    for value in values:
        if isinstance(value, list):
            for item in value:
                text = compress_text(str(item))
                if text and text not in collected:
                    collected.append(text)
        elif isinstance(value, str):
            text = compress_text(value)
            if text and text not in collected:
                collected.append(text)
    return collected


def _format_values(label: str, values: object) -> str:
    if not isinstance(values, list) or not values:
        return ""
    return f"{label}={', '.join(compress_text(str(item)) for item in values[:6])}"
