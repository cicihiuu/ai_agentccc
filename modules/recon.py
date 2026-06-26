from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

from ai_security_agent.integrations.http import fetch_text as http_fetch_text
from ai_security_agent.integrations.mcp_client import MCPClient
from ai_security_agent.schemas import Finding, ModuleResult
from ai_security_agent.shared_types import MCPServerSpec

from .common import get_report_contract, get_skill_bundle, get_support_skills, now_iso


STATIC_SUFFIXES = (
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
API_PATH_RE = re.compile(r"(?i)/(?:api|graphql|rest)(?:/|$)")
AUTH_PATH_RE = re.compile(r"(?i)/(?:admin|login|signin|sign-in|auth|account|user|users|member|dashboard|session)(?:/|$)")
DOWNLOAD_PATH_RE = re.compile(r"(?i)/(?:download|export|backup|dump|archive|report)(?:/|$)")
UPLOAD_PATH_RE = re.compile(r"(?i)/(?:upload|import|avatar|image|file|fetch|proxy|preview|webhook)(?:/|$)")
CONFIG_PATH_RE = re.compile(r"(?i)/(?:config|setup|install|debug|status|health|env)(?:/|$)")
INTERNAL_URL_RE = re.compile(r"(?i)https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|[a-z0-9.-]*\.internal)[^\"'<>\\s]*")
ROUTE_LITERAL_RE = re.compile(
    r"""(?ix)
    (?:
        \b(?:href|src|action)\s*=\s*["'](?P<html>[^"']+)["']
        |
        \b(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|open|new\s+URL)\s*\(\s*["'](?P<script>(?:https?://[^"']+|/[^"']+))["']
    )
    """
)
CONTROLLER_HINTS = {
    "api",
    "admin",
    "auth",
    "login",
    "signin",
    "account",
    "user",
    "users",
    "member",
    "profile",
    "dashboard",
    "upload",
    "import",
    "export",
    "download",
    "fetch",
    "proxy",
    "preview",
    "webhook",
    "config",
    "setup",
    "install",
    "debug",
    "health",
    "search",
    "report",
}


class ReconHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.title_parts: list[str] = []
        self.links: list[str] = []
        self.script_sources: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.script_count = 0
        self.form_count = 0
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = dict(attrs)
        if tag == "title":
            self.in_title = True
        elif tag == "a":
            href = attr_map.get("href")
            if href:
                self.links.append(href)
        elif tag == "script":
            self.script_count += 1
            src = attr_map.get("src")
            if src:
                self.script_sources.append(src)
        elif tag == "form":
            self.form_count += 1
            self._current_form = {
                "action": attr_map.get("action") or "",
                "method": str(attr_map.get("method") or "GET").upper(),
                "inputs": [],
            }
        elif tag in {"input", "textarea", "select"} and self._current_form is not None:
            name = str(attr_map.get("name") or "").strip()
            if not name:
                return
            self._current_form["inputs"].append(
                {
                    "name": name,
                    "type": str(attr_map.get("type") or tag).lower(),
                    "value": str(attr_map.get("value") or ""),
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False
        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self.in_title and data.strip():
            self.title_parts.append(data.strip())


def run(target: str, context: dict | None = None) -> ModuleResult:
    started = now_iso()
    parsed = urlparse(target)
    host = parsed.netloc or "unknown-host"
    path = parsed.path or "/"
    logs = ["Parsed target URL structure."]
    skill_bundle = get_skill_bundle(context)
    support_skills = get_support_skills(context)
    report_contract = get_report_contract(context)
    tool_records: list[dict[str, object]] = []
    fetch = _fetch_with_optional_mcp(target, context, tool_records)

    evidence_parts = [f"protocol={parsed.scheme or 'unknown'}", f"host={host}", f"path={path}"]
    followup_context: dict[str, Any] = {}
    if fetch.ok:
        parser = ReconHTMLParser()
        parser.feed(fetch.text)
        title = " ".join(parser.title_parts).strip() or "untitled"
        sample_links = _normalize_urls(target, parser.links, limit=10)
        normalized_forms = _normalize_forms(target, parser.forms, limit=10)
        sample_scripts = _same_origin_urls(target, parser.script_sources, limit=12)
        sample_forms = _format_form_samples(normalized_forms, limit=3)
        parameter_hints = _collect_parameter_hints(target, sample_links, normalized_forms)
        route_candidates = _collect_route_candidates(target, sample_links, normalized_forms, sample_scripts, fetch.text)
        api_paths = _filter_paths(route_candidates, API_PATH_RE)
        auth_paths = _filter_paths(route_candidates, AUTH_PATH_RE)
        download_export_paths = _filter_paths(route_candidates, DOWNLOAD_PATH_RE)
        upload_import_paths = _filter_paths(route_candidates, UPLOAD_PATH_RE)
        config_entrypoints = _filter_paths(route_candidates, CONFIG_PATH_RE)
        route_prefixes = _route_prefixes(route_candidates)
        controller_hints = _controller_hints(route_candidates)
        internal_urls = _collect_internal_urls(fetch.text, route_candidates)
        relationship_items = [
            {"seed": item, "reason": "recon_route_inventory", "source": "recon"}
            for item in route_candidates[:12]
        ]

        evidence_parts.extend(
            [
                f"http_status={fetch.status_code}",
                f"title={title}",
                f"forms={len(normalized_forms)}",
                f"links={len(parser.links)}",
                f"scripts={parser.script_count}",
                f"parameters={len(parameter_hints)}",
            ]
        )
        if sample_links:
            evidence_parts.append(f"sample_links={', '.join(sample_links[:3])}")
        if sample_scripts:
            evidence_parts.append(f"sample_scripts={', '.join(sample_scripts[:3])}")
        if sample_forms:
            evidence_parts.append(f"sample_forms={', '.join(sample_forms)}")
        if api_paths:
            evidence_parts.append(f"api_paths={', '.join(api_paths[:4])}")
        if auth_paths:
            evidence_parts.append(f"auth_paths={', '.join(auth_paths[:4])}")
        if route_prefixes:
            evidence_parts.append(f"route_prefixes={', '.join(route_prefixes[:6])}")

        followup_context = _build_followup_context(
            target=target,
            title=title,
            status_code=fetch.status_code,
            links=sample_links,
            forms=normalized_forms,
            parameters=parameter_hints,
            js_assets=sample_scripts,
            route_candidates=route_candidates,
            api_paths=api_paths,
            auth_paths=auth_paths,
            route_prefixes=route_prefixes,
            controller_hints=controller_hints,
            download_export_paths=download_export_paths,
            upload_import_paths=upload_import_paths,
            config_entrypoints=config_entrypoints,
            internal_urls=internal_urls,
            relationship_items=relationship_items,
            tool_records=tool_records,
        )
        logs.append(f"Fetched target entry page: HTTP {fetch.status_code}.")
        logs.append(
            "Recon inventory: "
            f"links={len(sample_links)}, forms={len(normalized_forms)}, scripts={len(sample_scripts)}, "
            f"routes={len(route_candidates)}, params={len(parameter_hints)}"
        )
    else:
        evidence_parts.append("http_fetch=not available")
        logs.append(f"Target page fetch failed or was skipped: {fetch.error or 'no response'}")
    if skill_bundle:
        logs.append(f"Loaded skill guidance: {skill_bundle.get('name', 'recon')}")
    if support_skills:
        logs.append("Support skills: " + ", ".join(item.get("name", "support") for item in support_skills))
    if report_contract:
        logs.append("Report contract sections: " + ", ".join(str(item) for item in report_contract.get("sections", [])))

    return ModuleResult(
        module="recon",
        target=target,
        status="ok",
        findings=[
            Finding(
                title="Target entrypoint and surface inventory",
                severity="info",
                location=target,
                evidence="; ".join(evidence_parts),
                kind="scope",
                verification_status="informational",
                verified=False,
                recommendation="Use the collected route, form, parameter, and script inventory as bounded seeds for downstream SQL, XSS, SSRF, authorization, and weak-password modules.",
            )
        ],
        logs=logs,
        followup_context=followup_context,
        started_at=started,
        finished_at=now_iso(),
    )


def _normalize_urls(base_url: str, values: list[str], *, limit: int) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        full_url = urljoin(base_url, value)
        if full_url in seen:
            continue
        seen.add(full_url)
        normalized.append(full_url)
        if len(normalized) >= limit:
            break
    return normalized


def _same_origin_urls(base_url: str, values: list[str], *, limit: int) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        full_url = urljoin(base_url, value)
        if not _same_origin(base_url, full_url):
            continue
        if full_url in seen:
            continue
        seen.add(full_url)
        normalized.append(full_url)
        if len(normalized) >= limit:
            break
    return normalized


def _normalize_forms(base_url: str, forms: list[dict[str, Any]], *, limit: int) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for form in forms:
        action = urljoin(base_url, str(form.get("action") or base_url))
        method = str(form.get("method") or "GET").upper()
        raw_inputs = form.get("inputs", [])
        inputs: list[str] = []
        input_types: dict[str, str] = {}
        if isinstance(raw_inputs, list):
            for item in raw_inputs:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "").strip()
                if not name:
                    continue
                if name not in inputs:
                    inputs.append(name)
                input_types[name] = str(item.get("type") or "text").lower()
        key = (action, method, tuple(inputs))
        if key in seen:
            continue
        seen.add(key)
        normalized.append(
            {
                "action": action,
                "method": method,
                "inputs": inputs,
                "input_types": input_types,
            }
        )
        if len(normalized) >= limit:
            break
    return normalized


def _format_form_samples(forms: list[dict[str, Any]], *, limit: int) -> list[str]:
    samples: list[str] = []
    for form in forms[:limit]:
        inputs = ",".join(str(item) for item in form.get("inputs", [])[:5])
        samples.append(f"{form.get('method', 'GET')} {form.get('action', '')} [{inputs}]")
    return samples


def _collect_parameter_hints(target: str, links: list[str], forms: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for name in parse_qs(urlparse(target).query, keep_blank_values=True):
        _append_unique(names, name)
    for link in links:
        for name in parse_qs(urlparse(link).query, keep_blank_values=True):
            _append_unique(names, name)
    for form in forms:
        for name in form.get("inputs", []):
            _append_unique(names, str(name))
    return names[:20]


def _collect_route_candidates(
    base_url: str,
    links: list[str],
    forms: list[dict[str, Any]],
    js_assets: list[str],
    html: str,
) -> list[str]:
    candidates: list[str] = []
    for link in links:
        _append_same_origin_route(candidates, base_url, link)
    for form in forms:
        _append_same_origin_route(candidates, base_url, str(form.get("action", "")))
    for script in js_assets:
        _append_same_origin_route(candidates, base_url, script, allow_static_js=True)
    for match in ROUTE_LITERAL_RE.finditer(html or ""):
        value = match.group("html") or match.group("script") or ""
        _append_same_origin_route(candidates, base_url, value)
    return candidates[:24]


def _append_same_origin_route(target: list[str], base_url: str, value: str, *, allow_static_js: bool = False) -> None:
    full_url = urljoin(base_url, value)
    if not _same_origin(base_url, full_url):
        return
    path = urlparse(full_url).path.lower()
    if path.endswith(STATIC_SUFFIXES) and not (allow_static_js and path.endswith(".js")):
        return
    _append_unique(target, full_url)


def _filter_paths(values: list[str], pattern: re.Pattern[str]) -> list[str]:
    return [item for item in values if pattern.search(urlparse(item).path)]


def _route_prefixes(values: list[str]) -> list[str]:
    prefixes: list[str] = []
    for value in values:
        segments = [item for item in urlparse(value).path.split("/") if item]
        if not segments:
            continue
        _append_unique(prefixes, f"/{segments[0]}")
        if len(segments) >= 2 and segments[0].lower() in CONTROLLER_HINTS:
            _append_unique(prefixes, f"/{segments[0]}/{segments[1]}")
    return prefixes[:12]


def _controller_hints(values: list[str]) -> list[str]:
    hints: list[str] = []
    for value in values:
        segments = [item.lower() for item in urlparse(value).path.split("/") if item]
        for segment in segments:
            if segment in CONTROLLER_HINTS:
                _append_unique(hints, segment)
    return hints[:12]


def _collect_internal_urls(html: str, routes: list[str]) -> list[str]:
    values: list[str] = []
    for match in INTERNAL_URL_RE.finditer(html or ""):
        _append_unique(values, match.group(0))
    for route in routes:
        parsed = urlparse(route)
        for query_values in parse_qs(parsed.query, keep_blank_values=True).values():
            for value in query_values:
                if INTERNAL_URL_RE.search(value):
                    _append_unique(values, value)
    return values[:12]


def _build_followup_context(
    *,
    target: str,
    title: str,
    status_code: int,
    links: list[str],
    forms: list[dict[str, Any]],
    parameters: list[str],
    js_assets: list[str],
    route_candidates: list[str],
    api_paths: list[str],
    auth_paths: list[str],
    route_prefixes: list[str],
    controller_hints: list[str],
    download_export_paths: list[str],
    upload_import_paths: list[str],
    config_entrypoints: list[str],
    internal_urls: list[str],
    relationship_items: list[dict[str, str]],
    tool_records: list[dict[str, object]],
) -> dict[str, Any]:
    correlated_discovery_seeds = route_candidates[:20]
    relationship_followup_seeds = route_candidates[:12]
    common = {
        "api_paths": api_paths,
        "auth_paths": auth_paths,
        "framework_routes": route_candidates,
        "route_prefixes": route_prefixes,
        "controller_hints": controller_hints,
        "correlated_discovery_seeds": correlated_discovery_seeds,
        "relationship_followup_seeds": relationship_followup_seeds,
        "relationship_followup_items": relationship_items,
    }
    return {
        "producer": "recon",
        "inventory": {
            "entry_url": target,
            "page_title": title,
            "http_status": status_code,
            "links": links,
            "forms": forms,
            "parameters": parameters,
            "js_assets": js_assets,
            "route_candidates": route_candidates,
        },
        "links": links,
        "forms": forms,
        "parameters": parameters,
        "js_assets": js_assets,
        "route_candidates": route_candidates,
        "api_paths": api_paths,
        "auth_paths": auth_paths,
        "route_prefixes": route_prefixes,
        "controller_hints": controller_hints,
        "download_export_paths": download_export_paths,
        "upload_import_paths": upload_import_paths,
        "config_entrypoints": config_entrypoints,
        "internal_urls": internal_urls,
        "correlated_discovery_seeds": correlated_discovery_seeds,
        "relationship_followup_seeds": relationship_followup_seeds,
        "relationship_followup_items": relationship_items,
        "tool_records": list(tool_records),
        "consumers": {
            "js_audit": {
                **common,
                "js_assets": js_assets,
                "config_entrypoints": config_entrypoints,
                "download_export_paths": download_export_paths,
                "upload_import_paths": upload_import_paths,
            },
            "sql_scan": {
                **common,
                "config_entrypoints": config_entrypoints,
            },
            "xss_triage": {
                "js_assets": js_assets,
                "api_paths": api_paths,
                "framework_routes": route_candidates,
                "route_prefixes": route_prefixes,
                "upload_import_paths": upload_import_paths,
                "download_export_paths": download_export_paths,
                "correlated_discovery_seeds": correlated_discovery_seeds,
            },
            "ssrf_triage": {
                **common,
                "download_export_paths": download_export_paths,
                "upload_import_paths": upload_import_paths,
                "config_entrypoints": config_entrypoints,
                "internal_urls": internal_urls,
            },
            "permission_bypass": {
                **common,
                "route_candidates": route_candidates,
                "internal_urls": internal_urls,
            },
            "weak_password": {
                "auth_paths": auth_paths,
                "api_paths": api_paths,
                "route_prefixes": route_prefixes,
                "correlated_discovery_seeds": correlated_discovery_seeds,
                "relationship_followup_seeds": relationship_followup_seeds,
            },
        },
    }


def _same_origin(base_url: str, candidate: str) -> bool:
    base = urlparse(base_url)
    parsed = urlparse(candidate)
    return parsed.scheme == base.scheme and parsed.netloc == base.netloc


def _append_unique(target: list[str], value: str) -> None:
    text = str(value or "").strip()
    if text and text not in target:
        target.append(text)


def _fetch_with_optional_mcp(target: str, context: dict | None, tool_records: list[dict[str, object]]):
    mcp_server = _web_tools_server(context)
    if mcp_server is None:
        exchange = http_fetch_text(target, timeout_seconds=4.0, max_bytes=180_000)
        return type("ReconFetch", (), {"ok": exchange.ok, "status_code": exchange.status_code, "text": exchange.text, "error": exchange.error})()
    with MCPClient(mcp_server) as client:
        fetched = client.call_tool("fetch_url", {"url": target, "timeout_seconds": 4.0})
        links = client.call_tool("extract_links", {"url": target})
    tool_records.append(
        {
            "tool_name": "mcp:web-tools/fetch_url",
            "arguments": {"url": target},
            "result_summary": f"status={fetched.get('status', 0)}",
            "status": "ok" if not fetched.get("error") else "failed",
        }
    )
    tool_records.append(
        {
            "tool_name": "mcp:web-tools/extract_links",
            "arguments": {"url": target},
            "result_summary": f"links={len(links.get('links', []))}",
            "status": "ok" if not links.get("error") else "failed",
        }
    )
    text = str(fetched.get("text", "") or "")
    if text and links.get("links"):
        text += "\n<!-- mcp-links:" + ",".join(str(item) for item in links.get("links", [])[:20]) + "-->"
    return type(
        "ReconFetch",
        (),
        {
            "ok": not fetched.get("error") and int(fetched.get("status", 0) or 0) > 0,
            "status_code": int(fetched.get("status", 0) or 0),
            "text": text,
            "error": str(fetched.get("error", "") or ""),
        },
    )()


def _web_tools_server(context: dict | None) -> MCPServerSpec | None:
    profile_config = dict((context or {}).get("profile_config", {})) if isinstance((context or {}).get("profile_config", {}), dict) else {}
    mcp = dict(profile_config.get("mcp", {})) if isinstance(profile_config.get("mcp", {}), dict) else {}
    if not mcp.get("enabled"):
        return None
    for item in mcp.get("servers", []):
        if not isinstance(item, dict):
            continue
        if str(item.get("name", "")).strip() == "web-tools":
            return MCPServerSpec.from_dict(item)
    return None
