from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from ai_security_agent.shared_types import MCPServerSpec
from ai_security_agent.modules.backup_audit_extended.secret_scanner import scan_text_blob
from ai_security_agent.integrations.http import fetch_bytes as http_fetch_bytes
from ai_security_agent.integrations.js_runtime import run_js_helper
from ai_security_agent.integrations.mcp_client import MCPClient
from ai_security_agent.llm import LLMError, complete_json_object, create_provider_from_config
from ai_security_agent.schemas import Finding, ModuleResult

from .common import (
    compress_text,
    encode_text_preview,
    get_report_contract,
    get_skill_bundle,
    get_support_skills,
    is_local_or_lab_target,
    now_iso,
)
from .followup_bridge import extract_followup_inputs


SCRIPT_RE = re.compile(r"<script\b(?P<attrs>[^>]*)>(?P<body>.*?)</script>", re.IGNORECASE | re.DOTALL)
SRC_RE = re.compile(r"\bsrc\s*=\s*['\"](?P<src>[^'\"]+)['\"]", re.IGNORECASE)
IMPORT_RE = re.compile(
    r"""(?:
        \bimport\s+(?:[^'"()]+?\s+from\s+)?["'](?P<static>[^"']+\.m?js(?:\?[^"']*)?)["']
        |
        \bimport\s*\(\s*["'](?P<dynamic>[^"']+\.m?js(?:\?[^"']*)?)["']\s*\)
    )""",
    re.IGNORECASE | re.VERBOSE,
)
TITLE_RE = re.compile(r"<title\b[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
SOURCE_RE = re.compile(
    r"\b(location\.(?:hash|search|href)|document\.(?:URL|documentURI|referrer)|window\.name|event\.data|postMessage|localStorage|sessionStorage)\b",
    re.IGNORECASE,
)
DOM_SINK_RE = re.compile(
    r"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML|v-html)\b",
    re.IGNORECASE,
)
EXEC_SINK_RE = re.compile(r"\b(eval|Function|setTimeout|setInterval)\b", re.IGNORECASE)
SECRET_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd)\b"
)
ASSIGNMENT_SECRET_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd)\b"
    r"[^\n]{0,40}[:=][^\n]{0,120}['\"][^'\"]{6,}['\"]"
)
URL_SECRET_RE = re.compile(r"(?i)https?://[^\s'\"`?#]+[?&](?:token|key|secret|apikey)=[^\s'\"`&#]+")
API_PATH_RE = re.compile(
    r"['\"](?P<path>(?:https?://[^'\"]+)?/(?:api|graphql|rest|admin|auth|oauth|login|upload|export)[^'\"]*)['\"]",
    re.IGNORECASE,
)
ROUTE_LITERAL_RE = re.compile(
    r"""(?:
        \b(?:url|uri|path|route|endpoint|api|href)\b\s*[:=]\s*
        |
        \bnew\s+URL\s*\(\s*
        |
        \b(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|open)\s*\(\s*
    )["'](?P<path>(?:https?://[^"']+|/(?:api|graphql|rest|admin|auth|oauth|login|upload|export|user|users|manage|dashboard)[^"']*))["']
    """,
    re.IGNORECASE | re.VERBOSE,
)
MINIFIED_HINT_RE = re.compile(r"[A-Za-z0-9_$]{80,}")
LINE_BREAK_RE = re.compile(r"\r\n?|\n")

MAX_INLINE_SCRIPT_BYTES = 120_000
MAX_EXTERNAL_SCRIPT_BYTES = 220_000
MAX_SCRIPT_ANALYSIS = 12
MAX_FINDINGS = 18
DEFAULT_CHUNK_SIZE = 7_000
SUMMARY_CHUNK_SIZE = 2_400
NODE_HELPER = Path(__file__).resolve().parents[3] / "scripts" / "js_audit_node_helper.js"
JS_AUDIT_CACHE = Path(__file__).resolve().parents[3] / ".cache" / "js_audit_llm_cache.json"
safe_fetch_bytes = http_fetch_bytes


@dataclass(slots=True)
class ScriptArtifact:
    location: str
    source: str
    origin: str
    content_type: str
    parse_ok: bool
    beautified: str
    parse_error: str = ""
    bytes_fetched: int = 0


@dataclass(slots=True)
class StaticIssue:
    category: str
    title: str
    severity: str
    location: str
    evidence: str
    recommendation: str
    verified: bool = False
    confidence: str = "candidate"
    remediation: str = ""
    metadata: dict[str, Any] | None = None


def run(target: str, context: dict | None = None) -> ModuleResult:
    started = now_iso()
    if not is_local_or_lab_target(target):
        return ModuleResult(
            module="js_audit",
            target=target,
            status="skipped",
            findings=[],
            logs=["Target is outside the local/course-lab allowlist; JS audit skipped."],
            started_at=started,
            finished_at=now_iso(),
            error="only localhost or course lab targets are allowed",
        )

    skill_bundle = get_skill_bundle(context)
    support_skills = get_support_skills(context)
    report_contract = get_report_contract(context)
    llm_config = _llm_config(context)
    followup_inputs = extract_followup_inputs("js_audit", context)

    logs: list[str] = []
    findings: list[Finding] = []
    tool_records: list[dict[str, object]] = []

    page = safe_fetch_bytes(target, timeout_seconds=2.5, max_bytes=220_000)
    if not page.ok:
        findings.append(
            Finding(
                title="Frontend JavaScript audit checklist",
                severity="low",
                location=target,
                evidence=f"Page fetch unavailable for JS audit: {page.error or 'no response'}",
                kind="scope",
                verification_status="informational",
                verified=False,
                recommendation="Manually review script inventory, DOM sinks, client-side secrets, and dynamic execution paths.",
            )
        )
        return ModuleResult(
            module="js_audit",
            target=target,
            status="ok",
            findings=_append_followup(findings, target, followup_inputs),
            logs=_build_logs(logs, skill_bundle, support_skills, report_contract, llm_config, fetched=False),
            started_at=started,
            finished_at=now_iso(),
        )

    html = _exchange_text(page)
    title = _extract_title(html)
    logs.append(f"Fetched entry page for JS audit: HTTP {page.status_code}, title={title or 'n/a'}")

    scripts = _collect_scripts(target, html, logs, followup_inputs)
    if not scripts:
        findings.append(
            Finding(
                title="Frontend JavaScript inventory review",
                severity="low",
                location=target,
                evidence="No inline or external script content was collected from the current response.",
                kind="evidence",
                verification_status="informational",
                verified=False,
                recommendation="Confirm whether scripts are injected dynamically, protected by auth, or loaded through a later browser workflow.",
            )
        )
        return ModuleResult(
            module="js_audit",
            target=target,
            status="ok",
            findings=_append_followup(findings, target, followup_inputs),
            logs=_build_logs(logs, skill_bundle, support_skills, report_contract, llm_config, fetched=True),
            started_at=started,
            finished_at=now_iso(),
        )

    logs.append(f"Collected {len(scripts)} script artifacts for audit.")

    node_result = _run_node_helper(scripts, logs, context, tool_records)
    analysis_inputs = _merge_node_analysis(scripts, node_result, logs)
    static_issues = _run_static_analysis(analysis_inputs, logs)
    findings.extend(_issues_to_findings(static_issues))

    llm_findings, llm_logs = _run_llm_summary(target, analysis_inputs, static_issues, llm_config)
    findings.extend(llm_findings)
    logs.extend(llm_logs)

    findings = _dedupe_findings(findings)[:MAX_FINDINGS]
    if not findings:
        findings.append(
            Finding(
                title="Frontend JavaScript audit checklist",
                severity="low",
                location=target,
                evidence="No confirmed XSS, sensitive data, or eval-style execution risk was identified in the current script sample.",
                kind="scope",
                verification_status="informational",
                verified=False,
                recommendation="Retain manual review for minified bundles, deferred loaders, template rendering, and authenticated script paths.",
            )
        )

    findings = _append_followup(findings, target, followup_inputs)
    return ModuleResult(
        module="js_audit",
        target=target,
        status="ok",
        findings=findings[:MAX_FINDINGS],
        followup_context=_build_js_followup_context(static_issues, analysis_inputs, tool_records),
        logs=_build_logs(logs, skill_bundle, support_skills, report_contract, llm_config, fetched=True),
        started_at=started,
        finished_at=now_iso(),
    )


def _collect_scripts(target: str, html: str, logs: list[str], followup_inputs: dict[str, Any] | None = None) -> list[ScriptArtifact]:
    scripts: list[ScriptArtifact] = []
    external_urls: list[str] = []
    for index, match in enumerate(SCRIPT_RE.finditer(html), start=1):
        attrs = match.group("attrs") or ""
        body = match.group("body") or ""
        src_match = SRC_RE.search(attrs)
        if src_match:
            _append_same_origin_url(external_urls, target, src_match.group("src"))
            continue
        inline = body.strip()
        if not inline:
            continue
        scripts.append(
            ScriptArtifact(
                location=f"{target}#inline-script-{index}",
                source=inline[:MAX_INLINE_SCRIPT_BYTES],
                origin="inline",
                content_type="text/javascript",
                parse_ok=False,
                beautified="",
                bytes_fetched=len(inline.encode("utf-8", errors="replace")),
            )
        )
    for value in _followup_js_assets(followup_inputs):
        _append_same_origin_url(external_urls, target, value)

    checked_external: set[str] = set()
    while external_urls and len(scripts) < MAX_SCRIPT_ANALYSIS:
        script_url = external_urls.pop(0)
        if script_url in checked_external:
            continue
        checked_external.add(script_url)
        fetched = safe_fetch_bytes(
            script_url,
            timeout_seconds=2.0,
            max_bytes=MAX_EXTERNAL_SCRIPT_BYTES,
        )
        if not fetched.ok:
            logs.append(f"External script fetch failed: {script_url} ({fetched.error or fetched.status_code})")
            continue
        text = _exchange_text(fetched)
        scripts.append(
            ScriptArtifact(
                location=script_url,
                source=text,
                origin="external",
                content_type=(fetched.headers or {}).get("content-type", ""),
                parse_ok=False,
                beautified="",
                bytes_fetched=_exchange_content_len(fetched),
            )
        )
        for imported in _extract_import_urls(script_url, text):
            _append_same_origin_url(external_urls, target, imported)
    return scripts[:MAX_SCRIPT_ANALYSIS]


def _exchange_text(exchange: Any) -> str:
    value = getattr(exchange, "text", "")
    if callable(value):
        return str(value())
    return str(value or "")


def _exchange_content_len(exchange: Any) -> int:
    content = getattr(exchange, "content", None)
    if isinstance(content, (bytes, bytearray)):
        return len(content)
    body = getattr(exchange, "body", None)
    if isinstance(body, (bytes, bytearray)):
        return len(body)
    text = _exchange_text(exchange)
    return len(text.encode("utf-8", errors="replace"))


def _append_same_origin_url(values: list[str], target: str, raw_url: str) -> None:
    candidate = urljoin(target, str(raw_url or "").strip())
    if not candidate:
        return
    if not _same_origin(target, candidate):
        return
    if candidate not in values:
        values.append(candidate)


def _same_origin(base: str, candidate: str) -> bool:
    base_parsed = urlparse(base)
    candidate_parsed = urlparse(candidate)
    return (
        (base_parsed.scheme or "http").lower(),
        (base_parsed.hostname or "").lower(),
        base_parsed.port,
    ) == (
        (candidate_parsed.scheme or "http").lower(),
        (candidate_parsed.hostname or "").lower(),
        candidate_parsed.port,
    )


def _extract_import_urls(script_url: str, source: str) -> list[str]:
    urls: list[str] = []
    for match in IMPORT_RE.finditer(source or ""):
        raw = match.group("static") or match.group("dynamic") or ""
        if raw and raw not in urls:
            urls.append(urljoin(script_url, raw))
    return urls[:8]


def _followup_js_assets(followup_inputs: dict[str, Any] | None) -> list[str]:
    if not isinstance(followup_inputs, dict):
        return []
    values: list[str] = []
    for key in ("js_assets", "correlated_discovery_seeds", "relationship_followup_seeds"):
        raw = followup_inputs.get(key, [])
        if isinstance(raw, list):
            values.extend(str(item) for item in raw if str(item).strip())
    return values[:12]


def _run_node_helper(
    scripts: list[ScriptArtifact],
    logs: list[str],
    context: dict | None,
    tool_records: list[dict[str, object]],
) -> dict[str, Any]:
    if not NODE_HELPER.exists():
        logs.append(f"Node helper not found; AST/beautify analysis downgraded: {NODE_HELPER}")
        return {}

    mcp_server = _web_tools_server(context)
    if mcp_server is not None:
        merged_scripts: list[dict[str, object]] = []
        with MCPClient(mcp_server) as client:
            for item in scripts:
                result = client.call_tool("parse_js_ast", {"location": item.location, "source": item.source})
                tool_records.append(
                    {
                        "tool_name": "mcp:web-tools/parse_js_ast",
                        "arguments": {"location": item.location},
                        "result_summary": f"location={item.location}",
                        "status": "ok",
                    }
                )
                merged_scripts.append(
                    {
                        "location": item.location,
                        "beautified": str(result.get("script", {}).get("beautified", "") if isinstance(result.get("script"), dict) else ""),
                        "parse_ok": bool(result.get("script", {}).get("parse_ok", False) if isinstance(result.get("script"), dict) else False),
                        "parse_error": str(result.get("script", {}).get("parse_error", "") if isinstance(result.get("script"), dict) else ""),
                        "ast_summary": dict(result.get("script", {}).get("ast_summary", {}) if isinstance(result.get("script"), dict) else {}),
                        "dangerous_sinks": list(result.get("script", {}).get("dangerous_sinks", []) if isinstance(result.get("script"), dict) else []),
                        "prototype_pollution": list(result.get("script", {}).get("prototype_pollution", []) if isinstance(result.get("script"), dict) else []),
                        "sink_rules": dict(result.get("script", {}).get("sink_rules", {}) if isinstance(result.get("script"), dict) else {}),
                    }
                )
        logs.append("JS AST/beautify analysis executed through MCP web-tools server.")
        return {"parser": "mcp", "beautifier": "mcp", "scripts": merged_scripts}

    payload = {
        "scripts": [
            {
                "location": item.location,
                "source_b64": encode_text_preview(item.source, limit=MAX_EXTERNAL_SCRIPT_BYTES),
            }
            for item in scripts
        ]
    }
    try:
        data = run_js_helper("node", NODE_HELPER, payload, timeout_seconds=20.0)
    except Exception as exc:
        logs.append(f"Node AST/beautify helper unavailable: {exc}")
        return {}

    parser = str(data.get("parser", "")).strip()
    beautifier = str(data.get("beautifier", "")).strip()
    if parser:
        logs.append(f"AST parser status: {parser}")
    if beautifier:
        logs.append(f"Beautifier status: {beautifier}")
    return data


def _merge_node_analysis(
    scripts: list[ScriptArtifact],
    node_result: dict[str, Any],
    logs: list[str],
) -> list[dict[str, Any]]:
    by_location = {
        str(item.get("location", "")): item for item in node_result.get("scripts", []) if isinstance(item, dict)
    }
    merged: list[dict[str, Any]] = []
    for item in scripts:
        node_item = by_location.get(item.location, {})
        beautified = str(node_item.get("beautified", "")).strip() or item.source
        parse_error = compress_text(str(node_item.get("parse_error", "")).strip())
        parse_ok = bool(node_item.get("parse_ok", False))
        if parse_error:
            logs.append(f"AST parse warning: {item.location} -> {parse_error}")
        merged.append(
            {
                "location": item.location,
                "origin": item.origin,
                "content_type": item.content_type,
                "source": item.source,
                "beautified": beautified,
                "parse_ok": parse_ok,
                "parse_error": parse_error,
                "bytes_fetched": item.bytes_fetched,
                "ast_summary": dict(node_item.get("ast_summary", {})) if isinstance(node_item.get("ast_summary"), dict) else {},
                "dangerous_sinks": _normalize_node_evidence(node_item.get("dangerous_sinks")),
                "prototype_pollution": _normalize_node_evidence(node_item.get("prototype_pollution")),
                "sink_rules": _normalize_sink_rules(node_item.get("sink_rules")),
            }
        )
    return merged


def _run_static_analysis(scripts: list[dict[str, Any]], logs: list[str]) -> list[StaticIssue]:
    issues: list[StaticIssue] = []
    for script in scripts:
        location = str(script.get("location", ""))
        source = str(script.get("source", ""))
        beautified = str(script.get("beautified", "")) or source
        ast_summary = dict(script.get("ast_summary", {}))
        dangerous_sinks = _normalize_node_evidence(script.get("dangerous_sinks"))
        prototype_evidence = _normalize_node_evidence(script.get("prototype_pollution"))
        sink_rules = _normalize_sink_rules(script.get("sink_rules"))

        source_hits = sorted(set(match.group(1) for match in SOURCE_RE.finditer(beautified)))
        dom_sinks = sorted(set(match.group(1) for match in DOM_SINK_RE.finditer(beautified)))
        exec_sinks = sorted(set(match.group(1) for match in EXEC_SINK_RE.finditer(beautified)))
        dom_evidence = [item for item in dangerous_sinks if str(item.get("kind", "")).strip() == "dom"] + sink_rules.get("xss", [])
        exec_evidence = [item for item in dangerous_sinks if str(item.get("kind", "")).strip() == "exec"] + sink_rules.get("eval", [])
        secret_evidence = sink_rules.get("secret", [])
        api_rule_evidence = sink_rules.get("api_path", [])
        prototype_evidence = prototype_evidence + sink_rules.get("prototype_pollution", [])

        if source_hits and (dom_sinks or dom_evidence):
            issues.append(
                StaticIssue(
                    category="xss",
                    title="Client-side source-to-DOM XSS candidate",
                    severity="high",
                    location=location,
                    evidence=_join_evidence(
                        f"Sources={', '.join(source_hits[:6])}",
                        f"DOM sinks={', '.join(dom_sinks[:6])}" if dom_sinks else "",
                        _format_node_evidence_block("DOM sink evidence", dom_evidence),
                    ),
                    recommendation="Trace attacker-controlled values before DOM write operations and replace unsafe HTML sinks with text-only rendering.",
                    remediation="Replace innerHTML/outerHTML/document.write with textContent or DOM-safe rendering helpers.",
                    metadata=_js_context(
                        script,
                        category="dom_source_sink",
                        source=", ".join(source_hits[:4]),
                        sink=", ".join(dom_sinks[:4]) or _first_node_sink(dom_evidence),
                        line=_first_node_line(dom_evidence),
                    ),
                )
            )

        if exec_sinks or exec_evidence:
            ast_eval_calls = int(ast_summary.get("eval_calls", 0) or 0)
            ast_new_function = int(ast_summary.get("new_function_calls", 0) or 0)
            severity = "high" if ast_eval_calls or ast_new_function or "eval" in {item.lower() for item in exec_sinks} else "medium"
            issues.append(
                StaticIssue(
                    category="eval",
                    title="Dynamic code execution sink in JavaScript",
                    severity=severity,
                    location=location,
                    evidence=_join_evidence(
                        f"Execution sinks={', '.join(exec_sinks[:6])}" if exec_sinks else "",
                        f"ast.eval_calls={ast_eval_calls}; ast.new_function_calls={ast_new_function}",
                        _format_node_evidence_block("Execution sink evidence", exec_evidence),
                    ),
                    recommendation="Remove eval/new Function style execution where possible and ensure timers do not execute attacker-controlled strings.",
                    remediation="Replace eval/new Function/string timers with explicit function dispatch or safe parser logic.",
                    metadata=_js_context(
                        script,
                        category="dynamic_execution",
                        sink=", ".join(exec_sinks[:4]) or _first_node_sink(exec_evidence),
                        line=_first_node_line(exec_evidence),
                    ),
                )
            )

        secret_findings = _extract_secret_findings(location, beautified)
        if secret_findings:
            for secret in secret_findings:
                issues.append(
                    StaticIssue(
                        category="secret",
                        title="Verified hard-coded sensitive information in JavaScript",
                        severity=str(secret.get("severity", "high") or "high"),
                        location=location,
                        evidence=_join_evidence(
                            f"rule_id={secret.get('rule_id', '')}",
                            f"line={secret.get('line', '-')}",
                            f"match_count={secret.get('match_count', 0)}",
                            f"sample={secret.get('sample', '')}",
                        ),
                        recommendation=str(secret.get("recommendation", "")),
                        verified=True,
                        confidence="confirmed",
                        remediation="Remove browser-shipped secrets; use server-issued short-lived tokens and rotate leaked material.",
                        metadata=_js_context(
                            script,
                            category="frontend_secret_exposure",
                            line=int(secret.get("line", 0) or 0),
                            masked_sample=str(secret.get("sample", "")),
                            rule_id=str(secret.get("rule_id", "")),
                        ),
                    )
                )
        elif secret_evidence:
            issues.append(
                StaticIssue(
                    category="secret",
                    title="Possible hard-coded sensitive information in JavaScript",
                    severity="high",
                    location=location,
                    evidence=_join_evidence(
                        _format_node_evidence_block("Secret-like symbol evidence", secret_evidence),
                    ),
                    recommendation="Move credentials to server-side storage, rotate exposed material, and avoid shipping secrets inside browser-delivered assets.",
                    remediation="Remove browser-shipped secrets; use server-issued short-lived tokens and rotate leaked material.",
                    metadata=_js_context(
                        script,
                        category="secret_identifier_candidate",
                        sink=_first_node_sink(secret_evidence),
                        line=_first_node_line(secret_evidence),
                    ),
                )
            )

        regex_proto_lines = _extract_prototype_pollution_lines(beautified)
        if prototype_evidence or regex_proto_lines:
            issues.append(
                StaticIssue(
                    category="prototype_pollution",
                    title="Prototype pollution candidate in JavaScript",
                    severity="high" if prototype_evidence else "medium",
                    location=location,
                    evidence=_join_evidence(
                        f"ast.prototype_pollution_candidates={int(ast_summary.get('prototype_pollution_candidates', 0) or 0)}",
                        _format_node_evidence_block("Prototype mutation evidence", prototype_evidence),
                        " | ".join(regex_proto_lines[:3]) if regex_proto_lines else "",
                    ),
                    recommendation="Reject __proto__/constructor/prototype keys in merge paths and avoid mutating prototype chains from untrusted input.",
                    remediation="Block __proto__/prototype/constructor keys in merge utilities and prefer Object.create(null) for untrusted maps.",
                    metadata=_js_context(
                        script,
                        category="prototype_pollution_candidate",
                        sink=_first_node_sink(prototype_evidence) or "prototype mutation",
                        line=_first_node_line(prototype_evidence),
                    ),
                )
            )

        api_paths = _extract_api_paths(beautified) + _extract_route_literals(beautified) + [
            item.get("sink", "") for item in api_rule_evidence if compress_text(str(item.get("sink", "")))
        ]
        api_paths = _dedupe_strings(api_paths)
        if api_paths:
            issues.append(
                StaticIssue(
                    category="api_path",
                    title="Exposed backend path in frontend JavaScript",
                    severity="low",
                    location=location,
                    evidence=", ".join(api_paths[:8]),
                    recommendation="Validate authn/authz on exposed routes and ensure debug or admin endpoints are not reachable from untrusted contexts.",
                    remediation="Reconfirm authz on surfaced routes and remove dead/debug/admin endpoints from browser bundles where possible.",
                    metadata=_js_context(script, category="api_path_hint", api_path=", ".join(api_paths[:8])),
                )
            )

        if not source_hits and not dom_sinks and not exec_sinks and MINIFIED_HINT_RE.search(source):
            logs.append(f"Minified bundle detected: {location}")
    return issues


def _extract_secret_lines(source: str) -> list[str]:
    values: list[str] = []
    for line_number, line in enumerate(LINE_BREAK_RE.split(source), start=1):
        text = compress_text(line)
        if not text:
            continue
        if ASSIGNMENT_SECRET_RE.search(text) or URL_SECRET_RE.search(text):
            values.append(f"L{line_number}: {text[:220]}")
            continue
        if SECRET_RE.search(text) and ("=" in text or ":" in text):
            quoted = re.findall(r"['\"][^'\"]{6,}['\"]", text)
            if quoted:
                values.append(f"L{line_number}: {text[:220]}")
    return values


def _extract_secret_findings(location: str, source: str) -> list[dict[str, Any]]:
    matches = scan_text_blob(location, location, source, max_findings=6)
    results: list[dict[str, Any]] = []
    for match in matches:
        raw_match = _first_regex_match_for_rule(match.rule_id, source)
        line_number = _line_number_for_index(source, raw_match.start()) if raw_match else 0
        results.append(
            {
                "rule_id": match.rule_id,
                "title": match.title,
                "severity": match.severity,
                "sample": match.sample,
                "match_count": match.match_count,
                "line": line_number,
                "recommendation": match.recommendation,
            }
        )
    return results


def _first_regex_match_for_rule(rule_id: str, source: str):
    try:
        from ai_security_agent.modules.backup_audit_extended.secret_scanner import SECRET_RULES
    except Exception:
        return None
    for rule in SECRET_RULES:
        if rule.id == rule_id:
            return rule.regex.search(source)
    return None


def _line_number_for_index(source: str, index: int) -> int:
    return source[: max(index, 0)].count("\n") + 1


def _extract_api_paths(source: str) -> list[str]:
    values: list[str] = []
    for match in API_PATH_RE.finditer(source):
        path = compress_text(match.group("path"))
        if not path:
            continue
        if len(path) > 220:
            path = path[:220]
        if path not in values:
            values.append(path)
    return values


def _extract_route_literals(source: str) -> list[str]:
    values: list[str] = []
    for match in ROUTE_LITERAL_RE.finditer(source):
        path = compress_text(match.group("path"))
        if not path:
            continue
        if len(path) > 220:
            path = path[:220]
        if path not in values:
            values.append(path)
    return values


def _extract_prototype_pollution_lines(source: str) -> list[str]:
    values: list[str] = []
    proto_patterns = (
        "__proto__",
        "constructor.prototype",
        "Object.setPrototypeOf",
        "Reflect.setPrototypeOf",
    )
    for line_number, line in enumerate(LINE_BREAK_RE.split(source), start=1):
        text = compress_text(line)
        if not text:
            continue
        if any(pattern in text for pattern in proto_patterns):
            values.append(f"L{line_number}: {text[:220]}")
    return values


def _normalize_node_evidence(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    normalized: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        entry = {
            "kind": compress_text(str(item.get("kind", ""))),
            "sink": compress_text(str(item.get("sink", ""))),
            "detail": compress_text(str(item.get("detail", ""))),
            "line": int(item.get("line", 0) or 0),
            "column": int(item.get("column", 0) or 0),
            "end_line": int(item.get("end_line", 0) or 0),
            "end_column": int(item.get("end_column", 0) or 0),
            "snippet": compress_text(str(item.get("snippet", "")))[:220],
        }
        if entry["sink"] or entry["snippet"]:
            normalized.append(entry)
    return normalized


def _format_node_evidence_block(label: str, items: list[dict[str, Any]], *, limit: int = 3) -> str:
    if not items:
        return ""
    rendered = [_format_node_evidence_item(item) for item in items[:limit] if _format_node_evidence_item(item)]
    return f"{label}={' | '.join(rendered)}" if rendered else ""


def _format_node_evidence_item(item: dict[str, Any]) -> str:
    sink = compress_text(str(item.get("sink", ""))) or "sink"
    detail = compress_text(str(item.get("detail", "")))
    line = int(item.get("line", 0) or 0)
    column = int(item.get("column", 0) or 0)
    snippet = compress_text(str(item.get("snippet", "")))
    prefix = f"{sink}@L{line}:C{column}" if line and column else sink
    if detail:
        prefix = f"{prefix} ({detail})"
    return f"{prefix} `{snippet}`" if snippet else prefix


def _issues_to_findings(issues: list[StaticIssue]) -> list[Finding]:
    return [
        Finding(
            title=item.title,
            severity=item.severity,
            location=item.location,
            evidence=_join_evidence(item.evidence, f"remediation={item.remediation}" if item.remediation else ""),
            kind="vulnerability" if item.verified else "candidate",
            verification_status="confirmed" if item.verified else "unconfirmed",
            verified=item.verified,
            recommendation=item.recommendation,
            metadata=dict(item.metadata or {}),
        )
        for item in issues
    ]


def _js_context(
    script: dict[str, Any],
    *,
    category: str,
    source: str = "",
    sink: str = "",
    api_path: str = "",
    line: int = 0,
    masked_sample: str = "",
    rule_id: str = "",
) -> dict[str, Any]:
    return {
        "js_context": {
            "script": str(script.get("location", "")),
            "origin": str(script.get("origin", "")),
            "content_type": str(script.get("content_type", "")),
            "category": category,
            "line": int(line or 0),
            "source": source,
            "sink": sink,
            "api_path": api_path,
            "masked_sample": masked_sample,
            "rule_id": rule_id,
        }
    }


def _first_node_sink(items: list[dict[str, Any]]) -> str:
    return compress_text(str(items[0].get("sink", ""))) if items else ""


def _first_node_line(items: list[dict[str, Any]]) -> int:
    return int(items[0].get("line", 0) or 0) if items else 0


def _run_llm_summary(
    target: str,
    scripts: list[dict[str, Any]],
    static_issues: list[StaticIssue],
    llm_config: dict[str, Any],
) -> tuple[list[Finding], list[str]]:
    logs: list[str] = []
    if not bool(llm_config.get("enabled", False)):
        logs.append("LLM summary skipped: profile llm.enabled is false.")
        return [], logs

    provider = create_provider_from_config(type("Cfg", (), llm_config)(), agent_mode="full_agent")
    if provider is None:
        logs.append("LLM summary skipped: provider is not available for current configuration.")
        return [], logs

    cache_key = _build_llm_cache_key(target, scripts, static_issues, llm_config)
    cached = _load_llm_cache().get(cache_key)
    if isinstance(cached, dict):
        logs.append("LLM summary cache hit for js_audit.")
        findings = _parse_llm_json_findings(cached)
        return findings[:4], logs

    try:
        payload = complete_json_object(
            provider,
            _build_summary_prompt(target, scripts, static_issues),
            model_id=str(llm_config.get("model_id", "")).strip(),
            max_tokens=1200,
            schema_hint=_llm_summary_schema_hint(),
        )
    except LLMError as exc:
        logs.append(f"LLM final summary failed: {exc}")
        return [], logs

    provider_name = str(llm_config.get("provider_name", "")).strip() or "llm"
    logs.append(f"LLM summary provider used: {provider_name}/{str(llm_config.get('model_id', '')).strip()}")
    _store_llm_cache_entry(cache_key, payload)
    findings = _parse_llm_json_findings(payload)
    if findings:
        logs.append(f"LLM structured review kept {len(findings)} candidate finding(s).")
    return findings[:4], logs


def _build_chunk_prompt(target: str, script: dict[str, Any]) -> str:
    source = str(script.get("beautified", "") or script.get("source", ""))[:DEFAULT_CHUNK_SIZE]
    ast_summary = json.dumps(script.get("ast_summary", {}), ensure_ascii=False)
    return (
        "You are auditing browser-delivered JavaScript for a controlled security lab.\n"
        "Focus only on these categories: xss, sensitive_info, eval.\n"
        "Return concise Chinese bullet points. Do not fabricate exploitation.\n\n"
        f"Target: {target}\n"
        f"Script: {script.get('location', '')}\n"
        f"Origin: {script.get('origin', '')}\n"
        f"AST summary: {ast_summary}\n"
        "Code snippet:\n"
        f"{source}"
    )


def _build_summary_prompt(
    target: str,
    scripts: list[dict[str, Any]],
    static_issues: list[StaticIssue],
) -> str:
    static_lines = [json.dumps(_static_issue_to_dict(item), ensure_ascii=False) for item in static_issues[:10]]
    script_lines = [json.dumps(_script_summary_for_prompt(item), ensure_ascii=False) for item in scripts[:8]]
    return (
        "You are reviewing browser-delivered JavaScript for a controlled security lab.\n"
        "Focus on categories: xss, sensitive_info, eval, prototype_pollution.\n"
        "Filter false positives aggressively.\n"
        "Return ONE JSON object only.\n"
        "Every finding must stay verified=false unless the provided evidence itself proves reproducibility.\n\n"
        f"Target: {target}\n"
        "Static findings JSON lines:\n"
        f"{chr(10).join(static_lines) or '- none'}\n"
        "Script inventory JSON lines:\n"
        f"{chr(10).join(script_lines) or '- none'}\n"
        "Output fields:\n"
        "{"
        '"summary":"中文总结",'
        '"findings":[{"category":"xss|sensitive_info|eval|prototype_pollution","severity":"high|medium|low","location":"...","title":"中文标题","evidence":"中文证据","recommendation":"中文建议","remediation":"中文修复建议","confidence":"candidate|supported|rejected","keep":true,"false_positive_reason":""}]'
        "}"
    )


def _parse_llm_json_findings(payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    raw_findings = payload.get("findings", [])
    if not isinstance(raw_findings, list):
        return findings
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        if not bool(item.get("keep", False)):
            continue
        confidence = compress_text(str(item.get("confidence", ""))).lower() or "candidate"
        if confidence == "rejected":
            continue
        category = compress_text(str(item.get("category", ""))).lower()
        severity = compress_text(str(item.get("severity", ""))).lower()
        location = compress_text(str(item.get("location", "")))
        title = compress_text(str(item.get("title", "")))
        evidence = compress_text(str(item.get("evidence", "")))
        recommendation = compress_text(str(item.get("recommendation", "")))
        remediation = compress_text(str(item.get("remediation", "")))
        if severity not in {"high", "medium", "low"}:
            continue
        if category not in {"xss", "sensitive_info", "eval", "prototype_pollution"}:
            continue
        findings.append(
            Finding(
                title=title or f"LLM {category} finding",
                severity=severity,
                location=location,
                evidence=_join_evidence(
                    evidence,
                    f"confidence={confidence}",
                    f"remediation={remediation}" if remediation else "",
                ),
                verified=False,
                recommendation=recommendation,
            )
        )
    return findings


def _append_followup(findings: list[Finding], target: str, followup_inputs: dict[str, Any]) -> list[Finding]:
    if followup_inputs:
        findings.append(_followup_scope_finding(target, followup_inputs))
    return findings


def _followup_scope_finding(target: str, followup_inputs: dict[str, Any]) -> Finding:
    return Finding(
        title="Backup-derived JavaScript follow-up scope",
        severity="info",
        location=target,
        evidence=_join_evidence(
            "This follow-up module was seeded from upstream backup_audit_extended frontend hints.",
            _format_values("js_assets", followup_inputs.get("js_assets", [])),
            _format_values("api_paths", followup_inputs.get("api_paths", [])),
            _format_values("framework_routes", followup_inputs.get("framework_routes", [])),
            _format_values("route_prefixes", followup_inputs.get("route_prefixes", [])),
            _format_values("controller_hints", followup_inputs.get("controller_hints", [])),
            _format_values("config_entrypoints", followup_inputs.get("config_entrypoints", [])),
            _format_values("download_export_paths", followup_inputs.get("download_export_paths", [])),
            _format_values("upload_import_paths", followup_inputs.get("upload_import_paths", [])),
            _format_values("artifact_name_hints", followup_inputs.get("artifact_name_hints", [])),
            _format_values("frameworks", followup_inputs.get("frameworks", [])),
            _format_values("source_paths", followup_inputs.get("source_paths", [])),
            _format_values("include_paths", followup_inputs.get("include_paths", [])),
            _format_values("correlated_discovery_seeds", followup_inputs.get("correlated_discovery_seeds", [])),
            _format_values("relationship_followup_seeds", followup_inputs.get("relationship_followup_seeds", [])),
            _format_values(
                "relationship_followup_items",
                _format_relationship_items(followup_inputs.get("relationship_followup_items", [])),
            ),
            _format_values("downloaded_artifacts", followup_inputs.get("downloaded_artifacts", [])),
            _format_values("exposed_artifacts", followup_inputs.get("exposed_artifacts", [])),
        ),
        kind="scope",
        verification_status="informational",
        verified=False,
        recommendation="Use recovered JS asset and route hints to prioritize later frontend review and backend linkage validation.",
    )


def _build_js_followup_context(
    static_issues: list[StaticIssue],
    scripts: list[dict[str, Any]],
    tool_records: list[dict[str, object]],
) -> dict[str, Any]:
    xss_candidates = [item.location for item in static_issues if item.category == "xss"]
    eval_candidates = [item.location for item in static_issues if item.category == "eval"]
    prototype_candidates = [item.location for item in static_issues if item.category == "prototype_pollution"]
    api_paths: list[str] = []
    secret_locations: list[str] = []
    js_assets = [str(item.get("location", "")) for item in scripts[:8] if str(item.get("location", "")).strip()]
    high_risk_findings = [
        {
            "title": item.title,
            "severity": item.severity,
            "location": item.location,
            "evidence": item.evidence,
            "verified": item.verified,
            "recommendation": item.recommendation,
        }
        for item in static_issues
        if item.severity in {"high", "critical"}
    ][:8]
    for item in static_issues:
        if item.category == "api_path":
            for token in item.evidence.split(","):
                token = compress_text(token)
                if token and token not in api_paths:
                    api_paths.append(token)
        if item.category == "secret" and item.location not in secret_locations:
            secret_locations.append(item.location)
    route_prefixes = _derive_route_prefixes(api_paths)
    auth_paths = [item for item in api_paths if re.search(r"/(?:admin|auth|oauth|login|user|role|permission)", item, re.IGNORECASE)]
    return {
        "producer": "js_audit",
        "tool_records": tool_records[:12],
        "js_assets": js_assets,
        "analysis_cache": {
            "llm_cache_enabled": True,
            "cache_file": str(JS_AUDIT_CACHE),
        },
        "script_inventory": [
            {
                "location": str(item.get("location", "")),
                "origin": str(item.get("origin", "")),
                "parse_ok": bool(item.get("parse_ok", False)),
                "ast_summary": dict(item.get("ast_summary", {})) if isinstance(item.get("ast_summary"), dict) else {},
                "dangerous_sinks": _normalize_node_evidence(item.get("dangerous_sinks"))[:3],
                "prototype_pollution": _normalize_node_evidence(item.get("prototype_pollution"))[:2],
                "sink_rules": _normalize_sink_rules(item.get("sink_rules")),
            }
            for item in scripts[:8]
        ],
        "ast_overview": _build_ast_overview(scripts),
        "xss_candidates": xss_candidates[:8],
        "eval_candidates": eval_candidates[:8],
        "prototype_pollution_candidates": prototype_candidates[:8],
        "secret_locations": secret_locations[:8],
        "api_paths": api_paths[:10],
        "route_prefixes": route_prefixes[:8],
        "auth_paths": auth_paths[:8],
        "high_risk_findings": high_risk_findings,
        "js_contexts": [
            dict(item.metadata.get("js_context", {}))
            for item in static_issues
            if isinstance(item.metadata, dict) and isinstance(item.metadata.get("js_context", {}), dict)
        ][:12],
        "consumers": {
            "xss_triage": {
                "js_assets": js_assets,
                "xss_candidates": xss_candidates[:8],
                "api_paths": api_paths[:10],
                "route_prefixes": route_prefixes[:8],
            },
            "ssrf_triage": {
                "js_assets": js_assets,
                "api_paths": api_paths[:10],
                "auth_paths": auth_paths[:8],
                "route_prefixes": route_prefixes[:8],
                "correlated_discovery_seeds": js_assets[:4],
                "high_risk_candidates": [
                    f"{item['title']}@{item['location']}" for item in high_risk_findings[:6]
                ],
            },
            "poc_verify": {
                "js_assets": js_assets,
                "api_paths": api_paths[:10],
                "high_risk_findings": high_risk_findings,
            },
            "permission_bypass": {
                "js_assets": js_assets,
                "api_paths": api_paths[:10],
                "auth_paths": auth_paths[:8],
                "route_prefixes": route_prefixes[:8],
                "correlated_discovery_seeds": js_assets[:4],
                "high_risk_candidates": [
                    f"{item['title']}@{item['location']}" for item in high_risk_findings[:6]
                ],
            },
        },
    }


def _build_ast_overview(scripts: list[dict[str, Any]]) -> dict[str, int]:
    overview = {
        "scripts_total": len(scripts),
        "parsed_scripts": 0,
        "eval_calls": 0,
        "new_function_calls": 0,
        "dom_sink_calls": 0,
        "prototype_pollution_candidates": 0,
        "dangerous_sink_count": 0,
        "tree_sitter_rule_hits": 0,
    }
    for item in scripts:
        if bool(item.get("parse_ok", False)):
            overview["parsed_scripts"] += 1
        ast_summary = item.get("ast_summary", {})
        if not isinstance(ast_summary, dict):
            continue
        for key in (
            "eval_calls",
            "new_function_calls",
            "dom_sink_calls",
            "prototype_pollution_candidates",
            "dangerous_sink_count",
        ):
            overview[key] += int(ast_summary.get(key, 0) or 0)
        sink_rules = item.get("sink_rules", {})
        if isinstance(sink_rules, dict):
            for value in sink_rules.values():
                if isinstance(value, list):
                    overview["tree_sitter_rule_hits"] += len(value)
    return overview


def _derive_route_prefixes(api_paths: list[str]) -> list[str]:
    prefixes: list[str] = []
    for path in api_paths:
        normalized = compress_text(path)
        if not normalized:
            continue
        match = re.search(r"(https?://[^/]+)?(?P<path>/.*)", normalized)
        route = match.group("path") if match else normalized
        segments = [segment for segment in route.split("/") if segment]
        if not segments:
            continue
        candidates = ["/" + segments[0]]
        if len(segments) >= 2:
            candidates.append("/" + "/".join(segments[:2]))
        for candidate in candidates:
            if candidate not in prefixes:
                prefixes.append(candidate)
    return prefixes


def _build_logs(
    logs: list[str],
    skill_bundle: dict[str, Any],
    support_skills: list[dict[str, Any]],
    report_contract: dict[str, Any],
    llm_config: dict[str, Any],
    *,
    fetched: bool,
) -> list[str]:
    items = list(logs)
    if skill_bundle:
        items.append(f"Skill guidance loaded: {skill_bundle.get('name', 'js-audit')}")
    if support_skills:
        items.append("Support skills: " + ", ".join(item.get("name", "support") for item in support_skills))
    if report_contract:
        items.append("Report contract section: " + ", ".join(str(item) for item in report_contract.get("sections", [])))
    provider_name = str(llm_config.get("provider_name", "")).strip() or "n/a"
    items.append(
        f"LLM config: enabled={bool(llm_config.get('enabled', False))}, provider={provider_name}, fetched_entry={fetched}"
    )
    return items or ["JS audit completed."]


def _web_tools_server(context: dict | None) -> MCPServerSpec | None:
    if not isinstance(context, dict):
        return None
    profile_config = dict(context.get("profile_config", {})) if isinstance(context.get("profile_config", {}), dict) else {}
    mcp = dict(profile_config.get("mcp", {})) if isinstance(profile_config.get("mcp", {}), dict) else {}
    if not mcp.get("enabled"):
        return None
    for item in mcp.get("servers", []):
        if isinstance(item, dict) and str(item.get("name", "")).strip() == "web-tools":
            return MCPServerSpec.from_dict(item)
    return None


def _llm_config(context: dict | None) -> dict[str, Any]:
    if not isinstance(context, dict):
        return {}
    value = context.get("llm_config", {})
    return dict(value) if isinstance(value, dict) else {}


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str]] = set()
    result: list[Finding] = []
    for item in findings:
        key = (item.title, item.severity, item.location, item.evidence)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _extract_title(html: str) -> str:
    match = TITLE_RE.search(html or "")
    return compress_text(match.group(1)) if match else ""


def _format_values(label: str, values: object) -> str:
    if not isinstance(values, list) or not values:
        return ""
    rendered = [compress_text(str(value)) for value in values if compress_text(str(value))]
    return f"{label}={', '.join(rendered[:6])}" if rendered else ""


def _join_evidence(*parts: str) -> str:
    return "; ".join(part for part in parts if part)


def _format_relationship_items(items: object) -> list[str]:
    if not isinstance(items, list):
        return []
    labels: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        seed = compress_text(str(item.get("seed", "")))
        if not seed:
            continue
        priority = compress_text(str(item.get("priority", "low"))) or "low"
        traits = compress_text(str(item.get("traits", "generic"))) or "generic"
        components = compress_text(str(item.get("components", seed))) or seed
        labels.append(f"{seed}:{priority}:{traits}:{components}")
    return labels


def _normalize_sink_rules(value: object) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(value, dict):
        return {}
    normalized: dict[str, list[dict[str, Any]]] = {}
    for key, items in value.items():
        if not isinstance(items, list):
            continue
        normalized[str(key)] = _normalize_node_evidence(items)
    return normalized


def _static_issue_to_dict(item: StaticIssue) -> dict[str, Any]:
    return {
        "category": item.category,
        "title": item.title,
        "severity": item.severity,
        "location": item.location,
        "evidence": item.evidence,
        "recommendation": item.recommendation,
        "verified": item.verified,
        "confidence": item.confidence,
        "remediation": item.remediation,
    }


def _script_summary_for_prompt(item: dict[str, Any]) -> dict[str, Any]:
    snippet = _redact_sensitive_js_text(str(item.get("beautified", "") or item.get("source", "")))
    return {
        "location": str(item.get("location", "")),
        "origin": str(item.get("origin", "")),
        "parse_ok": bool(item.get("parse_ok", False)),
        "ast_summary": dict(item.get("ast_summary", {})) if isinstance(item.get("ast_summary"), dict) else {},
        "dangerous_sinks": _normalize_node_evidence(item.get("dangerous_sinks"))[:3],
        "prototype_pollution": _normalize_node_evidence(item.get("prototype_pollution"))[:2],
        "sink_rules": _normalize_sink_rules(item.get("sink_rules")),
        "snippet": compress_text(snippet)[:1200],
    }


def _llm_summary_schema_hint() -> str:
    return (
        '{"summary":"中文总结","findings":['
        '{"category":"xss","severity":"high","location":"http://127.0.0.1/...","title":"中文标题","evidence":"中文证据",'
        '"recommendation":"中文建议","remediation":"中文修复建议","confidence":"supported","keep":true,"false_positive_reason":""}'
        "]}"
    )


def _build_llm_cache_key(
    target: str,
    scripts: list[dict[str, Any]],
    static_issues: list[StaticIssue],
    llm_config: dict[str, Any],
) -> str:
    payload = {
        "target": target,
        "model_id": str(llm_config.get("model_id", "")).strip(),
        "provider_name": str(llm_config.get("provider_name", "")).strip(),
        "scripts": [_script_summary_for_prompt(item) for item in scripts[:8]],
        "static_issues": [_static_issue_to_dict(item) for item in static_issues[:10]],
    }
    digest = hashlib.md5(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    return digest


def _load_llm_cache() -> dict[str, Any]:
    try:
        if not JS_AUDIT_CACHE.exists():
            return {}
        data = json.loads(JS_AUDIT_CACHE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _store_llm_cache_entry(cache_key: str, payload: dict[str, Any]) -> None:
    cache = _load_llm_cache()
    cache[cache_key] = payload
    JS_AUDIT_CACHE.parent.mkdir(parents=True, exist_ok=True)
    JS_AUDIT_CACHE.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")


def _dedupe_strings(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = compress_text(str(value))
        if text and text not in result:
            result.append(text)
    return result


def _redact_sensitive_js_text(source: str) -> str:
    text = str(source or "")
    text = re.sub(
        r"""(?i)\b(api[_-]?key|secret|token|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|pwd)\b(\s*[:=]\s*)['"][^'"]{3,}['"]""",
        lambda match: f"{match.group(1)}{match.group(2)}\"***\"",
        text,
    )
    text = re.sub(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})\b", "***", text)
    return text

