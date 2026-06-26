from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from threading import Lock, RLock
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlencode, urljoin, urlparse, urlunparse

import requests

from ai_security_agent.integrations.docker_sandbox import run_poc_in_docker
from ai_security_agent.integrations.http import fetch_text
from ai_security_agent.modules.backup_audit_extended import run as run_backup_audit_extended
from ai_security_agent.modules.config_audit import run as run_config_audit
from ai_security_agent.modules.cors_audit import run as run_cors_audit
from ai_security_agent.modules.js_audit import run as run_js_audit
from ai_security_agent.modules.jwt_audit import run as run_jwt_audit
from ai_security_agent.modules.permission_bypass import run as run_permission_bypass
from ai_security_agent.modules.recon import run as run_recon
from ai_security_agent.modules.state_bootstrap import run as run_state_bootstrap
from ai_security_agent.modules.sql_bypass.adaptive_engine import SQLBypassAdaptiveEngine
from ai_security_agent.modules.sql_bypass.models import PayloadStrategy, SQLBypassCandidate
from ai_security_agent.modules.sql_bypass import run as run_sql_bypass
from ai_security_agent.modules.sql_scan import run as run_sql_scan
from ai_security_agent.modules.ssrf_triage import run as run_ssrf_triage
from ai_security_agent.modules.weak_password import run as run_weak_password
from ai_security_agent.modules.xss_triage import run as run_xss_triage

from .models import Artifact, Observation, now_iso


@dataclass(slots=True)
class ToolExecution:
    status: str
    summary: str
    payload: dict[str, Any]
    artifacts: list[Artifact]


ToolFn = Callable[[dict[str, Any], dict[str, Any]], ToolExecution]


class CallbackStore:
    def __init__(self) -> None:
        self._events: dict[str, list[dict[str, Any]]] = {}
        self._lock = Lock()

    def create(self, token: str) -> str:
        with self._lock:
            self._events.setdefault(token, [])
        return f"callback://{token}"

    def list_events(self, token: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._events.get(token, [])]

    def register_hit(self, token: str, payload: dict[str, Any]) -> None:
        with self._lock:
            self._events.setdefault(token, []).append(dict(payload))


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, requests.Session] = {}
        self._lock = Lock()

    def get(self, name: str) -> requests.Session:
        with self._lock:
            return self._sessions.setdefault(name, requests.Session())

    def save(self, name: str, session: requests.Session) -> None:
        with self._lock:
            self._sessions[name] = session

    def list_names(self) -> list[str]:
        with self._lock:
            return sorted(self._sessions.keys())


class BrowserStateStore:
    def __init__(self) -> None:
        self._states: dict[str, dict[str, Any]] = {}
        self._lock = RLock()

    def get(self, name: str) -> dict[str, Any]:
        with self._lock:
            state = self._states.setdefault(
                name,
                {
                    "session_name": name,
                    "current_url": "",
                    "dom": "",
                    "status_code": 0,
                    "console_logs": [],
                    "network_events": [],
                    "last_action": "",
                    "form_fields": {},
                    "created_at": now_iso(),
                    "updated_at": now_iso(),
                },
            )
            return state

    def update(self, name: str, **values: Any) -> dict[str, Any]:
        with self._lock:
            state = self.get(name)
            state.update(values)
            state["updated_at"] = now_iso()
            return state


def _safe_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-") or "artifact"


def _response_core(body: str) -> str:
    lowered = body.lower()
    markers = ["id='per_info'", 'id="per_info"', "class=\"notice\"", "class='notice'", "login success", "your username", "your password"]
    chunks = []
    for marker in markers:
        pos = lowered.find(marker)
        if pos >= 0:
            chunks.append(body[max(0, pos - 120) : pos + 800])
    if chunks:
        return "\n".join(chunks)
    stripped = re.sub(r"<script\b.*?</script>", "", body, flags=re.I | re.S)
    stripped = re.sub(r"<[^>]+>", " ", stripped)
    return re.sub(r"\s+", " ", stripped)[-1500:]


def _request_headers_from_legacy_context(context: dict[str, Any]) -> dict[str, str]:
    upstream = context.get("upstream_followup_context", {}) if isinstance(context, dict) else {}
    if not isinstance(upstream, dict):
        return {}
    bootstrap = upstream.get("state_bootstrap", {})
    if not isinstance(bootstrap, dict):
        return {}
    headers = bootstrap.get("request_headers", {})
    if not isinstance(headers, dict):
        request_context = bootstrap.get("request_context", {})
        headers = request_context.get("request_headers", {}) if isinstance(request_context, dict) else {}
    return {str(key): str(value) for key, value in headers.items() if str(key).strip() and str(value).strip()} if isinstance(headers, dict) else {}


def _xss_needs_fresh_auth_retry(result: Any) -> bool:
    findings = list(getattr(result, "findings", []) or [])
    if any(bool(getattr(item, "verified", False)) for item in findings):
        return False
    followup = getattr(result, "followup_context", {}) or {}
    consumers = followup.get("consumers", {}) if isinstance(followup, dict) else {}
    xss_context = consumers.get("xss_triage", {}) if isinstance(consumers, dict) else {}
    candidates = xss_context.get("xss_candidates", []) if isinstance(xss_context, dict) else []
    if isinstance(candidates, list) and candidates:
        return True
    for item in findings:
        metadata = getattr(item, "metadata", {}) or {}
        if metadata.get("candidate_count", 0):
            return True
    return False


class ToolRegistry:
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.callback_store = CallbackStore()
        self.session_store = SessionStore()
        self.browser_store = BrowserStateStore()
        self.tools: dict[str, ToolFn] = {
            "http_request": self._http_request,
            "response_diff": self._response_diff,
            "extract_links_from_html": self._extract_links_from_html,
            "extract_forms_from_html": self._extract_forms_from_html,
            "extract_parameters_from_response": self._extract_parameters_from_response,
            "replay_request_with_mutation": self._replay_request_with_mutation,
            "artifact_capture": self._artifact_capture,
            "create_callback_endpoint": self._create_callback_endpoint,
            "poll_callback_events": self._poll_callback_events,
            "run_poc_in_docker": self._run_poc_in_docker,
            "capture_request_response": self._capture_request_response,
            "fetch_candidate_file": self._fetch_candidate_file,
            "extract_archive": self._extract_archive,
            "parse_config": self._parse_config,
            "parse_js_ast": self._parse_js_ast,
            "extract_js_endpoints": self._extract_js_endpoints,
            "extract_fetch_calls": self._extract_fetch_calls,
            "extract_dom_sinks": self._extract_dom_sinks,
            "map_source_routes": self._map_source_routes,
            "grep_sensitive_patterns": self._grep_sensitive_patterns,
            "browser_action": self._browser_action,
            "session_store": self._session_action,
            "save_session": self._save_session,
            "load_session": self._load_session,
            "switch_session": self._switch_session,
            "clone_session": self._clone_session,
            "same_request_different_session_replay": self._same_request_different_session_replay,
            "create_identity": self._create_identity,
            "state_bootstrap_bridge": self._state_bootstrap_bridge,
            "compare_http_responses": self._compare_http_responses,
            "build_ssrf_probe_set": self._build_ssrf_probe_set,
            "replay_with_redirect_chain": self._replay_with_redirect_chain,
            "parser_confusion_probe": self._parser_confusion_probe,
            "discover_sql_candidates": self._discover_sql_candidates,
            "probe_sql_boolean": self._probe_sql_boolean,
            "generate_sql_bypass_plan": self._generate_sql_bypass_plan,
            "run_sql_bypass_probe": self._run_sql_bypass_probe,
            "generate_poc_verification_case": self._generate_poc_verification_case,
            "recon_bridge": self._recon_bridge,
            "sql_scan_bridge": self._sql_scan_bridge,
            "run_waf_bypass_strategy": self._sql_bypass_bridge,
            "run_sqlmap_safe": self._sql_bypass_bridge,
            "xss_triage_bridge": self._xss_bridge,
            "ssrf_triage_bridge": self._ssrf_bridge,
            "permission_bypass_bridge": self._permission_bridge,
            "weak_password_bridge": self._weak_password_bridge,
            "backup_audit_bridge": self._backup_bridge,
            "config_audit_bridge": self._config_bridge,
            "cors_audit_bridge": self._cors_bridge,
            "jwt_audit_bridge": self._jwt_bridge,
            "js_audit_bridge": self._js_bridge,
            "run_skill_deep_scan": self._run_skill_deep_scan,
        }

    def execute(self, tool_name: str, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        handler = self.tools.get(tool_name)
        if handler is None:
            raise ValueError(f"unknown tool: {tool_name}")
        return handler(arguments, context)

    def _module_context(self, context: dict[str, Any]) -> dict[str, Any]:
        legacy_context = dict(context.get("legacy_context", {}))
        profile = dict(context.get("profile", {})) if isinstance(context.get("profile", {}), dict) else {}
        if profile and "profile_config" not in legacy_context:
            legacy_context["profile_config"] = {
                "state_bootstrap": dict(profile.get("state_bootstrap", {})) if isinstance(profile.get("state_bootstrap", {}), dict) else {},
            }
        llm_config = legacy_context.get("llm_config")
        if isinstance(llm_config, dict) and llm_config:
            return legacy_context

        if not profile:
            return legacy_context

        enabled = bool(profile.get("llm_enabled", False))
        legacy_context["llm_config"] = {
            "enabled": enabled,
            "provider_name": str(profile.get("provider_name", "")).strip(),
            "model_id": str(profile.get("model_id", "")).strip(),
            "base_url": str(profile.get("base_url", "")).strip(),
            "api_key_env": str(profile.get("api_key_env", "")).strip(),
            "timeout_seconds": float(profile.get("timeout_seconds", 15.0) or 15.0),
            "max_retries": int(profile.get("max_retries", 2) or 0),
            "headers": dict(profile.get("headers", {})) if isinstance(profile.get("headers", {}), dict) else {},
        }
        return legacy_context

    def _extract_callback_tokens(self, value: str) -> list[str]:
        return re.findall(r"callback://([A-Za-z0-9._:-]+)", value)

    def _maybe_register_callback_hits(self, request_url: str, request_body: Any, response: requests.Response) -> list[str]:
        probe_tokens = set(self._extract_callback_tokens(request_url))
        probe_tokens.update(self._extract_callback_tokens(unquote(request_url)))
        if isinstance(request_body, str):
            probe_tokens.update(self._extract_callback_tokens(request_body))
            probe_tokens.update(self._extract_callback_tokens(unquote(request_body)))
        if not probe_tokens:
            return []
        response_markers: set[str] = set()
        header_value = str(response.headers.get("X-Agent-Callback-Hit", "")).strip()
        if header_value:
            response_markers.update(item.strip() for item in header_value.split(",") if item.strip())
        response_markers.update(re.findall(r"callback-hit:([A-Za-z0-9._:-]+)", response.text))
        confirmed = sorted(token for token in probe_tokens if token in response_markers)
        for token in confirmed:
            self.callback_store.register_hit(
                token,
                {
                    "token": token,
                    "source_url": response.url,
                    "status_code": response.status_code,
                    "confirmation": "response_marker",
                },
            )
        return confirmed

    def _artifact(self, *, kind: str, name: str, body: str, content_type: str = "text/plain", metadata: dict[str, Any] | None = None) -> Artifact:
        artifact_id = f"art-{_safe_name(name)}-{abs(hash((name, now_iso()))) % 1_000_000}"
        path = self.workspace / f"{artifact_id}.txt"
        path.write_text(body, encoding="utf-8")
        return Artifact(
            artifact_id=artifact_id,
            kind=kind,
            name=name,
            path=str(path),
            content_type=content_type,
            summary=body[:160],
            metadata=dict(metadata or {}),
        )

    def _http_request(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        url = str(arguments.get("url") or context.get("target") or "").strip()
        if not url:
            return ToolExecution("error", "缺少 url", {"error": "missing url"}, [])
        method = str(arguments.get("method", "GET")).upper()
        headers = dict(arguments.get("headers", {})) if isinstance(arguments.get("headers", {}), dict) else {}
        cookies = dict(arguments.get("cookies", {})) if isinstance(arguments.get("cookies", {}), dict) else {}
        data = arguments.get("body")
        follow_redirects = bool(arguments.get("follow_redirects", True))
        session_name = str(arguments.get("session_name", "")).strip()
        session = self.session_store.get(session_name or "default")
        if cookies:
            session.cookies.update(cookies)
        try:
            response = session.request(method, url, headers=headers, data=data, allow_redirects=follow_redirects, timeout=8)
        except requests.RequestException as exc:
            return ToolExecution("error", f"{method} {url} failed: {exc}", {"url": url, "status_code": 0, "body": "", "error": str(exc)}, [])
        callback_hits = self._maybe_register_callback_hits(url, data, response)
        payload = {
            "url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:120000],
            "truncated_body": response.text[:120000],
            "elapsed_ms": int(response.elapsed.total_seconds() * 1000),
            "callback_hits": callback_hits,
        }
        return ToolExecution("ok", f"{method} {url} -> HTTP {response.status_code}", payload, [])

    def _response_diff(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        before = str(arguments.get("before", ""))
        after = str(arguments.get("after", ""))
        if not before and "last_observation_payload" in context:
            before = str(context["last_observation_payload"].get("body", ""))
        added = max(len(after) - len(before), 0)
        removed = max(len(before) - len(after), 0)
        words_before = Counter(re.findall(r"\w+", before.lower()))
        words_after = Counter(re.findall(r"\w+", after.lower()))
        changed = sorted({word for word in set(words_before) | set(words_after) if words_before[word] != words_after[word]})[:12]
        payload = {"added_chars": added, "removed_chars": removed, "changed_tokens": changed}
        return ToolExecution("ok", f"response diff: +{added}/-{removed}, tokens={len(changed)}", payload, [])

    def _html_from_arguments(self, arguments: dict[str, Any], context: dict[str, Any]) -> str:
        html = str(arguments.get("html", "") or arguments.get("content", ""))
        if not html and isinstance(context.get("last_observation_payload"), dict):
            html = str(context["last_observation_payload"].get("body", ""))
        return html

    def _extract_links_from_html(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        html = self._html_from_arguments(arguments, context)
        base = str(arguments.get("base_url") or context.get("target") or "")
        raw_links = re.findall(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", html, flags=re.I)
        links = []
        for link in raw_links:
            absolute = urljoin(base, link)
            if absolute not in links:
                links.append(absolute)
        payload = {"links": links[:100], "count": len(links)}
        return ToolExecution("ok", f"extracted links={len(links)}", payload, [])

    def _extract_forms_from_html(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        html = self._html_from_arguments(arguments, context)
        base = str(arguments.get("base_url") or context.get("target") or "")
        forms = []
        for form_match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, flags=re.I | re.S):
            attrs = form_match.group(1)
            body = form_match.group(2)
            action = re.search(r"""action\s*=\s*["']([^"']+)["']""", attrs, flags=re.I)
            method = re.search(r"""method\s*=\s*["']([^"']+)["']""", attrs, flags=re.I)
            inputs = re.findall(r"""<(?:input|textarea|select)\b[^>]*name\s*=\s*["']([^"']+)["']""", body, flags=re.I)
            forms.append(
                {
                    "action": urljoin(base, action.group(1)) if action else base,
                    "method": (method.group(1).upper() if method else "GET"),
                    "inputs": sorted(set(inputs)),
                }
            )
        return ToolExecution("ok", f"extracted forms={len(forms)}", {"forms": forms, "count": len(forms)}, [])

    def _extract_parameters_from_response(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        html = self._html_from_arguments(arguments, context)
        url = str(arguments.get("url") or "")
        if not url and isinstance(context.get("last_observation_payload"), dict):
            url = str(context["last_observation_payload"].get("url", ""))
        params = set(parse_qs(urlparse(url).query).keys())
        params.update(re.findall(r"""name\s*=\s*["']([^"']+)["']""", html, flags=re.I))
        params.update(re.findall(r"""[?&]([A-Za-z_][A-Za-z0-9_-]*)=""", html))
        return ToolExecution("ok", f"extracted parameters={len(params)}", {"parameters": sorted(params), "url": url}, [])

    def _replay_request_with_mutation(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        url = str(arguments.get("url") or context.get("target") or "").strip()
        parameter = str(arguments.get("parameter", "")).strip()
        value = str(arguments.get("value", arguments.get("payload", "agent_probe")))
        if parameter:
            parsed = urlparse(url)
            method = str(arguments.get("method", "GET")).upper()
            if method == "POST":
                body_params = parse_qs(str(arguments.get("body", "")), keep_blank_values=True)
                body_params[parameter] = [value]
                arguments = {**arguments, "body": urlencode(body_params, doseq=True)}
            else:
                query = parse_qs(parsed.query, keep_blank_values=True)
                query[parameter] = [value]
                url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
        return self._http_request({**arguments, "url": url}, context)

    def _artifact_capture(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        name = str(arguments.get("name", "artifact")).strip() or "artifact"
        body = str(arguments.get("content", ""))
        if not body and "last_observation_payload" in context:
            last = context["last_observation_payload"]
            body = json.dumps(last, ensure_ascii=False, indent=2) if isinstance(last, dict) else str(last)
        artifact = self._artifact(kind=str(arguments.get("kind", "capture")), name=name, body=body)
        return ToolExecution("ok", f"captured artifact {name}", {"artifact_id": artifact.artifact_id, "path": artifact.path}, [artifact])

    def _create_callback_endpoint(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        token = str(arguments.get("token", "")).strip() or _safe_name(context.get("scan_id", "callback"))
        endpoint = self.callback_store.create(token)
        return ToolExecution("ok", f"created callback endpoint {endpoint}", {"token": token, "endpoint": endpoint}, [])

    def _poll_callback_events(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        token = str(arguments.get("token", "")).strip()
        events = self.callback_store.list_events(token)
        return ToolExecution("ok", f"callback events={len(events)}", {"token": token, "events": events, "hit_count": len(events)}, [])

    def _run_poc_in_docker(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        script = str(arguments.get("script", ""))
        if not script:
            return ToolExecution("error", "缺少 script", {"error": "missing script"}, [])
        env_names = [
            str(item).strip()
            for item in arguments.get("env_names", [])
            if str(item).strip()
        ] if isinstance(arguments.get("env_names", []), list) else []
        script_artifact = self._artifact(kind="poc_script", name="poc.py", body=script, content_type="text/x-python")
        artifacts_dir = self.workspace / "sandbox-artifacts"
        try:
            result = run_poc_in_docker(
                docker_binary=str(arguments.get("docker_binary", "docker")),
                image=str(arguments.get("image", "python:3.12-slim")),
                script_path=script_artifact.path,
                artifacts_dir=artifacts_dir,
                timeout_seconds=float(arguments.get("timeout_seconds", 20.0) or 20.0),
                env_names=env_names,
            )
        except FileNotFoundError as exc:
            return ToolExecution("error", "docker binary not found", {"error": str(exc)}, [script_artifact])
        payload = {
            "returncode": result.returncode,
            "stdout": result.stdout[:4000],
            "stderr": result.stderr[:2000],
            "timed_out": result.timed_out,
            "parsed": result.parsed or {},
            "source_finding_id": str(arguments.get("source_finding_id", "")).strip() or str(context.get("source_finding_id", "")).strip(),
        }
        return ToolExecution("ok" if result.ok else "error", f"docker poc rc={result.returncode}", payload, [script_artifact])

    def _capture_request_response(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        body = json.dumps(arguments, ensure_ascii=False, indent=2)
        artifact = self._artifact(kind="request_response", name="request-response", body=body, content_type="application/json")
        return ToolExecution("ok", "captured request/response record", {"artifact_id": artifact.artifact_id}, [artifact])

    def _fetch_candidate_file(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        target = str(arguments.get("target") or context.get("target") or "").strip()
        candidate = str(arguments.get("candidate", "")).strip()
        if not target or not candidate:
            return ToolExecution("error", "缺少 target/candidate", {"error": "missing target or candidate"}, [])
        url = urljoin(target if target.endswith("/") else target + "/", candidate.lstrip("/"))
        exchange = fetch_text(url, timeout_seconds=3.0, max_bytes=200_000)
        payload = {"url": url, "status_code": exchange.status_code, "ok": exchange.ok, "body": exchange.text[:12000], "error": exchange.error}
        return ToolExecution("ok" if exchange.ok else "error", f"fetch candidate {candidate}: HTTP {exchange.status_code}", payload, [])

    def _extract_archive(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        archive_path = Path(str(arguments.get("path", "")).strip())
        if not archive_path.exists():
            return ToolExecution("error", "归档不存在", {"error": "archive not found"}, [])
        output_dir = self.workspace / f"extract-{_safe_name(archive_path.stem)}"
        output_dir.mkdir(parents=True, exist_ok=True)
        command = ["tar", "-xf", str(archive_path), "-C", str(output_dir)]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        except FileNotFoundError:
            return ToolExecution("error", "当前环境缺少 tar", {"error": "tar not available"}, [])
        return ToolExecution("ok" if completed.returncode == 0 else "error", f"extract rc={completed.returncode}", {"stdout": completed.stdout, "stderr": completed.stderr, "output_dir": str(output_dir)}, [])

    def _parse_config(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        text = str(arguments.get("content", ""))
        if not text and arguments.get("path"):
            text = Path(str(arguments["path"])).read_text(encoding="utf-8", errors="ignore")
        pairs = {}
        for line in text.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                pairs[key.strip()] = value.strip()
        risky_keys = [key for key in pairs if any(marker in key.lower() for marker in ("secret", "token", "password", "debug", "key"))]
        return ToolExecution("ok", f"parsed config keys={len(pairs)} risky={len(risky_keys)}", {"pairs": pairs, "risky_keys": risky_keys}, [])

    def _parse_js_ast(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        source = str(arguments.get("source", ""))
        endpoint_candidates: list[str] = []
        patterns = [
            r"""(?:href|src|action)\s*=\s*["']([^"'#?][^"']*|/[^"']*)["']""",
            r"""fetch\s*\(\s*["']([^"']+)["']""",
            r"""axios\.(?:get|post|put|delete)\s*\(\s*["']([^"']+)["']""",
        ]
        for pattern in patterns:
            for match in re.findall(pattern, source, flags=re.IGNORECASE):
                candidate = str(match).strip()
                if not candidate or candidate.startswith(("javascript:", "#")):
                    continue
                if candidate not in endpoint_candidates:
                    endpoint_candidates.append(candidate)
        findings = {
            "eval_calls": len(re.findall(r"\beval\s*\(", source)),
            "inner_html": len(re.findall(r"\binnerHTML\b", source)),
            "dangerous_sources": len(re.findall(r"location\.(?:hash|search|href)", source)),
            "endpoint_candidates": endpoint_candidates[:12],
        }
        return ToolExecution("ok", "parsed js ast heuristics", findings, [])

    def _js_source(self, arguments: dict[str, Any], context: dict[str, Any]) -> str:
        source = str(arguments.get("source", "") or arguments.get("content", ""))
        if not source and isinstance(context.get("last_observation_payload"), dict):
            source = str(context["last_observation_payload"].get("body", ""))
        return source

    def _extract_js_endpoints(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        source = self._js_source(arguments, context)
        base = str(arguments.get("base_url") or context.get("target") or "")
        endpoints: list[str] = []
        for pattern in (
            r"""fetch\s*\(\s*["']([^"']+)["']""",
            r"""axios\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']""",
            r"""["']((?:/api|/v1|/v2|/admin|/user|/auth)[^"']*)["']""",
        ):
            for item in re.findall(pattern, source, flags=re.I):
                url = urljoin(base, str(item).strip())
                if url not in endpoints:
                    endpoints.append(url)
        return ToolExecution("ok", f"js endpoints={len(endpoints)}", {"endpoint_candidates": endpoints[:80], "count": len(endpoints)}, [])

    def _extract_fetch_calls(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        source = self._js_source(arguments, context)
        calls = []
        for match in re.finditer(r"""(fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["']([^"']+)["']""", source, flags=re.I):
            calls.append({"callee": match.group(1), "url": match.group(2), "offset": match.start()})
        return ToolExecution("ok", f"fetch calls={len(calls)}", {"fetch_calls": calls[:80], "count": len(calls)}, [])

    def _extract_dom_sinks(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        source = self._js_source(arguments, context)
        sinks = []
        for sink in ("innerHTML", "outerHTML", "document.write", "insertAdjacentHTML", "eval", "Function", "setTimeout"):
            for match in re.finditer(re.escape(sink), source):
                sinks.append({"sink": sink, "offset": match.start(), "excerpt": source[max(0, match.start() - 60) : match.start() + 100]})
        return ToolExecution("ok", f"dom sinks={len(sinks)}", {"dom_sinks": sinks[:80], "count": len(sinks)}, [])

    def _map_source_routes(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        source = self._js_source(arguments, context)
        routes = sorted(set(re.findall(r"""["'](/[A-Za-z0-9_./{}:-]{2,})["']""", source)))
        return ToolExecution("ok", f"source routes={len(routes)}", {"route_candidates": routes[:100], "count": len(routes)}, [])

    def _grep_sensitive_patterns(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        text = str(arguments.get("content", ""))
        if not text and arguments.get("path"):
            text = Path(str(arguments["path"])).read_text(encoding="utf-8", errors="ignore")
        patterns = [r"api[_-]?key", r"secret", r"token", r"password", r"AKIA[0-9A-Z]{16}"]
        hits = [pattern for pattern in patterns if re.search(pattern, text, flags=re.IGNORECASE)]
        return ToolExecution("ok", f"sensitive hits={len(hits)}", {"patterns": hits}, [])

    def _run_skill_deep_scan(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        skill = str(arguments.get("skill") or context.get("current_step") or "").strip()
        target = str(arguments.get("target") or context.get("target") or "").strip()
        if not skill or not target:
            return ToolExecution("error", "missing skill/target", {"error": "missing skill or target"}, [])
        from .skill_deep_scan import run_skill

        result = run_skill(skill, target, self.workspace / "skill-deep-scan" / _safe_name(skill))
        payload = result.to_dict()
        payload["verified_finding_count"] = len(result.verified_findings)
        payload["verification_record_count"] = len(result.verification_records)
        payload["candidate_count"] = len(result.candidates)
        payload["rejected_count"] = len(result.rejected_candidates)
        return ToolExecution(
            "ok" if result.status == "completed" else "error",
            f"skill deep scan {skill}: verified={len(result.verified_findings)} candidates={len(result.candidates)} rejected={len(result.rejected_candidates)}",
            payload,
            [],
        )

    def _browser_action(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        command = str(arguments.get("command", "goto")).strip() or "goto"
        session_name = str(arguments.get("session_name", "default")).strip() or "default"
        session = self.session_store.get(session_name)
        browser = self.browser_store.get(session_name)
        if command in {"open", "goto"}:
            execution = self._http_request({"url": arguments.get("url") or context.get("target"), "method": "GET", "session_name": session_name}, context)
            payload = dict(execution.payload)
            event = {
                "action": command,
                "method": "GET",
                "url": payload.get("url", arguments.get("url") or context.get("target")),
                "status_code": payload.get("status_code", 0),
            }
            network_events = list(browser.get("network_events", []))
            network_events.append(event)
            browser.update(
                {
                    "current_url": str(payload.get("url", "")),
                    "dom": str(payload.get("body", "")),
                    "status_code": int(payload.get("status_code", 0) or 0),
                    "last_action": command,
                    "network_events": network_events[-40:],
                }
            )
            return ToolExecution(
                execution.status,
                f"browser {command} -> HTTP {payload.get('status_code', 0)}",
                {
                    **payload,
                    "browser_session": session_name,
                    "current_url": browser.get("current_url", ""),
                    "dom_excerpt": str(browser.get("dom", ""))[:500],
                    "network_event_count": len(browser.get("network_events", [])),
                },
                execution.artifacts,
            )
        if command in {"fill_form", "fill", "submit"}:
            action_url = str(arguments.get("url") or context.get("target") or "").strip()
            fields = dict(arguments.get("fields", {})) if isinstance(arguments.get("fields", {}), dict) else {}
            if command in {"fill", "fill_form"}:
                form_fields = dict(browser.get("form_fields", {}))
                form_fields.update(fields)
                browser.update({"form_fields": form_fields, "last_action": command})
                return ToolExecution(
                    "ok",
                    f"browser filled fields={len(fields)}",
                    {"browser_session": session_name, "fields": sorted(form_fields.keys()), "current_url": browser.get("current_url", "")},
                    [],
                )
            if not fields:
                fields = dict(browser.get("form_fields", {}))
            response = session.post(action_url, data=fields, allow_redirects=True, timeout=8)
            event = {"action": "submit", "method": "POST", "url": response.url, "status_code": response.status_code, "field_count": len(fields)}
            network_events = list(browser.get("network_events", []))
            network_events.append(event)
            browser.update(
                {
                    "current_url": response.url,
                    "dom": response.text[:120000],
                    "status_code": response.status_code,
                    "last_action": command,
                    "network_events": network_events[-40:],
                }
            )
            return ToolExecution(
                "ok",
                f"form submitted -> HTTP {response.status_code}",
                {
                    "browser_session": session_name,
                    "url": response.url,
                    "status_code": response.status_code,
                    "body": response.text[:120000],
                    "submitted_fields": sorted(fields.keys()),
                    "network_event_count": len(browser.get("network_events", [])),
                },
                [],
            )
        if command == "click":
            selector = str(arguments.get("selector", "")).strip()
            event = {"action": "click", "selector": selector, "url": browser.get("current_url") or arguments.get("url") or context.get("target")}
            network_events = list(browser.get("network_events", []))
            network_events.append(event)
            browser.update({"last_action": command, "network_events": network_events[-40:]})
            return ToolExecution("ok", f"browser click {selector or '<unknown>'}", {"browser_session": session_name, **event}, [])
        if command == "execute_js":
            script = str(arguments.get("script", "") or arguments.get("js", ""))
            console_logs = list(browser.get("console_logs", []))
            result: Any = None
            if "document.body.innerHTML" in script or "document.documentElement.outerHTML" in script:
                result = str(browser.get("dom", ""))
            elif "location.href" in script:
                result = str(browser.get("current_url", ""))
            elif "console.log" in script:
                match = re.search(r"console\.log\((.*?)\)", script, flags=re.S)
                logged = match.group(1).strip("'\" ") if match else script[:120]
                console_logs.append({"level": "log", "message": logged, "source": "execute_js"})
            else:
                result = {"executed": True, "script_excerpt": script[:160]}
            browser.update({"console_logs": console_logs[-80:], "last_action": command})
            return ToolExecution(
                "ok",
                "browser execute_js",
                {"browser_session": session_name, "result": result, "console_log_count": len(browser.get("console_logs", []))},
                [],
            )
        if command == "get_dom":
            dom = str(browser.get("dom", ""))
            if not dom and isinstance(context.get("last_observation_payload"), dict):
                dom = str(context["last_observation_payload"].get("body", ""))
            return ToolExecution(
                "ok",
                f"browser dom bytes={len(dom)}",
                {"browser_session": session_name, "url": browser.get("current_url", ""), "dom": dom[:120000], "dom_length": len(dom)},
                [],
            )
        if command == "get_console_logs":
            events = list(browser.get("console_logs", []))
            return ToolExecution("ok", f"browser console logs={len(events)}", {"browser_session": session_name, "events": events, "count": len(events)}, [])
        if command == "get_network_events":
            events = list(browser.get("network_events", []))
            return ToolExecution("ok", f"browser network events={len(events)}", {"browser_session": session_name, "events": events, "count": len(events)}, [])
        if command == "wait_for_selector":
            selector = str(arguments.get("selector", "")).strip()
            dom = str(browser.get("dom", ""))
            found = bool(selector and (selector in dom or selector.lstrip("#.") in dom))
            browser.update({"last_action": command})
            return ToolExecution("ok", f"browser wait selector found={found}", {"browser_session": session_name, "selector": selector, "found": found}, [])
        if command == "get_cookies":
            cookies = requests.utils.dict_from_cookiejar(session.cookies)
            return ToolExecution("ok", f"cookies={len(cookies)}", {"cookies": cookies}, [])
        if command == "save_session":
            self.session_store.save(session_name, session)
            return ToolExecution("ok", f"saved session {session_name}", {"session_name": session_name}, [])
        if command == "load_session":
            session = self.session_store.get(session_name)
            cookies = requests.utils.dict_from_cookiejar(session.cookies)
            return ToolExecution("ok", f"loaded session {session_name}", {"session_name": session_name, "cookies": cookies}, [])
        if command == "screenshot":
            body = json.dumps(
                {
                    "browser_session": session_name,
                    "current_url": browser.get("current_url", context.get("target", "")),
                    "status_code": browser.get("status_code", 0),
                    "dom_excerpt": str(browser.get("dom", ""))[:1000],
                    "console_logs": browser.get("console_logs", [])[-10:],
                    "network_events": browser.get("network_events", [])[-10:],
                },
                ensure_ascii=False,
                indent=2,
            )
            artifact = self._artifact(kind="screenshot", name=f"browser-screenshot-{session_name}", body=body, content_type="application/json")
            browser.update({"last_action": command})
            return ToolExecution(
                "ok",
                "generated browser state screenshot artifact",
                {
                    "artifact_id": artifact.artifact_id,
                    "browser_session": session_name,
                    "current_url": browser.get("current_url", ""),
                    "network_event_count": len(browser.get("network_events", [])),
                    "console_log_count": len(browser.get("console_logs", [])),
                },
                [artifact],
            )
        return ToolExecution("error", f"unsupported browser command {command}", {"error": "unsupported browser command"}, [])

    def _session_action(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        action = str(arguments.get("action", "list")).strip() or "list"
        session_name = str(arguments.get("session_name", "default")).strip() or "default"
        if action == "list":
            return ToolExecution("ok", f"sessions={len(self.session_store.list_names())}", {"sessions": self.session_store.list_names()}, [])
        if action == "switch":
            session = self.session_store.get(session_name)
            return ToolExecution("ok", f"switched session {session_name}", {"session_name": session_name, "cookie_count": len(session.cookies)}, [])
        if action == "set_cookie":
            key = str(arguments.get("name", "")).strip()
            value = str(arguments.get("value", "")).strip()
            if not key:
                return ToolExecution("error", "缺少 cookie 名称", {"error": "missing cookie name"}, [])
            session = self.session_store.get(session_name)
            session.cookies.set(key, value)
            return ToolExecution("ok", f"set cookie for {session_name}", {"session_name": session_name, "cookie_name": key}, [])
        return ToolExecution("error", f"unsupported session action {action}", {"error": "unsupported session action"}, [])

    def _save_session(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        session_name = str(arguments.get("session_name", "default")).strip() or "default"
        session = self.session_store.get(session_name)
        self.session_store.save(session_name, session)
        return ToolExecution("ok", f"saved session {session_name}", {"session_name": session_name}, [])

    def _load_session(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        session_name = str(arguments.get("session_name", "default")).strip() or "default"
        session = self.session_store.get(session_name)
        return ToolExecution("ok", f"loaded session {session_name}", {"session_name": session_name, "cookies": requests.utils.dict_from_cookiejar(session.cookies)}, [])

    def _switch_session(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        return self._load_session(arguments, context)

    def _clone_session(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        source_name = str(arguments.get("source_session", arguments.get("session_name", "default"))).strip() or "default"
        target_name = str(arguments.get("target_session", f"{source_name}_clone")).strip() or f"{source_name}_clone"
        source = self.session_store.get(source_name)
        clone = requests.Session()
        clone.cookies.update(source.cookies)
        self.session_store.save(target_name, clone)
        return ToolExecution("ok", f"cloned session {source_name} -> {target_name}", {"source_session": source_name, "target_session": target_name}, [])

    def _same_request_different_session_replay(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        url = str(arguments.get("url") or context.get("target") or "").strip()
        method = str(arguments.get("method", "GET")).upper()
        sessions = arguments.get("sessions", ["user_a", "user_b"])
        session_names = [str(item) for item in sessions] if isinstance(sessions, list) else ["user_a", "user_b"]
        overrides = arguments.get("session_overrides", {})
        overrides = dict(overrides) if isinstance(overrides, dict) else {}
        responses = []
        for session_name in session_names[:4]:
            override = overrides.get(session_name, {})
            override = dict(override) if isinstance(override, dict) else {}
            execution = self._http_request(
                {
                    "url": url,
                    "method": method,
                    "session_name": session_name,
                    "headers": dict(override.get("headers", {})) if isinstance(override.get("headers", {}), dict) else {},
                    "cookies": dict(override.get("cookies", {})) if isinstance(override.get("cookies", {}), dict) else {},
                },
                context,
            )
            responses.append({"session_name": session_name, **execution.payload})
        diff = self._compare_http_responses({"before": responses[0] if responses else {}, "after": responses[1] if len(responses) > 1 else {}}, context)
        return ToolExecution("ok", f"replayed {len(responses)} sessions", {"responses": responses, "diff": diff.payload}, [])

    def _create_identity(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        prefix = str(arguments.get("prefix", "tester")).strip() or "tester"
        role = str(arguments.get("role", "user")).strip() or "user"
        identity_id = f"{_safe_name(prefix)}-{_safe_name(role)}"
        payload = {
            "identity_id": identity_id,
            "username": f"{identity_id}",
            "email": f"{identity_id}@agent.local",
            "password": "Passw0rd!23",
            "role": role,
        }
        return ToolExecution("ok", f"created test identity {identity_id}", payload, [])

    def _compare_http_responses(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        before = arguments.get("before", {})
        after = arguments.get("after", {})
        before_status = int(before.get("status_code", 0)) if isinstance(before, dict) else 0
        after_status = int(after.get("status_code", 0)) if isinstance(after, dict) else 0
        before_body = str(before.get("body", "")) if isinstance(before, dict) else ""
        after_body = str(after.get("body", "")) if isinstance(after, dict) else ""
        status_changed = before_status != after_status
        added = max(len(after_body) - len(before_body), 0)
        removed = max(len(before_body) - len(after_body), 0)
        shared_prefix = 0
        for left, right in zip(before_body, after_body):
            if left != right:
                break
            shared_prefix += 1
        payload = {
            "before_status": before_status,
            "after_status": after_status,
            "status_changed": status_changed,
            "added_chars": added,
            "removed_chars": removed,
            "shared_prefix": shared_prefix,
            "suspicious_difference": status_changed or abs(len(after_body) - len(before_body)) > 40,
        }
        return ToolExecution("ok", "compared authorization responses", payload, [])

    def _build_ssrf_probe_set(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        callback = str(arguments.get("callback") or arguments.get("endpoint") or "")
        if not callback:
            token = str(arguments.get("token") or context.get("scan_id") or "ssrf")
            callback = self.callback_store.create(token)
        probes = [
            callback,
            f"https://example.invalid/redirect?next={callback}",
            "http://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            f"http://localhost@{urlparse(callback).netloc or 'callback.local'}/",
        ]
        return ToolExecution("ok", f"ssrf probes={len(probes)}", {"probes": probes, "callback": callback}, [])

    def _replay_with_redirect_chain(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        return self._http_request({**arguments, "follow_redirects": True}, context)

    def _parser_confusion_probe(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        base_url = str(arguments.get("url") or context.get("target") or "").strip()
        callback = str(arguments.get("callback") or "callback://parser-confusion")
        variants = [
            callback,
            callback.replace("callback://", "http://127.0.0.1@"),
            f"http://example.com\\@{callback}",
            f"//{callback}",
        ]
        results = []
        for variant in variants:
            parsed = urlparse(base_url)
            query = parse_qs(parsed.query, keep_blank_values=True)
            parameter = str(arguments.get("parameter", "url"))
            query[parameter] = [variant]
            probe_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
            results.append({"variant": variant, "probe_url": probe_url})
        return ToolExecution("ok", f"parser confusion variants={len(results)}", {"variants": results}, [])

    def _discover_sql_candidates(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        target = str(arguments.get("target") or context.get("target", "")).strip()
        legacy_context = dict(context.get("legacy_context", {}))
        result = run_sql_scan(target, legacy_context)
        findings = [item.to_dict() for item in getattr(result, "findings", [])]
        followup_context = dict(getattr(result, "followup_context", {}))
        sql_context = followup_context.get("consumers", {}).get("sql_bypass", {}) if isinstance(followup_context, dict) else {}
        raw_candidates = sql_context.get("sql_findings", []) if isinstance(sql_context, dict) else []
        candidates = [dict(item) for item in raw_candidates if isinstance(item, dict)] if isinstance(raw_candidates, list) else []
        payload = {
            "module": getattr(result, "module", "sql_scan"),
            "status": getattr(result, "status", ""),
            "candidate_count": len(candidates),
            "candidates": candidates[:6],
            "findings": findings[:6],
            "logs": list(getattr(result, "logs", [])),
            "followup_context": followup_context,
        }
        return ToolExecution("ok", f"sql candidates discovered={len(candidates)}", payload, [])

    def _probe_sql_boolean(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        raw_candidate = arguments.get("candidate")
        candidate = dict(raw_candidate) if isinstance(raw_candidate, dict) else {}
        if not candidate:
            step_contexts = context.get("step_contexts", {})
            sql_scan_context = step_contexts.get("sql_scan", {}) if isinstance(step_contexts, dict) else {}
            if isinstance(sql_scan_context, dict):
                primary = sql_scan_context.get("primary_sql_candidate", {})
                if isinstance(primary, dict) and primary:
                    candidate = dict(primary)
                elif isinstance(sql_scan_context.get("sql_candidates", []), list) and sql_scan_context.get("sql_candidates", []):
                    first = sql_scan_context["sql_candidates"][0]
                    candidate = dict(first) if isinstance(first, dict) else {}
        if not candidate:
            last_payload = context.get("last_observation_payload", {})
            raw_candidates = last_payload.get("candidates", []) if isinstance(last_payload, dict) else []
            if isinstance(raw_candidates, list) and raw_candidates:
                first = raw_candidates[0]
                candidate = dict(first) if isinstance(first, dict) else {}
        page_url = str(candidate.get("page_url", "")).strip()
        parameter = str(candidate.get("parameter", "") or candidate.get("param_name", "")).strip()
        method = str(candidate.get("method", "GET") or "GET").upper()
        if not page_url or not parameter:
            return ToolExecution("error", "missing sql candidate", {"error": "missing candidate context"}, [])
        baseline_url = str(candidate.get("baseline_url", "")).strip() or page_url
        baseline_body = str(candidate.get("baseline_body", "")).strip()
        true_value, false_value = self._sql_boolean_values(parameter, page_url)
        true_request = self._sql_probe_request(method, baseline_url, baseline_body, parameter, true_value)
        false_request = self._sql_probe_request(method, baseline_url, baseline_body, parameter, false_value)
        request_headers = _request_headers_from_legacy_context(dict(context.get("legacy_context", {})))
        true_response = self._send_sql_probe(true_request, request_headers=request_headers)
        false_response = self._send_sql_probe(false_request, request_headers=request_headers)
        true_body = str(true_response.get("body", ""))
        false_body = str(false_response.get("body", ""))
        true_core = _response_core(true_body)
        false_core = _response_core(false_body)
        delta = abs(int(true_response.get("length", len(true_body)) or 0) - int(false_response.get("length", len(false_body)) or 0))
        suspicious = bool(
            true_response.get("status_code") != false_response.get("status_code")
            or delta > 30
            or (true_core and true_core != false_core)
            or ("database" in true_body.lower() and "database" not in false_body.lower())
        )
        payload = {
            "candidate": candidate,
            "true_probe": true_response,
            "false_probe": false_response,
            "true_value": true_value,
            "false_value": false_value,
            "length_delta": delta,
            "status_changed": true_response.get("status_code") != false_response.get("status_code"),
            "suspicious_boolean_difference": suspicious,
        }
        return ToolExecution("ok", f"sql boolean probe delta={delta}", payload, [])

    def _sql_boolean_values(self, parameter: str, page_url: str) -> tuple[str, str]:
        lowered_name = parameter.lower()
        lowered_url = page_url.lower()
        if lowered_name in {"name", "keyword", "search", "q"} or "search" in lowered_url:
            return ("test%' and '1'='1", "test%' and '1'='2")
        if lowered_name in {"id", "uid", "user_id", "page", "sort"}:
            return ("1 and 1=1", "1 and 1=2")
        return ("1' and '1'='1", "1' and '1'='2")

    def _sql_probe_request(self, method: str, url: str, body: str, parameter: str, value: str) -> dict[str, str]:
        parsed = urlparse(url)
        if method == "POST":
            params = parse_qs(body, keep_blank_values=True)
            params[parameter] = [value]
            return {"method": "POST", "url": urlunparse(parsed._replace(query="")), "body": urlencode(params, doseq=True)}
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[parameter] = [value]
        return {"method": "GET", "url": urlunparse(parsed._replace(query=urlencode(params, doseq=True))), "body": ""}

    def _send_sql_probe(self, request_info: dict[str, str], *, request_headers: dict[str, str] | None = None) -> dict[str, Any]:
        session = self.session_store.get("default")
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if request_info.get("method") == "POST" else {}
        headers.update(dict(request_headers or {}))
        response = session.request(
            request_info.get("method", "GET"),
            request_info["url"],
            headers=headers,
            data=request_info.get("body", ""),
            allow_redirects=True,
            timeout=8,
        )
        return {
            "method": request_info.get("method", "GET"),
            "url": response.url,
            "request_body": request_info.get("body", ""),
            "status_code": response.status_code,
            "body": response.text[:120000],
            "length": len(response.text),
        }

    def _generate_sql_bypass_plan(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        raw_candidate = arguments.get("candidate")
        candidate = dict(raw_candidate) if isinstance(raw_candidate, dict) else {}
        if not candidate:
            step_contexts = context.get("step_contexts", {})
            sql_scan_context = step_contexts.get("sql_scan", {}) if isinstance(step_contexts, dict) else {}
            if isinstance(sql_scan_context, dict):
                primary = sql_scan_context.get("primary_sql_candidate", {})
                if isinstance(primary, dict) and primary:
                    candidate = dict(primary)
                elif isinstance(sql_scan_context.get("sql_candidates", []), list) and sql_scan_context.get("sql_candidates", []):
                    first = sql_scan_context["sql_candidates"][0]
                    candidate = dict(first) if isinstance(first, dict) else {}
        if not candidate:
            last_payload = context.get("last_observation_payload", {})
            if isinstance(last_payload, dict):
                candidate = dict(last_payload.get("candidate", {})) if isinstance(last_payload.get("candidate", {}), dict) else {}
                if not candidate:
                    raw_candidates = last_payload.get("candidates", [])
                    if isinstance(raw_candidates, list) and raw_candidates:
                        first = raw_candidates[0]
                        candidate = dict(first) if isinstance(first, dict) else {}
        if not candidate:
            return ToolExecution("error", "missing sql bypass candidate", {"error": "missing candidate context"}, [])
        engine = SQLBypassAdaptiveEngine()
        candidate_obj = SQLBypassCandidate.from_dict(candidate)
        baseline_request, baseline = engine.probe_runner.send_baseline(candidate_obj)
        _basic_request, basic_attack = engine.probe_runner.send_basic_attack(candidate_obj)
        waf_profile = engine.evasion_engine.analyze_response(
            basic_attack.headers or baseline.headers,
            f"{basic_attack.text or ''}\n{basic_attack.error or ''}",
            status_code=basic_attack.status_code,
        )
        strategies = engine.evasion_engine.generate_strategies(candidate_obj, waf_profile, limit=4)
        tamper = engine.evasion_engine.tamper_recommendations(waf_profile)
        payload = {
            "candidate": candidate_obj.to_dict(),
            "baseline": {
                "request": baseline_request.to_dict(parameter=candidate_obj.parameter, redacted=False),
                "status_code": baseline.status_code,
                "length": len(baseline.text),
                "blocked": False,
            },
            "basic_attack": {
                "status_code": basic_attack.status_code,
                "length": len(basic_attack.text),
                "blocked": bool(getattr(basic_attack, "status_code", 0) in {401, 403, 406, 418, 429}),
            },
            "waf_profile": waf_profile.to_dict(),
            "strategies": [item.to_dict(redacted=False) for item in strategies],
            "tamper_recommendations": [item.to_dict() for item in tamper[:5]],
        }
        return ToolExecution("ok", f"sql bypass plan generated strategies={len(strategies)}", payload, [])

    def _run_sql_bypass_probe(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        raw_candidate = arguments.get("candidate")
        raw_strategy = arguments.get("strategy")
        candidate = dict(raw_candidate) if isinstance(raw_candidate, dict) else {}
        strategy_payload = dict(raw_strategy) if isinstance(raw_strategy, dict) else {}
        if not candidate or not strategy_payload:
            last_payload = context.get("last_observation_payload", {})
            if isinstance(last_payload, dict):
                if not candidate and isinstance(last_payload.get("candidate", {}), dict):
                    candidate = dict(last_payload.get("candidate", {}))
                if not strategy_payload:
                    raw_strategies = last_payload.get("strategies", [])
                    if isinstance(raw_strategies, list) and raw_strategies:
                        first = raw_strategies[0]
                        strategy_payload = dict(first) if isinstance(first, dict) else {}
        if not candidate or not strategy_payload:
            return ToolExecution("error", "missing bypass plan context", {"error": "missing candidate or strategy"}, [])
        candidate_obj = SQLBypassCandidate.from_dict(candidate)
        strategy = PayloadStrategy(
            name=str(strategy_payload.get("name", "strategy")).strip() or "strategy",
            payload=str(strategy_payload.get("payload", "")).strip(),
            true_payload=str(strategy_payload.get("true_payload", "")).strip(),
            false_payload=str(strategy_payload.get("false_payload", "")).strip(),
            family=str(strategy_payload.get("family", "generic")).strip() or "generic",
            note=str(strategy_payload.get("note", "")).strip(),
            tamper_hint=str(strategy_payload.get("tamper_hint", "")).strip(),
        )
        engine = SQLBypassAdaptiveEngine()
        baseline_request, baseline = engine.probe_runner.send_baseline(candidate_obj)
        observation = engine.probe_runner.send_strategy(candidate_obj, strategy, baseline_request=baseline_request, baseline=baseline)
        payload = {
            "candidate": candidate_obj.to_dict(),
            "strategy": strategy.to_dict(redacted=False),
            "observation": observation.to_dict(parameter=candidate_obj.parameter, redacted=False),
            "assessment_signal": observation.assessment_signal,
            "signal_type": observation.signal_type,
            "basis": observation.basis,
        }
        return ToolExecution("ok", f"sql bypass probe {strategy.name} signal={observation.assessment_signal}", payload, [])

    def _generate_poc_verification_case(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        verified_findings = context.get("verified_findings", [])
        step_contexts = context.get("step_contexts", {})
        upstream_steps = sorted(step_contexts.keys()) if isinstance(step_contexts, dict) else []
        child_context = step_contexts.get("child_contributions", {}) if isinstance(step_contexts, dict) else {}
        child_recommendations = child_context.get("recommended_next_tests", []) if isinstance(child_context, dict) else []
        processed_finding_ids = context.get("processed_poc_finding_ids", [])
        if not isinstance(child_recommendations, list):
            child_recommendations = []
        if not isinstance(processed_finding_ids, list):
            processed_finding_ids = []
        if not isinstance(verified_findings, list) or not verified_findings:
            return ToolExecution("ok", "no verified findings available", {"status": "no_candidate"}, [])
        finding = self._select_poc_candidate(verified_findings, processed_ids=processed_finding_ids)
        if not finding:
            return ToolExecution("ok", "no suitable poc candidate", {"status": "no_candidate"}, [])
        category = str(finding.get("category", "")).strip()
        source_title = str(finding.get("title", "")).strip()
        source_location = str(finding.get("location", "")).strip()
        source_severity = str(finding.get("severity", "high")).strip() or "high"
        metadata = finding.get("metadata", {}) if isinstance(finding.get("metadata", {}), dict) else {}
        if category == "sql_injection":
            candidate = metadata.get("sql_candidate", {}) if isinstance(metadata.get("sql_candidate", {}), dict) else {}
            page_url = str(candidate.get("page_url", "")).strip()
            baseline_url = str(candidate.get("baseline_url", "")).strip()
            parameter = str(candidate.get("parameter", "")).strip()
            method = str(candidate.get("method", "GET") or "GET").upper()
            if page_url and parameter and method == "GET":
                probe_seed = baseline_url or page_url
                probe_url = self._build_sql_quote_probe_url(probe_seed, parameter)
                docker_baseline = self._docker_reachable_url(baseline_url) if baseline_url else ""
                script = self._build_sql_poc_script(probe_url, baseline_url=docker_baseline)
                payload = {
                    "status": "ready",
                    "source_finding_id": str(finding.get("finding_id", "")),
                    "source_title": source_title,
                    "source_location": source_location,
                    "source_severity": source_severity,
                    "category": category,
                    "upstream_steps": upstream_steps,
                    "child_recommendations": child_recommendations[:12],
                    "verification_target": probe_url,
                    "parameter": parameter,
                    "script": script,
                    "summary": "generated docker poc case for sql replay",
                }
                return ToolExecution("ok", "poc case ready", payload, [])
        if category == "xss":
            candidate = metadata.get("xss_candidate", {}) if isinstance(metadata.get("xss_candidate", {}), dict) else {}
            if candidate:
                verification_target = str(candidate.get("request_url", "") or candidate.get("page_url", "")).strip()
                method = str(candidate.get("method", "GET") or "GET").upper()
                if verification_target and method == "GET":
                    marker = self._xss_reflection_marker(verification_target, str(candidate.get("parameter", "")).strip())
                    docker_target = self._docker_reachable_url(verification_target)
                    payload = {
                        "status": "ready",
                        "source_finding_id": str(finding.get("finding_id", "")),
                        "source_title": source_title,
                        "source_location": source_location,
                        "source_severity": source_severity,
                        "category": category,
                        "upstream_steps": upstream_steps,
                        "child_recommendations": child_recommendations[:12],
                        "verification_target": docker_target,
                        "parameter": str(candidate.get("parameter", "")).strip(),
                        "script": self._build_xss_poc_script(docker_target, marker=marker),
                        "xss_context": {
                            "page_url": str(candidate.get("page_url", "")).strip(),
                            "method": method,
                            "parameter": str(candidate.get("parameter", "")).strip(),
                            "context": str(candidate.get("context", "")).strip(),
                            "confirmed_strategies": list(candidate.get("confirmed_strategies", []) if isinstance(candidate.get("confirmed_strategies", []), list) else []),
                        },
                        "summary": "generated docker poc case for bounded XSS reflection replay",
                    }
                    return ToolExecution("ok", "poc case ready", payload, [])
                payload = {
                    "status": "manual_only",
                    "source_finding_id": str(finding.get("finding_id", "")),
                    "source_title": source_title,
                    "source_location": source_location,
                    "source_severity": source_severity,
                    "category": category,
                    "upstream_steps": upstream_steps,
                    "child_recommendations": child_recommendations[:12],
                    "verification_target": verification_target,
                    "parameter": str(candidate.get("parameter", "")).strip(),
                    "xss_context": {
                        "page_url": str(candidate.get("page_url", "")).strip(),
                        "method": str(candidate.get("method", "")).strip(),
                        "parameter": str(candidate.get("parameter", "")).strip(),
                        "context": str(candidate.get("context", "")).strip(),
                        "confirmed_strategies": list(candidate.get("confirmed_strategies", []) if isinstance(candidate.get("confirmed_strategies", []), list) else []),
                    },
                    "summary": "xss_triage already produced browser-context proof; no safe docker replay template was generated",
                }
                return ToolExecution("ok", "poc case manual only", payload, [])
        if category in {"backup_source_audit", "config_exposure", "frontend_secret_exposure"}:
            verification_target = self._exposure_poc_target(source_location, metadata)
            if verification_target:
                docker_target = self._docker_reachable_url(verification_target)
                payload = {
                    "status": "ready",
                    "source_finding_id": str(finding.get("finding_id", "")),
                    "source_title": source_title,
                    "source_location": source_location,
                    "source_severity": source_severity,
                    "category": category,
                    "upstream_steps": upstream_steps,
                    "child_recommendations": child_recommendations[:12],
                    "verification_target": docker_target,
                    "script": self._build_exposure_poc_script(docker_target, category=category),
                    "summary": "generated docker poc case for read-only exposure replay",
                }
                return ToolExecution("ok", "poc case ready", payload, [])
        if category == "ssrf":
            ssrf_context = metadata.get("ssrf_context", {}) if isinstance(metadata.get("ssrf_context", {}), dict) else {}
            method = str(ssrf_context.get("method", "GET") or "GET").upper()
            verification_target = str(ssrf_context.get("probe_url", "") or source_location).strip()
            baseline_target = str(ssrf_context.get("request_url", "")).strip()
            if verification_target and method == "GET":
                docker_target = self._docker_reachable_url(verification_target)
                docker_baseline = self._docker_reachable_url(baseline_target) if baseline_target else ""
                matched_markers = [
                    str(item).strip()
                    for item in ssrf_context.get("matched_markers", [])
                    if str(item).strip()
                ] if isinstance(ssrf_context.get("matched_markers", []), list) else []
                payload = {
                    "status": "ready",
                    "source_finding_id": str(finding.get("finding_id", "")),
                    "source_title": source_title,
                    "source_location": source_location,
                    "source_severity": source_severity,
                    "category": category,
                    "upstream_steps": upstream_steps,
                    "child_recommendations": child_recommendations[:12],
                    "verification_target": docker_target,
                    "baseline_target": docker_baseline,
                    "parameter": str(ssrf_context.get("parameter", "")).strip(),
                    "script": self._build_ssrf_poc_script(
                        docker_target,
                        baseline_url=docker_baseline,
                        probe_value=str(ssrf_context.get("probe_value", "")).strip(),
                        matched_markers=matched_markers,
                    ),
                    "ssrf_context": {
                        "page_url": str(ssrf_context.get("page_url", "")).strip(),
                        "method": method,
                        "parameter": str(ssrf_context.get("parameter", "")).strip(),
                        "probe_value": str(ssrf_context.get("probe_value", "")).strip(),
                        "probe_type": str(ssrf_context.get("probe_type", "")).strip(),
                        "matched_markers": matched_markers,
                    },
                    "summary": "generated docker poc case for bounded SSRF replay",
                }
                return ToolExecution("ok", "poc case ready", payload, [])
        if category == "cors":
            cors_context = metadata.get("cors_context", {}) if isinstance(metadata.get("cors_context", {}), dict) else {}
            verification_target = str(cors_context.get("url", "") or source_location).strip()
            if verification_target:
                docker_target = self._docker_reachable_url(verification_target)
                probe_origin = str(cors_context.get("probe_origin", "") or "https://evil-origin.invalid").strip()
                allow_origin = str(cors_context.get("allow_origin", "")).strip()
                allow_credentials = str(cors_context.get("allow_credentials", "")).strip()
                risk = str(cors_context.get("risk", "")).strip()
                payload = {
                    "status": "ready",
                    "source_finding_id": str(finding.get("finding_id", "")),
                    "source_title": source_title,
                    "source_location": source_location,
                    "source_severity": source_severity,
                    "category": category,
                    "upstream_steps": upstream_steps,
                    "child_recommendations": child_recommendations[:12],
                    "verification_target": docker_target,
                    "script": self._build_cors_poc_script(
                        docker_target,
                        origin=probe_origin,
                        expected_allow_origin=allow_origin,
                        expected_allow_credentials=allow_credentials,
                        risk=risk,
                    ),
                    "cors_context": {
                        "url": verification_target,
                        "probe_origin": probe_origin,
                        "allow_origin": allow_origin,
                        "allow_credentials": allow_credentials,
                        "risk": risk,
                    },
                    "summary": "generated docker poc case for CORS header replay",
                }
                return ToolExecution("ok", "poc case ready", payload, [])
        if category == "jwt":
            jwt_context = metadata.get("jwt_context", {}) if isinstance(metadata.get("jwt_context", {}), dict) else {}
            verification_target = str(jwt_context.get("url", "") or source_location).strip()
            if verification_target:
                docker_target = self._docker_reachable_url(verification_target)
                issue = str(jwt_context.get("issue", "")).strip()
                payload_keys = [
                    str(item).strip()
                    for item in jwt_context.get("payload_keys", [])
                    if str(item).strip()
                ] if isinstance(jwt_context.get("payload_keys", []), list) else []
                payload = {
                    "status": "ready",
                    "source_finding_id": str(finding.get("finding_id", "")),
                    "source_title": source_title,
                    "source_location": source_location,
                    "source_severity": source_severity,
                    "category": category,
                    "upstream_steps": upstream_steps,
                    "child_recommendations": child_recommendations[:12],
                    "verification_target": docker_target,
                    "script": self._build_jwt_poc_script(
                        docker_target,
                        issue=issue,
                        expected_alg=str(jwt_context.get("alg", "")).strip(),
                        signature_present=bool(jwt_context.get("signature_present", False)),
                        payload_keys=payload_keys,
                    ),
                    "jwt_context": {
                        "url": verification_target,
                        "issue": issue,
                        "alg": str(jwt_context.get("alg", "")).strip(),
                        "typ": str(jwt_context.get("typ", "")).strip(),
                        "signature_present": bool(jwt_context.get("signature_present", False)),
                        "payload_keys": payload_keys,
                    },
                    "summary": "generated docker poc case for JWT response replay",
                }
                return ToolExecution("ok", "poc case ready", payload, [])
        if category == "authorization":
            permission_context = metadata.get("permission_context", {}) if isinstance(metadata.get("permission_context", {}), dict) else {}
            method = str(permission_context.get("method", "GET") or "GET").upper()
            verification_target = str(permission_context.get("mutated_url", "") or source_location or permission_context.get("url", "")).strip()
            baseline_target = str(permission_context.get("url", "")).strip()
            if verification_target and method == "GET":
                docker_target = self._docker_reachable_url(verification_target)
                docker_baseline = self._docker_reachable_url(baseline_target) if baseline_target else ""
                payload = {
                    "status": "ready",
                    "source_finding_id": str(finding.get("finding_id", "")),
                    "source_title": source_title,
                    "source_location": source_location,
                    "source_severity": source_severity,
                    "category": category,
                    "upstream_steps": upstream_steps,
                    "child_recommendations": child_recommendations[:12],
                    "verification_target": docker_target,
                    "baseline_target": docker_baseline,
                    "parameter": str(permission_context.get("parameter", "")).strip(),
                    "script": self._build_permission_poc_script(
                        docker_target,
                        baseline_url=docker_baseline,
                        context_type=str(permission_context.get("type", "")).strip(),
                        parameter=str(permission_context.get("parameter", "")).strip(),
                    ),
                    "permission_context": {
                        "url": baseline_target,
                        "mutated_url": str(permission_context.get("mutated_url", "")).strip(),
                        "method": method,
                        "type": str(permission_context.get("type", "")).strip(),
                        "parameter": str(permission_context.get("parameter", "")).strip(),
                        "baseline_value": str(permission_context.get("baseline_value", "")).strip(),
                        "mutated_value": str(permission_context.get("mutated_value", "")).strip(),
                    },
                    "summary": "generated docker poc case for authorization/IDOR replay",
                }
                return ToolExecution("ok", "poc case ready", payload, [])
        if category == "weak_password":
            weak_context = metadata.get("weak_password_context", {}) if isinstance(metadata.get("weak_password_context", {}), dict) else {}
            verification_target = str(weak_context.get("action", "") or source_location).strip()
            method = str(weak_context.get("method", "POST") or "POST").upper()
            username = str(weak_context.get("username", "")).strip()
            username_field = str(weak_context.get("username_field", "")).strip()
            password_field = str(weak_context.get("password_field", "")).strip()
            password_env = str(weak_context.get("password_env", "") or weak_context.get("credential_env", "")).strip()
            if verification_target and method in {"GET", "POST"} and username and username_field and password_field and password_env:
                docker_target = self._docker_reachable_url(verification_target)
                payload = {
                    "status": "ready",
                    "source_finding_id": str(finding.get("finding_id", "")),
                    "source_title": source_title,
                    "source_location": source_location,
                    "source_severity": source_severity,
                    "category": category,
                    "upstream_steps": upstream_steps,
                    "child_recommendations": child_recommendations[:12],
                    "verification_target": docker_target,
                    "env_names": [password_env],
                    "script": self._build_weak_password_poc_script(
                        docker_target,
                        method=method,
                        username=username,
                        username_field=username_field,
                        password_field=password_field,
                        password_env=password_env,
                    ),
                    "weak_password_context": {
                        "action": verification_target,
                        "method": method,
                        "username": username,
                        "username_field": username_field,
                        "password_field": password_field,
                        "masked_password": str(weak_context.get("masked_password", "")).strip(),
                        "password_env": password_env,
                        "source": str(weak_context.get("source", "")).strip(),
                    },
                    "summary": "generated docker poc case for bounded weak-password login replay via environment-provided secret",
                }
                return ToolExecution("ok", "poc case ready", payload, [])
            payload = {
                "status": "manual_only",
                "source_finding_id": str(finding.get("finding_id", "")),
                "source_title": source_title,
                "source_location": source_location,
                "source_severity": source_severity,
                "category": category,
                "upstream_steps": upstream_steps,
                "child_recommendations": child_recommendations[:12],
                "verification_target": verification_target,
                "weak_password_context": {
                    "page_url": str(weak_context.get("page_url", "")).strip(),
                    "action": verification_target,
                    "method": method,
                    "username": username,
                    "username_field": username_field,
                    "password_field": password_field,
                    "masked_password": str(weak_context.get("masked_password", "")).strip(),
                    "source": str(weak_context.get("source", "")).strip(),
                },
                "manual_poc_checklist": [
                    "Use the upstream weak-password finding as the accepted-credential proof.",
                    "Keep the password redacted in reports and artifacts.",
                    "If automated replay is required, provide a password_env field that names an environment variable containing the credential.",
                    "Run only a single bounded login replay and confirm authenticated markers such as logout or dashboard.",
                ],
                "summary": "weak-password proof is redacted; no plaintext credential or password_env was available for safe docker replay",
            }
            return ToolExecution("ok", "poc case manual only", payload, [])
        payload = {
            "status": "manual_only",
            "source_finding_id": str(finding.get("finding_id", "")),
            "source_title": source_title,
            "source_location": source_location,
            "source_severity": source_severity,
            "category": category,
            "upstream_steps": upstream_steps,
            "child_recommendations": child_recommendations[:12],
            "summary": "no safe docker replay template was available for this finding",
        }
        return ToolExecution("ok", "poc case manual only", payload, [])

    def _select_poc_candidate(self, findings: list[dict[str, Any]], *, processed_ids: list[str] | None = None) -> dict[str, Any]:
        processed = {str(item).strip() for item in (processed_ids or []) if str(item).strip()}
        eligible_findings = [
            item
            for item in findings
            if isinstance(item, dict) and str(item.get("finding_id", "")).strip() not in processed
        ]
        sql_with_candidate = []
        for item in eligible_findings:
            if str(item.get("category", "")).strip() != "sql_injection":
                continue
            metadata = item.get("metadata", {}) if isinstance(item.get("metadata", {}), dict) else {}
            if isinstance(metadata.get("sql_candidate", {}), dict) and metadata.get("sql_candidate", {}):
                sql_with_candidate.append(item)
        if sql_with_candidate:
            get_candidates = []
            other_candidates = []
            for item in sql_with_candidate:
                metadata = item.get("metadata", {}) if isinstance(item.get("metadata", {}), dict) else {}
                candidate = metadata.get("sql_candidate", {}) if isinstance(metadata.get("sql_candidate", {}), dict) else {}
                method = str(candidate.get("method", "GET") or "GET").strip().upper()
                if method == "GET":
                    get_candidates.append(item)
                else:
                    other_candidates.append(item)
            preferred = get_candidates or other_candidates
            preferred = sorted(preferred, key=self._sql_poc_candidate_priority)
            return dict(preferred[0])
        priority = {
            "sql_injection": 0,
            "frontend_secret_exposure": 1,
            "ssrf": 1,
            "xss": 2,
            "authorization": 3,
            "config_exposure": 4,
            "backup_source_audit": 5,
            "cors": 6,
            "jwt": 7,
            "weak_password": 8,
        }
        ordered = sorted(
            eligible_findings,
            key=lambda item: (priority.get(str(item.get("category", "")).strip(), 99), str(item.get("finding_id", ""))),
        )
        return dict(ordered[0]) if ordered else {}

    def _build_sql_quote_probe_url(self, page_url: str, parameter: str) -> str:
        parsed = urlparse(page_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[parameter] = ["1'"]
        updated = parsed._replace(query=urlencode(params, doseq=True))
        return self._docker_reachable_url(urlunparse(updated))

    def _sql_poc_candidate_priority(self, finding: dict[str, Any]) -> tuple[Any, ...]:
        metadata = finding.get("metadata", {}) if isinstance(finding.get("metadata", {}), dict) else {}
        candidate = metadata.get("sql_candidate", {}) if isinstance(metadata.get("sql_candidate", {}), dict) else {}
        page_url = str(candidate.get("page_url", "")).strip()
        parameter = str(candidate.get("parameter", "")).strip().lower()
        strategies = {
            str(item).strip().lower()
            for item in candidate.get("confirmed_strategies", [])
            if str(item).strip()
        } if isinstance(candidate.get("confirmed_strategies", []), list) else set()
        basis = str(candidate.get("basis", "")).strip().lower()
        parsed = urlparse(page_url)
        has_seed_query = bool(parsed.query)
        numeric_parameter = parameter in {"id", "uid", "user_id", "page", "sort"}
        quote_delta = 0
        match = re.search(r"quote probe differs from baseline by (\\d+) bytes", basis)
        if match:
            try:
                quote_delta = int(match.group(1))
            except ValueError:
                quote_delta = 0
        return (
            0 if str(candidate.get("method", "GET") or "GET").strip().upper() == "GET" else 1,
            -int(has_seed_query),
            -int(numeric_parameter),
            -int("quote_error" in strategies),
            -int("union_basic" in strategies),
            -quote_delta,
            -len(strategies),
            str(finding.get("finding_id", "")),
        )

    def _docker_reachable_url(self, url: str) -> str:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if host not in {"127.0.0.1", "localhost"}:
            return url
        netloc = parsed.netloc
        if ":" in netloc:
            _host, port = netloc.rsplit(":", 1)
            netloc = f"host.docker.internal:{port}"
        else:
            netloc = "host.docker.internal"
        return urlunparse(parsed._replace(netloc=netloc))

    def _xss_reflection_marker(self, url: str, parameter: str) -> str:
        parsed = urlparse(url)
        if parameter:
            values = parse_qs(parsed.query, keep_blank_values=True).get(parameter, [])
            if values and str(values[0]).strip():
                return str(values[0])
        decoded = unquote(parsed.query)
        for marker in ("<script", "alert(1)", "onerror", "<svg", "javascript:"):
            if marker.lower() in decoded.lower():
                return marker
        return "<script>alert(1)</script>"

    def _exposure_poc_target(self, source_location: str, metadata: dict[str, Any]) -> str:
        candidates = [source_location]
        for key in ("backup_context", "config_context", "js_context"):
            context = metadata.get(key, {}) if isinstance(metadata.get(key, {}), dict) else {}
            candidates.extend(
                [
                    str(context.get("url", "")).strip(),
                    str(context.get("location", "")).strip(),
                    str(context.get("script_url", "")).strip(),
                    str(context.get("candidate_url", "")).strip(),
                ]
            )
        for candidate in candidates:
            value = str(candidate).strip()
            if value.startswith(("http://", "https://")):
                return value
        return ""

    def _build_sql_poc_script(self, probe_url: str, *, baseline_url: str = "") -> str:
        safe_url = json.dumps(probe_url)
        safe_baseline = json.dumps(str(baseline_url or ""))
        return (
            "import json\n"
            "import urllib.error\n"
            "import urllib.request\n"
            f"url = {safe_url}\n"
            f"baseline_url = {safe_baseline}\n"
            "def fetch(target):\n"
            "    try:\n"
            "        with urllib.request.urlopen(target, timeout=8) as resp:\n"
            "            body = resp.read().decode('utf-8', errors='ignore')\n"
            "            return {'status': getattr(resp, 'status', 200), 'body': body, 'error': ''}\n"
            "    except urllib.error.HTTPError as exc:\n"
            "        body = exc.read().decode('utf-8', errors='ignore')\n"
            "        return {'status': exc.code, 'body': body, 'error': str(exc)}\n"
            "baseline = fetch(baseline_url) if baseline_url else {'status': 0, 'body': '', 'error': ''}\n"
            "try:\n"
            "    probe = fetch(url)\n"
            "    body = probe['body']\n"
            "    lowered = body.lower()\n"
            "    baseline_body = baseline['body']\n"
            "    delta = abs(len(body) - len(baseline_body)) if baseline_url else 0\n"
            "    status_changed = bool(baseline_url) and probe['status'] != baseline['status']\n"
            "    diff_changed = bool(baseline_url) and delta > 80 and body != baseline_body\n"
            "    verified = (\n"
            "        ('sql syntax' in lowered)\n"
            "        or ('database error' in lowered)\n"
            "        or ('pdoexception' in lowered)\n"
            "        or ('warning' in lowered and 'mysql' in lowered)\n"
            "        or status_changed\n"
            "        or diff_changed\n"
            "    )\n"
            "    print(json.dumps({\n"
            "            'verified': verified,\n"
            "            'status': 'confirmed' if verified else 'not_confirmed',\n"
            "            'request_url': url,\n"
            "            'baseline_url': baseline_url,\n"
            "            'observed_status': probe['status'],\n"
            "            'baseline_status': baseline['status'],\n"
            "            'delta': delta,\n"
            "            'status_changed': status_changed,\n"
            "            'evidence_excerpt': body[:400],\n"
            "        }))\n"
            "except Exception as exc:\n"
            "    print(json.dumps({'verified': False, 'status': 'error', 'request_url': url, 'error': str(exc)}))\n"
        )

    def _build_xss_poc_script(self, url: str, *, marker: str) -> str:
        safe_url = json.dumps(url)
        safe_marker = json.dumps(marker)
        return (
            "import html\n"
            "import json\n"
            "import urllib.error\n"
            "import urllib.request\n"
            f"url = {safe_url}\n"
            f"marker = {safe_marker}\n"
            "try:\n"
            "    with urllib.request.urlopen(url, timeout=8) as resp:\n"
            "        body = resp.read().decode('utf-8', errors='ignore')\n"
            "        status = getattr(resp, 'status', 200)\n"
            "    lowered = body.lower()\n"
            "    marker_variants = [marker, html.escape(marker), 'alert(1)', '<script']\n"
            "    hits = [item for item in marker_variants if item and item.lower() in lowered]\n"
            "    verified = status < 500 and bool(hits)\n"
            "    print(json.dumps({\n"
            "        'verified': verified,\n"
            "        'status': 'confirmed' if verified else 'not_confirmed',\n"
            "        'request_url': url,\n"
            "        'observed_status': status,\n"
            "        'matched_markers': hits,\n"
            "        'evidence_excerpt': body[:400],\n"
            "    }))\n"
            "except urllib.error.HTTPError as exc:\n"
            "    body = exc.read().decode('utf-8', errors='ignore')\n"
            "    print(json.dumps({'verified': False, 'status': 'http_error', 'request_url': url, 'observed_status': exc.code, 'evidence_excerpt': body[:400]}))\n"
            "except Exception as exc:\n"
            "    print(json.dumps({'verified': False, 'status': 'error', 'request_url': url, 'error': str(exc)}))\n"
        )

    def _build_exposure_poc_script(self, url: str, *, category: str) -> str:
        safe_url = json.dumps(url)
        safe_category = json.dumps(category)
        return (
            "import json\n"
            "import urllib.error\n"
            "import urllib.request\n"
            f"url = {safe_url}\n"
            f"category = {safe_category}\n"
            "markers = {\n"
            "    'frontend_secret_exposure': ['app_key', 'api_key', 'apikey', 'secret', 'token', 'password', 'client_secret'],\n"
            "    'config_exposure': ['db_password', 'database', 'debug', 'app_key', 'secret', 'password', 'mysql'],\n"
            "    'backup_source_audit': ['[core]', 'db_password', 'database', 'backup', 'config', 'secret', 'password'],\n"
            "}.get(category, ['secret', 'password', 'config'])\n"
            "try:\n"
            "    req = urllib.request.Request(url, headers={'User-Agent': 'ai-security-agent-poc/1.0'})\n"
            "    with urllib.request.urlopen(req, timeout=8) as resp:\n"
            "        raw = resp.read(262144)\n"
            "        status = getattr(resp, 'status', 200)\n"
            "        content_type = resp.headers.get('content-type', '')\n"
            "    text = raw.decode('utf-8', errors='ignore')\n"
            "    lowered = text.lower()\n"
            "    hits = [item for item in markers if item in lowered]\n"
            "    has_archive_bytes = raw.startswith(b'PK') or raw.startswith(b'\\x1f\\x8b')\n"
            "    verified = status < 400 and len(raw) > 0 and (bool(hits) or (category == 'backup_source_audit' and has_archive_bytes))\n"
            "    print(json.dumps({\n"
            "        'verified': verified,\n"
            "        'status': 'confirmed' if verified else 'not_confirmed',\n"
            "        'request_url': url,\n"
            "        'observed_status': status,\n"
            "        'content_type': content_type,\n"
            "        'byte_count': len(raw),\n"
            "        'matched_markers': hits,\n"
            "        'archive_magic': has_archive_bytes,\n"
            "        'evidence_excerpt': text[:400],\n"
            "    }))\n"
            "except urllib.error.HTTPError as exc:\n"
            "    body = exc.read().decode('utf-8', errors='ignore')\n"
            "    print(json.dumps({'verified': False, 'status': 'http_error', 'request_url': url, 'observed_status': exc.code, 'evidence_excerpt': body[:400]}))\n"
            "except Exception as exc:\n"
            "    print(json.dumps({'verified': False, 'status': 'error', 'request_url': url, 'error': str(exc)}))\n"
        )

    def _build_ssrf_poc_script(
        self,
        url: str,
        *,
        baseline_url: str = "",
        probe_value: str = "",
        matched_markers: list[str] | None = None,
    ) -> str:
        safe_url = json.dumps(url)
        safe_baseline = json.dumps(str(baseline_url or ""))
        safe_probe_value = json.dumps(str(probe_value or ""))
        safe_markers = json.dumps([str(item) for item in (matched_markers or []) if str(item).strip()])
        return (
            "import json\n"
            "import urllib.error\n"
            "import urllib.request\n"
            f"url = {safe_url}\n"
            f"baseline_url = {safe_baseline}\n"
            f"probe_value = {safe_probe_value}\n"
            f"expected_markers = {safe_markers}\n"
            "def fetch(target):\n"
            "    if not target:\n"
            "        return {'status': 0, 'body': '', 'error': ''}\n"
            "    req = urllib.request.Request(target, headers={'User-Agent': 'ai-security-agent-poc/1.0'})\n"
            "    try:\n"
            "        with urllib.request.urlopen(req, timeout=8) as resp:\n"
            "            body = resp.read(262144).decode('utf-8', errors='ignore')\n"
            "            return {'status': getattr(resp, 'status', 200), 'body': body, 'error': ''}\n"
            "    except urllib.error.HTTPError as exc:\n"
            "        body = exc.read().decode('utf-8', errors='ignore')\n"
            "        return {'status': exc.code, 'body': body, 'error': str(exc)}\n"
            "try:\n"
            "    baseline = fetch(baseline_url)\n"
            "    probe = fetch(url)\n"
            "    body = probe['body']\n"
            "    baseline_body = baseline['body']\n"
            "    lowered = body.lower()\n"
            "    internal_markers = ['internal', 'localhost', 'loopback', 'dashboard', 'health', 'metadata', 'service catalog', 'local root']\n"
            "    marker_hits = [item for item in expected_markers if item and item.lower() in lowered]\n"
            "    internal_hits = [item for item in internal_markers if item in lowered]\n"
            "    delta = abs(len(body) - len(baseline_body)) if baseline_url else 0\n"
            "    status_changed = bool(baseline_url) and probe['status'] != baseline['status']\n"
            "    diff_changed = bool(baseline_url) and body != baseline_body and delta > 120\n"
            "    verified = probe['status'] < 500 and (bool(marker_hits) or bool(internal_hits) or status_changed or diff_changed)\n"
            "    print(json.dumps({\n"
            "        'verified': verified,\n"
            "        'status': 'confirmed' if verified else 'not_confirmed',\n"
            "        'request_url': url,\n"
            "        'baseline_url': baseline_url,\n"
            "        'probe_value': probe_value,\n"
            "        'observed_status': probe['status'],\n"
            "        'baseline_status': baseline['status'],\n"
            "        'delta': delta,\n"
            "        'status_changed': status_changed,\n"
            "        'matched_markers': marker_hits + internal_hits,\n"
            "        'evidence_excerpt': body[:400],\n"
            "    }))\n"
            "except Exception as exc:\n"
            "    print(json.dumps({'verified': False, 'status': 'error', 'request_url': url, 'error': str(exc)}))\n"
        )

    def _build_cors_poc_script(
        self,
        url: str,
        *,
        origin: str,
        expected_allow_origin: str,
        expected_allow_credentials: str,
        risk: str,
    ) -> str:
        safe_url = json.dumps(url)
        safe_origin = json.dumps(origin)
        safe_expected_allow_origin = json.dumps(expected_allow_origin)
        safe_expected_allow_credentials = json.dumps(expected_allow_credentials)
        safe_risk = json.dumps(risk)
        return (
            "import json\n"
            "import urllib.error\n"
            "import urllib.request\n"
            f"url = {safe_url}\n"
            f"origin = {safe_origin}\n"
            f"expected_allow_origin = {safe_expected_allow_origin}\n"
            f"expected_allow_credentials = {safe_expected_allow_credentials}\n"
            f"risk = {safe_risk}\n"
            "try:\n"
            "    req = urllib.request.Request(url, headers={'Origin': origin, 'Accept': '*/*', 'User-Agent': 'ai-security-agent-poc/1.0'})\n"
            "    try:\n"
            "        resp = urllib.request.urlopen(req, timeout=8)\n"
            "    except urllib.error.HTTPError as exc:\n"
            "        resp = exc\n"
            "    with resp:\n"
            "        body = resp.read(8192).decode('utf-8', errors='ignore')\n"
            "        status = getattr(resp, 'status', getattr(resp, 'code', 0))\n"
            "        headers = {str(k).lower(): str(v) for k, v in resp.headers.items()}\n"
            "    allow_origin = headers.get('access-control-allow-origin', '')\n"
            "    allow_credentials = headers.get('access-control-allow-credentials', '').lower()\n"
            "    reflected = bool(origin and allow_origin == origin)\n"
            "    credentials = allow_credentials == 'true'\n"
            "    expected_origin_match = (not expected_allow_origin) or allow_origin == expected_allow_origin\n"
            "    expected_credentials_match = (not expected_allow_credentials) or allow_credentials == expected_allow_credentials.lower()\n"
            "    if risk == 'origin_reflection_credentials':\n"
            "        verified = reflected and credentials\n"
            "    elif risk == 'origin_reflection':\n"
            "        verified = reflected\n"
            "    elif risk == 'wildcard_credentials':\n"
            "        verified = allow_origin == '*' and credentials\n"
            "    elif risk == 'null_origin_credentials':\n"
            "        verified = allow_origin == 'null' and credentials\n"
            "    else:\n"
            "        verified = expected_origin_match and expected_credentials_match and bool(allow_origin)\n"
            "    print(json.dumps({\n"
            "        'verified': bool(verified),\n"
            "        'status': 'confirmed' if verified else 'not_confirmed',\n"
            "        'request_url': url,\n"
            "        'probe_origin': origin,\n"
            "        'observed_status': status,\n"
            "        'allow_origin': allow_origin,\n"
            "        'allow_credentials': allow_credentials,\n"
            "        'risk': risk,\n"
            "        'evidence_excerpt': body[:400],\n"
            "    }))\n"
            "except Exception as exc:\n"
            "    print(json.dumps({'verified': False, 'status': 'error', 'request_url': url, 'probe_origin': origin, 'error': str(exc)}))\n"
        )

    def _build_jwt_poc_script(
        self,
        url: str,
        *,
        issue: str,
        expected_alg: str,
        signature_present: bool,
        payload_keys: list[str],
    ) -> str:
        safe_url = json.dumps(url)
        safe_issue = json.dumps(issue)
        safe_expected_alg = json.dumps(expected_alg)
        safe_signature_present = json.dumps(bool(signature_present))
        safe_payload_keys = json.dumps([str(item) for item in payload_keys if str(item).strip()])
        return (
            "import base64\n"
            "import json\n"
            "import re\n"
            "import urllib.error\n"
            "import urllib.request\n"
            f"url = {safe_url}\n"
            f"issue = {safe_issue}\n"
            f"expected_alg = {safe_expected_alg}\n"
            f"expected_signature_present = {safe_signature_present}\n"
            f"expected_payload_keys = {safe_payload_keys}\n"
            "jwt_re = re.compile(r'(eyJ[a-zA-Z0-9_-]+)\\.(eyJ[a-zA-Z0-9_-]+)\\.([a-zA-Z0-9_-]*)')\n"
            "sensitive_keys = {'password', 'pwd', 'secret', 'token', 'ssn', 'creditcard', 'private_key', 'apikey', 'api_key'}\n"
            "def decode_json(data):\n"
            "    padding = '=' * ((4 - len(data) % 4) % 4)\n"
            "    return json.loads(base64.urlsafe_b64decode(data + padding).decode('utf-8', errors='replace'))\n"
            "def flatten_keys(value, prefix=''):\n"
            "    keys = []\n"
            "    if isinstance(value, dict):\n"
            "        for key, nested in value.items():\n"
            "            label = f'{prefix}.{key}' if prefix else str(key)\n"
            "            keys.append(label)\n"
            "            keys.extend(flatten_keys(nested, label))\n"
            "    elif isinstance(value, list):\n"
            "        for index, nested in enumerate(value):\n"
            "            keys.extend(flatten_keys(nested, f'{prefix}[{index}]'))\n"
            "    return keys\n"
            "try:\n"
            "    req = urllib.request.Request(url, headers={'User-Agent': 'ai-security-agent-poc/1.0'})\n"
            "    with urllib.request.urlopen(req, timeout=8) as resp:\n"
            "        body = resp.read(262144).decode('utf-8', errors='ignore')\n"
            "        status = getattr(resp, 'status', 200)\n"
            "    matched = []\n"
            "    decoded = []\n"
            "    for header_b64, payload_b64, signature in jwt_re.findall(body):\n"
            "        try:\n"
            "            header = decode_json(header_b64)\n"
            "            payload = decode_json(payload_b64)\n"
            "        except Exception:\n"
            "            continue\n"
            "        alg = str(header.get('alg', '')).lower()\n"
            "        keys = flatten_keys(payload)\n"
            "        key_names = {item.rsplit('.', 1)[-1].lower() for item in keys}\n"
            "        token_issues = []\n"
            "        if alg == 'none':\n"
            "            token_issues.append('alg=none')\n"
            "        if not signature:\n"
            "            token_issues.append('empty_signature')\n"
            "        sensitive_hits = sorted(item for item in keys if item.rsplit('.', 1)[-1].lower() in sensitive_keys)\n"
            "        if sensitive_hits:\n"
            "            token_issues.append('sensitive_claims')\n"
            "        issue_lower = issue.lower()\n"
            "        expected_key_hits = [item for item in expected_payload_keys if item and item in keys]\n"
            "        if ('alg=none' in issue_lower and 'alg=none' in token_issues) or ('empty_signature' in issue_lower and 'empty_signature' in token_issues) or ('sensitive_claims' in issue_lower and ('sensitive_claims' in token_issues or expected_key_hits)) or (expected_alg and alg == expected_alg.lower()):\n"
            "            matched.extend(token_issues or ['jwt_decoded'])\n"
            "        decoded.append({'alg': alg, 'signature_present': bool(signature), 'payload_keys': keys[:24], 'sensitive_hits': sensitive_hits[:12]})\n"
            "    verified = status < 500 and bool(matched)\n"
            "    print(json.dumps({\n"
            "        'verified': verified,\n"
            "        'status': 'confirmed' if verified else 'not_confirmed',\n"
            "        'request_url': url,\n"
            "        'observed_status': status,\n"
            "        'issue': issue,\n"
            "        'token_count': len(decoded),\n"
            "        'matched_issues': sorted(set(matched)),\n"
            "        'decoded_tokens': decoded[:4],\n"
            "    }))\n"
            "except urllib.error.HTTPError as exc:\n"
            "    body = exc.read().decode('utf-8', errors='ignore')\n"
            "    print(json.dumps({'verified': False, 'status': 'http_error', 'request_url': url, 'observed_status': exc.code, 'evidence_excerpt': body[:400]}))\n"
            "except Exception as exc:\n"
            "    print(json.dumps({'verified': False, 'status': 'error', 'request_url': url, 'error': str(exc)}))\n"
        )

    def _build_permission_poc_script(
        self,
        url: str,
        *,
        baseline_url: str = "",
        context_type: str = "",
        parameter: str = "",
    ) -> str:
        safe_url = json.dumps(url)
        safe_baseline = json.dumps(str(baseline_url or ""))
        safe_context_type = json.dumps(str(context_type or ""))
        safe_parameter = json.dumps(str(parameter or ""))
        return (
            "import json\n"
            "import urllib.error\n"
            "import urllib.request\n"
            f"url = {safe_url}\n"
            f"baseline_url = {safe_baseline}\n"
            f"context_type = {safe_context_type}\n"
            f"parameter = {safe_parameter}\n"
            "privileged_markers = ['admin', 'dashboard', 'management', 'role', 'permission', 'account', 'email', 'order', 'logout', 'users', 'settings', 'export']\n"
            "deny_markers = ['forbidden', 'unauthorized', 'access denied', 'permission denied', 'login required', 'not allowed']\n"
            "def fetch(target, headers=None):\n"
            "    if not target:\n"
            "        return {'status': 0, 'body': '', 'error': ''}\n"
            "    req = urllib.request.Request(target, headers=headers or {'User-Agent': 'ai-security-agent-poc/1.0'})\n"
            "    try:\n"
            "        with urllib.request.urlopen(req, timeout=8) as resp:\n"
            "            body = resp.read(262144).decode('utf-8', errors='ignore')\n"
            "            return {'status': getattr(resp, 'status', 200), 'body': body, 'error': ''}\n"
            "    except urllib.error.HTTPError as exc:\n"
            "        body = exc.read().decode('utf-8', errors='ignore')\n"
            "        return {'status': exc.code, 'body': body, 'error': str(exc)}\n"
            "def marker_hits(body, markers):\n"
            "    lowered = (body or '').lower()\n"
            "    return [item for item in markers if item in lowered]\n"
            "try:\n"
            "    is_idor = bool(parameter) or 'idor' in context_type.lower()\n"
            "    if is_idor:\n"
            "        baseline = fetch(baseline_url)\n"
            "        probe = fetch(url)\n"
            "        delta = abs(len(probe['body']) - len(baseline['body'])) if baseline_url else 0\n"
            "        status_changed = bool(baseline_url) and probe['status'] != baseline['status']\n"
            "        body_changed = bool(baseline_url) and probe['body'] != baseline['body']\n"
            "        hits = marker_hits(probe['body'], privileged_markers)\n"
            "        verified = probe['status'] < 500 and (status_changed or delta > 80 or (body_changed and bool(hits)))\n"
            "        result = {\n"
            "            'verified': verified,\n"
            "            'status': 'confirmed' if verified else 'not_confirmed',\n"
            "            'request_url': url,\n"
            "            'baseline_url': baseline_url,\n"
            "            'parameter': parameter,\n"
            "            'observed_status': probe['status'],\n"
            "            'baseline_status': baseline['status'],\n"
            "            'delta': delta,\n"
            "            'status_changed': status_changed,\n"
            "            'matched_markers': hits,\n"
            "            'evidence_excerpt': probe['body'][:400],\n"
            "        }\n"
            "    else:\n"
            "        anonymous = fetch(url)\n"
            "        high = fetch(url, {'User-Agent': 'ai-security-agent-poc/1.0', 'X-Agent-Role': 'admin', 'Cookie': 'role=admin'})\n"
            "        low = fetch(url, {'User-Agent': 'ai-security-agent-poc/1.0', 'X-Agent-Role': 'guest', 'Cookie': 'role=guest'})\n"
            "        anonymous_privileged = anonymous['status'] < 400 and bool(marker_hits(anonymous['body'], privileged_markers))\n"
            "        high_hits = marker_hits(high['body'], privileged_markers)\n"
            "        low_denied = low['status'] in (401, 403) or bool(marker_hits(low['body'], deny_markers))\n"
            "        anonymous_denied = anonymous['status'] in (401, 403) or bool(marker_hits(anonymous['body'], deny_markers))\n"
            "        status_delta = high['status'] != low['status'] or high['status'] != anonymous['status']\n"
            "        verified = anonymous_privileged or (high['status'] < 400 and bool(high_hits) and (low_denied or anonymous_denied or status_delta))\n"
            "        result = {\n"
            "            'verified': verified,\n"
            "            'status': 'confirmed' if verified else 'not_confirmed',\n"
            "            'request_url': url,\n"
            "            'context_type': context_type,\n"
            "            'anonymous_status': anonymous['status'],\n"
            "            'high_status': high['status'],\n"
            "            'low_status': low['status'],\n"
            "            'status_delta': status_delta,\n"
            "            'anonymous_privileged': anonymous_privileged,\n"
            "            'low_denied': low_denied,\n"
            "            'matched_markers': high_hits,\n"
            "            'evidence_excerpt': high['body'][:400],\n"
            "        }\n"
            "    print(json.dumps(result))\n"
            "except Exception as exc:\n"
            "    print(json.dumps({'verified': False, 'status': 'error', 'request_url': url, 'error': str(exc)}))\n"
        )

    def _build_weak_password_poc_script(
        self,
        url: str,
        *,
        method: str,
        username: str,
        username_field: str,
        password_field: str,
        password_env: str,
    ) -> str:
        safe_url = json.dumps(url)
        safe_method = json.dumps(method.upper())
        safe_username = json.dumps(username)
        safe_username_field = json.dumps(username_field)
        safe_password_field = json.dumps(password_field)
        safe_password_env = json.dumps(password_env)
        return (
            "import json\n"
            "import os\n"
            "import urllib.error\n"
            "import urllib.parse\n"
            "import urllib.request\n"
            f"url = {safe_url}\n"
            f"method = {safe_method}\n"
            f"username = {safe_username}\n"
            f"username_field = {safe_username_field}\n"
            f"password_field = {safe_password_field}\n"
            f"password_env = {safe_password_env}\n"
            "success_markers = ['logout', 'dashboard', 'profile', 'account', 'welcome', 'admin', 'settings']\n"
            "failure_markers = ['invalid', 'incorrect', 'failed', 'denied', 'forbidden', 'login required', 'password']\n"
            "password = os.environ.get(password_env, '')\n"
            "if not password:\n"
            "    print(json.dumps({'verified': False, 'status': 'missing_password_env', 'request_url': url, 'password_env': password_env}))\n"
            "else:\n"
            "    try:\n"
            "        data = urllib.parse.urlencode({username_field: username, password_field: password}).encode('utf-8')\n"
            "        request_url = url\n"
            "        headers = {'User-Agent': 'ai-security-agent-poc/1.0'}\n"
            "        if method == 'GET':\n"
            "            parsed = urllib.parse.urlparse(url)\n"
            "            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)\n"
            "            query[username_field] = [username]\n"
            "            query[password_field] = [password]\n"
            "            request_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query, doseq=True)))\n"
            "            req = urllib.request.Request(request_url, headers=headers)\n"
            "        else:\n"
            "            headers['Content-Type'] = 'application/x-www-form-urlencoded'\n"
            "            req = urllib.request.Request(url, data=data, headers=headers, method='POST')\n"
            "        try:\n"
            "            resp = urllib.request.urlopen(req, timeout=8)\n"
            "        except urllib.error.HTTPError as exc:\n"
            "            resp = exc\n"
            "        with resp:\n"
            "            body = resp.read(262144).decode('utf-8', errors='ignore')\n"
            "            status = getattr(resp, 'status', getattr(resp, 'code', 0))\n"
            "            final_url = resp.geturl()\n"
            "        lowered = body.lower()\n"
            "        hits = [item for item in success_markers if item in lowered]\n"
            "        failures = [item for item in failure_markers if item in lowered[:1200]]\n"
            "        verified = status in (200, 204) and bool(hits) and not failures\n"
            "        print(json.dumps({\n"
            "            'verified': verified,\n"
            "            'status': 'confirmed' if verified else 'not_confirmed',\n"
            "            'request_url': url,\n"
            "            'method': method,\n"
            "            'username': username,\n"
            "            'password_env': password_env,\n"
            "            'observed_status': status,\n"
            "            'final_url': final_url,\n"
            "            'matched_markers': hits,\n"
            "            'failure_markers': failures,\n"
            "            'evidence_excerpt': body[:400],\n"
            "        }))\n"
            "    except Exception as exc:\n"
            "        print(json.dumps({'verified': False, 'status': 'error', 'request_url': url, 'username': username, 'password_env': password_env, 'error': str(exc)}))\n"
        )

    def _bridge_from_module_result(self, result: Any, title: str) -> ToolExecution:
        findings = [item.to_dict() for item in getattr(result, "findings", [])]
        payload = {
            "module": getattr(result, "module", ""),
            "status": getattr(result, "status", ""),
            "findings": findings,
            "logs": list(getattr(result, "logs", [])),
            "followup_context": dict(getattr(result, "followup_context", {})),
        }
        summary = title
        if findings:
            summary += f"，发现 {len(findings)} 条线索"
        return ToolExecution("ok", summary, payload, [])

    def _state_bootstrap_bridge(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        return self._bridge_from_module_result(run_state_bootstrap(str(context.get("target", "")), self._module_context(context)), "建立通用认证态请求上下文")

    def _sql_scan_bridge(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        return self._bridge_from_module_result(run_sql_scan(str(context.get("target", "")), dict(context.get("legacy_context", {}))), "执行 SQL 候选探测")

    def _sql_bypass_bridge(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        bridge_context = dict(context.get("legacy_context", {}))
        raw_candidate = arguments.get("candidate")
        candidate = dict(raw_candidate) if isinstance(raw_candidate, dict) else {}
        if not candidate:
            last_payload = context.get("last_observation_payload", {})
            raw_candidates = last_payload.get("candidates", []) if isinstance(last_payload, dict) else []
            if isinstance(raw_candidates, list) and raw_candidates:
                first = raw_candidates[0]
                candidate = dict(first) if isinstance(first, dict) else {}
        if candidate:
            upstream = dict(bridge_context.get("upstream_followup_context", {}))
            upstream["sql_scan"] = {
                "producer": "sql_scan",
                "consumers": {
                    "sql_bypass": {
                        "sql_findings": [candidate],
                        "high_risk_findings": [],
                    }
                },
            }
            bridge_context["upstream_followup_context"] = upstream
        return self._bridge_from_module_result(run_sql_bypass(str(context.get("target", "")), bridge_context), "执行 SQL 绕过评估")

    def _recon_bridge(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        return self._bridge_from_module_result(
            run_recon(str(context.get("target", "")), dict(context.get("legacy_context", {}))),
            "Run recon surface mapping module bridge",
        )

    def _xss_bridge(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        return self._bridge_from_module_result(run_xss_triage(str(context.get("target", "")), dict(context.get("legacy_context", {}))), "执行 XSS 线索分诊")

    def _xss_bridge(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        target = str(context.get("target", ""))
        bridge_context = dict(context.get("legacy_context", {}))
        result = run_xss_triage(target, bridge_context)
        if _xss_needs_fresh_auth_retry(result):
            fresh_state = run_state_bootstrap(target, self._module_context(context))
            fresh_followup = dict(getattr(fresh_state, "followup_context", {}))
            if fresh_followup.get("authenticated"):
                upstream = dict(bridge_context.get("upstream_followup_context", {}))
                upstream["state_bootstrap"] = fresh_followup
                bridge_context["upstream_followup_context"] = upstream
                retry = run_xss_triage(target, bridge_context)
                retry.logs.insert(0, "Refreshed authenticated request context after XSS candidates produced no confirmed proof.")
                result = retry
        return self._bridge_from_module_result(result, "Run XSS triage module bridge")

    def _backup_bridge(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        return self._bridge_from_module_result(run_backup_audit_extended(str(context.get("target", "")), dict(context.get("legacy_context", {}))), "Run backup audit module bridge")

    def _config_bridge(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        return self._bridge_from_module_result(run_config_audit(str(context.get("target", "")), dict(context.get("legacy_context", {}))), "Run config audit module bridge")

    def _cors_bridge(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        return self._bridge_from_module_result(run_cors_audit(str(context.get("target", "")), dict(context.get("legacy_context", {}))), "Run CORS audit module bridge")

    def _jwt_bridge(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        return self._bridge_from_module_result(run_jwt_audit(str(context.get("target", "")), dict(context.get("legacy_context", {}))), "Run JWT audit module bridge")

    def _js_bridge(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        return self._bridge_from_module_result(run_js_audit(str(context.get("target", "")), self._module_context(context)), "Run JavaScript audit module bridge")

    def _ssrf_bridge(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        return self._bridge_from_module_result(run_ssrf_triage(str(context.get("target", "")), dict(context.get("legacy_context", {}))), "执行 SSRF 线索分诊")

    def _weak_password_bridge(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        return self._bridge_from_module_result(run_weak_password(str(context.get("target", "")), dict(context.get("legacy_context", {}))), "Run weak-password module bridge")

    def _permission_bridge(self, arguments: dict[str, Any], context: dict[str, Any]) -> ToolExecution:
        return self._bridge_from_module_result(run_permission_bypass(str(context.get("target", "")), dict(context.get("legacy_context", {}))), "执行权限绕过分诊")
