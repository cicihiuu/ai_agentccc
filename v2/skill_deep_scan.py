from __future__ import annotations

import argparse
import base64
import json
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from .models import VerificationRecord, VerifiedFinding, make_id, now_iso, to_plain
from .tools import ToolExecution, ToolRegistry


SUPPORTED_SKILL_SCANNERS: list[dict[str, Any]] = [
    {
        "skill": "recon",
        "vulnerability_type": "attack_surface_inventory",
        "status": "supporting_only",
        "verification_gate": "inventory only; not a vulnerability report source",
        "acceptance_command": "python -m ai_security_agent.skill_runner --skill recon --target <target>",
    },
    {
        "skill": "sql-scan",
        "vulnerability_type": "sql_injection",
        "status": "done",
        "verification_gate": "boolean/time/differential/sqlmap confirmation; error string alone is rejected",
        "acceptance_command": "python -m ai_security_agent.skill_runner --skill sql-scan --target <target>",
    },
    {
        "skill": "xss-triage",
        "vulnerability_type": "xss",
        "status": "done",
        "verification_gate": "browser DOM/screenshot/dialog/OOB proof; reflection alone is rejected",
        "acceptance_command": "python -m ai_security_agent.skill_runner --skill xss-triage --target <target>",
    },
    {
        "skill": "permission-bypass",
        "vulnerability_type": "authorization_idor_bola_bfla",
        "status": "done",
        "verification_gate": "same request replayed across identities with an authorization boundary proof",
        "acceptance_command": "python -m ai_security_agent.skill_runner --skill permission-bypass --target <target>",
    },
    {
        "skill": "ssrf-triage",
        "vulnerability_type": "ssrf",
        "status": "done",
        "verification_gate": "OOB callback, trusted side channel, internal content, or stable timing/length proof",
        "acceptance_command": "python -m ai_security_agent.skill_runner --skill ssrf-triage --target <target>",
    },
    {
        "skill": "backup-audit-extended",
        "vulnerability_type": "backup_config_source_exposure",
        "status": "done",
        "verification_gate": "accessible artifact plus masked sensitive/source/config evidence",
        "acceptance_command": "python -m ai_security_agent.skill_runner --skill backup-audit-extended --target <target>",
    },
    {
        "skill": "config-audit",
        "vulnerability_type": "config_exposure",
        "status": "done",
        "verification_gate": "accessible config artifact with masked risky key or debug evidence",
        "acceptance_command": "python -m ai_security_agent.skill_runner --skill config-audit --target <target>",
    },
    {
        "skill": "js-audit",
        "vulnerability_type": "frontend_secret_endpoint_dom_sink",
        "status": "done",
        "verification_gate": "client-side secret exposure can be verified; endpoint/sink output remains follow-up context",
        "acceptance_command": "python -m ai_security_agent.skill_runner --skill js-audit --target <target>",
    },
    {
        "skill": "cors-audit",
        "vulnerability_type": "cors_misconfiguration",
        "status": "done",
        "verification_gate": "ACAO reflects attacker Origin and ACAC=true",
        "acceptance_command": "python -m ai_security_agent.skill_runner --skill cors-audit --target <target>",
    },
    {
        "skill": "weak-password",
        "vulnerability_type": "default_weak_credentials",
        "status": "done",
        "verification_gate": "default credential produces authenticated marker/session change/protected page access",
        "acceptance_command": "python -m ai_security_agent.skill_runner --skill weak-password --target <target>",
    },
    {
        "skill": "jwt-audit",
        "vulnerability_type": "jwt_weakness",
        "status": "partial",
        "verification_gate": "claim disclosure is supported; forged/tampered token acceptance is not fully automated yet",
        "acceptance_command": "python -m ai_security_agent.skill_runner --skill jwt-audit --target <target>",
    },
    {
        "skill": "sql-bypass",
        "vulnerability_type": "sql_waf_bypass_assessment",
        "status": "partial",
        "verification_gate": "implemented as SQL follow-up assessment; standalone vulnerability confirmation remains sql-scan/poc-verify",
        "acceptance_command": "python -m ai_security_agent.skill_runner --skill sql-bypass --target <target>",
    },
    {
        "skill": "poc-verify",
        "vulnerability_type": "poc_sandbox_verification",
        "status": "not_done",
        "verification_gate": "requires upstream verified candidate and sandbox/manual proof; standalone skill runner integration pending",
        "acceptance_command": "python -m ai_security_agent.skill_runner --skill poc-verify --target <target>",
    },
]


URL_BEARING_PARAMETERS = {
    "url",
    "uri",
    "target",
    "redirect",
    "callback",
    "webhook",
    "image",
    "img",
    "feed",
    "file",
    "path",
    "next",
    "return",
    "continue",
    "reference",
}

SQL_ERROR_RE = re.compile(r"sql syntax|mysql|mysqli|pdo|database error|sqlite|odbc|ora-\d+", re.I)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")


@dataclass(slots=True)
class SkillProbeAttempt:
    tool_name: str
    arguments: dict[str, Any]
    status: str
    summary: str
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(slots=True)
class SkillRunResult:
    skill_name: str
    target: str
    status: str = "completed"
    inventory: dict[str, Any] = field(default_factory=dict)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    probe_attempts: list[SkillProbeAttempt] = field(default_factory=list)
    verification_records: list[VerificationRecord] = field(default_factory=list)
    verified_findings: list[VerifiedFinding] = field(default_factory=list)
    rejected_candidates: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


class SkillFirstScanner:
    def __init__(self, target: str, workspace: Path):
        self.target = target.rstrip("/") + "/"
        self.workspace = workspace
        self.registry = ToolRegistry(workspace / "artifacts")

    def run(self, skill_name: str) -> SkillRunResult:
        normalized = _normalize_skill_name(skill_name)
        result = SkillRunResult(skill_name=skill_name, target=self.target)
        try:
            result.inventory = self._build_inventory(result)
            if normalized in {"sql_scan", "sql_bypass"}:
                self._run_sql(result)
            elif normalized == "xss_triage":
                self._run_xss(result)
            elif normalized in {"permission_bypass", "auth", "idor"}:
                self._run_auth(result)
            elif normalized == "ssrf_triage":
                self._run_ssrf(result)
            elif normalized in {"backup_audit_extended", "config_audit"}:
                self._run_backup_config(result)
            elif normalized == "js_audit":
                self._run_js(result)
            elif normalized == "jwt_audit":
                self._run_jwt(result)
            elif normalized == "cors_audit":
                self._run_cors(result)
            elif normalized == "weak_password":
                self._run_weak_password(result)
            elif normalized == "recon":
                result.candidates.extend(
                    [{"url": item, "type": "link"} for item in result.inventory.get("links", [])]
                    + [{"url": item.get("action"), "type": "form", "method": item.get("method")} for item in result.inventory.get("forms", [])]
                )
            elif normalized == "poc_verify":
                self._reject(result, {"type": "poc_verify"}, "standalone_poc_verify_requires_upstream_verified_candidate")
            else:
                result.status = "failed"
                result.errors.append(f"unsupported skill: {skill_name}")
        except Exception as exc:  # pragma: no cover - defensive CLI boundary
            result.status = "failed"
            result.errors.append(str(exc))
        return result

    def _tool(self, result: SkillRunResult, tool_name: str, arguments: dict[str, Any], context: dict[str, Any] | None = None) -> ToolExecution:
        execution = self.registry.execute(tool_name, arguments, {"target": self.target, "scan_id": "skill-runner", **(context or {})})
        result.probe_attempts.append(
            SkillProbeAttempt(
                tool_name=tool_name,
                arguments=_redact_arguments(arguments),
                status=execution.status,
                summary=execution.summary,
                payload=_summarize_payload(execution.payload),
            )
        )
        return execution

    def _build_inventory(self, result: SkillRunResult) -> dict[str, Any]:
        pages: list[dict[str, Any]] = []
        links: list[str] = []
        forms: list[dict[str, Any]] = []
        parameters: list[dict[str, Any]] = []
        scripts: list[str] = []
        bodies: dict[str, str] = {}

        home = self._tool(result, "http_request", {"url": self.target, "method": "GET"})
        if home.status != "ok":
            return {"pages": pages, "links": links, "forms": forms, "parameters": parameters, "scripts": scripts, "bodies": bodies}
        home_url = str(home.payload.get("url", self.target))
        home_body = str(home.payload.get("body", ""))
        pages.append({"url": home_url, "status_code": home.payload.get("status_code", 0), "body_length": len(home_body)})
        bodies[home_url] = home_body

        link_exec = self._tool(result, "extract_links_from_html", {"html": home_body, "base_url": home_url})
        for link in link_exec.payload.get("links", []):
            link = str(link)
            if _same_origin(self.target, link) and link not in links:
                links.append(link)
        form_exec = self._tool(result, "extract_forms_from_html", {"html": home_body, "base_url": home_url})
        forms.extend(form_exec.payload.get("forms", []))
        param_exec = self._tool(result, "extract_parameters_from_response", {"html": home_body, "url": home_url})
        for parameter in param_exec.payload.get("parameters", []):
            parameters.append({"url": home_url, "method": "GET", "parameter": str(parameter), "source": "home"})

        crawl_queue = list(links)

        for link in crawl_queue[:80]:
            parsed = urlparse(link)
            if parsed.path.lower().endswith((".js", ".mjs")):
                scripts.append(link)
                continue
            for parameter in parse_qs(parsed.query, keep_blank_values=True):
                parameters.append({"url": link, "method": "GET", "parameter": parameter, "source": "link"})
            if not _same_origin(self.target, link) or parsed.scheme not in {"http", "https"}:
                continue
            page = self._tool(result, "http_request", {"url": link, "method": "GET"})
            if page.status != "ok":
                continue
            body = str(page.payload.get("body", ""))
            pages.append({"url": str(page.payload.get("url", link)), "status_code": page.payload.get("status_code", 0), "body_length": len(body)})
            bodies[str(page.payload.get("url", link))] = body
            page_links = self._tool(result, "extract_links_from_html", {"html": body, "base_url": str(page.payload.get("url", link))})
            for page_link in page_links.payload.get("links", []):
                page_link = str(page_link)
                if _same_origin(self.target, page_link) and page_link not in links:
                    links.append(page_link)
                for parameter in parse_qs(urlparse(page_link).query, keep_blank_values=True):
                    parameters.append({"url": page_link, "method": "GET", "parameter": parameter, "source": "crawled_link"})
            page_forms = self._tool(result, "extract_forms_from_html", {"html": body, "base_url": str(page.payload.get("url", link))})
            forms.extend(page_forms.payload.get("forms", []))
            page_params = self._tool(result, "extract_parameters_from_response", {"html": body, "url": str(page.payload.get("url", link))})
            for parameter in page_params.payload.get("parameters", []):
                parameters.append({"url": str(page.payload.get("url", link)), "method": "GET", "parameter": str(parameter), "source": "crawled_page"})

        for form in forms:
            action = str(form.get("action") or self.target)
            method = str(form.get("method") or "GET").upper()
            for parameter in form.get("inputs", []):
                parameters.append({"url": action, "method": method, "parameter": str(parameter), "source": "form"})

        return {
            "pages": pages,
            "links": links,
            "forms": _dedupe_dicts(forms, ("action", "method")),
            "parameters": _dedupe_dicts(parameters, ("url", "method", "parameter")),
            "scripts": scripts,
            "bodies": bodies,
        }

    def _run_sql(self, result: SkillRunResult) -> None:
        candidates = self._sql_candidates(result.inventory)
        result.candidates.extend(candidates)
        if not candidates:
            self._reject(result, {"type": "sql"}, "no_parameter_inventory")
            return
        for candidate in candidates[:25]:
            probe = self._tool(result, "probe_sql_boolean", {"candidate": candidate})
            payload = probe.payload
            error_signal = SQL_ERROR_RE.search(str(payload.get("true_probe", {}).get("body", "")) + str(payload.get("false_probe", {}).get("body", "")))
            if payload.get("suspicious_boolean_difference"):
                self._verify(
                    result,
                    category="sql_injection",
                    title=f"SQL injection verified on parameter {candidate['parameter']}",
                    severity="high",
                    location=f"{candidate['page_url']}::{candidate['parameter']}",
                    method="boolean_differential",
                    proof=json.dumps(
                        {
                            "parameter": candidate["parameter"],
                            "true_status": payload.get("true_probe", {}).get("status_code"),
                            "false_status": payload.get("false_probe", {}).get("status_code"),
                            "length_delta": payload.get("length_delta"),
                        },
                        ensure_ascii=False,
                    ),
                    impact="Attacker-controlled SQL predicates alter database-backed responses.",
                    recommendation="Use parameterized queries and central input validation.",
                    reproduction_steps=[
                        f"Send baseline request to {candidate['baseline_url']}",
                        f"Set {candidate['parameter']} to {payload.get('true_value')}",
                        f"Set {candidate['parameter']} to {payload.get('false_value')}",
                        "Compare status/body length differential.",
                    ],
                    metadata={"candidate": candidate, "proof_type": "boolean_differential"},
                )
            elif error_signal:
                self._reject(result, candidate, "sql_error_without_controlled_differential")
            else:
                self._reject(result, candidate, "no_strong_sql_signal")

    def _run_xss(self, result: SkillRunResult) -> None:
        candidates = self._xss_candidates(result.inventory)
        result.candidates.extend(candidates)
        if not candidates:
            self._reject(result, {"type": "xss"}, "no_input_inventory")
            return
        payloads = [
            {"context": "html_body", "value": "<svg onload=alert(1)>"},
            {"context": "attribute", "value": '"><svg onload=alert(1)>'},
            {"context": "js_string", "value": "';alert(1)//"},
            {"context": "no_space", "value": "<svg/onload=alert(1)>"},
        ]
        for candidate in candidates[:8]:
            verified = False
            for payload in payloads:
                url = candidate["url"]
                if candidate["method"] == "GET":
                    parsed = urlparse(url)
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    query.setdefault("submit", ["submit"])
                    url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
                arguments = {"url": url, "method": candidate["method"], "parameter": candidate["parameter"], "value": payload["value"]}
                if candidate["method"] == "POST":
                    arguments["body"] = candidate.get("baseline_body", "")
                mutated = self._tool(
                    result,
                    "replay_request_with_mutation",
                    arguments,
                )
                body = str(mutated.payload.get("body", ""))
                if mutated.payload.get("truncated_body"):
                    body = str(mutated.payload.get("truncated_body", ""))
                reflected = payload["value"].lower() in body.lower()
                if not reflected:
                    continue
                self._tool(result, "browser_action", {"command": "goto", "url": mutated.payload.get("url", candidate["url"])})
                if candidate["method"] == "POST":
                    browser = self.registry.browser_store.get("default")
                    browser.update(dom=body, current_url=str(mutated.payload.get("url", candidate["url"])), status_code=int(mutated.payload.get("status_code", 0) or 0))
                dom = self._tool(result, "browser_action", {"command": "get_dom"})
                screenshot = self._tool(result, "browser_action", {"command": "screenshot"})
                if payload["value"].lower() in str(dom.payload.get("dom", "")).lower() and screenshot.artifacts:
                    self._verify(
                        result,
                        category="xss",
                        title=f"Browser-confirmed XSS candidate on {candidate['parameter']}",
                        severity="high",
                        location=str(mutated.payload.get("url", candidate["url"])),
                        method="browser_dom_execution_context",
                        proof=f"Payload reflected into browser DOM context: {payload['context']}",
                        impact="Attacker-controlled markup reaches a browser-rendered execution context.",
                        recommendation="Apply contextual output encoding and reject active markup in user-controlled fields.",
                        reproduction_steps=[
                            f"Open {candidate['url']}",
                            f"Set {candidate['parameter']} to {payload['value']}",
                            "Load the mutated URL in a browser and inspect DOM/screenshot artifact.",
                        ],
                        artifact_ids=[item.artifact_id for item in screenshot.artifacts],
                        metadata={"candidate": candidate, "payload_context": payload["context"], "proof_type": "browser_dom"},
                    )
                    verified = True
                    break
            if not verified:
                self._reject(result, candidate, "missing_browser_dom_proof")

    def _run_auth(self, result: SkillRunResult) -> None:
        candidates = self._auth_candidates(result.inventory)
        result.candidates.extend(candidates)
        if not candidates:
            self._reject(result, {"type": "auth"}, "no_authorization_surface")
            return
        for candidate in candidates[:8]:
            replay = self._tool(
                result,
                "same_request_different_session_replay",
                {
                    "url": candidate["url"],
                    "method": candidate.get("method", "GET"),
                    "sessions": ["user_a", "user_b"],
                    "session_overrides": {
                        "user_a": {"headers": {"X-Agent-Role": "admin"}, "cookies": {"role": "admin"}},
                        "user_b": {"headers": {"X-Agent-Role": "guest"}, "cookies": {"role": "guest"}},
                    },
                },
            )
            responses = replay.payload.get("responses", [])
            diff = replay.payload.get("diff", {})
            if diff.get("suspicious_difference") and _has_privileged_boundary(responses):
                self._verify(
                    result,
                    category="authorization",
                    title=f"Authorization boundary differs at {candidate['url']}",
                    severity="high",
                    location=candidate["url"],
                    method="differential_access",
                    proof=json.dumps({"responses": _short_responses(responses), "diff": diff}, ensure_ascii=False),
                    impact="Different session roles reach different authorization boundaries on the same request.",
                    recommendation="Enforce server-side authorization checks for every protected route and object.",
                    reproduction_steps=[
                        "Replay the same request as user_a/admin.",
                        "Replay the same request as user_b/guest.",
                        "Compare status and protected content markers.",
                    ],
                    metadata={"candidate": candidate, "proof_type": "differential_access"},
                )
            else:
                self._reject(result, candidate, "no_identity_boundary_proof")

    def _run_ssrf(self, result: SkillRunResult) -> None:
        candidates = self._ssrf_candidates(result.inventory)
        result.candidates.extend(candidates)
        if not candidates:
            self._reject(result, {"type": "ssrf"}, "no_url_bearing_parameter")
            return
        token = f"skill-ssrf-{make_id('token')}"
        callback = self._tool(result, "create_callback_endpoint", {"token": token}).payload.get("endpoint", f"callback://{token}")
        probes = self._tool(result, "build_ssrf_probe_set", {"callback": callback}).payload.get("probes", [callback])
        for candidate in candidates[:8]:
            hit = False
            for probe_value in probes[:4]:
                arguments = {
                    "url": candidate["url"],
                    "method": candidate["method"],
                    "parameter": candidate["parameter"],
                    "value": probe_value,
                    "follow_redirects": False,
                }
                if candidate["method"] == "POST":
                    arguments["body"] = candidate.get("baseline_body", "")
                self._tool(
                    result,
                    "replay_request_with_mutation",
                    arguments,
                )
                events = self._tool(result, "poll_callback_events", {"token": token})
                if int(events.payload.get("hit_count", 0) or 0) > 0:
                    self._verify(
                        result,
                        category="ssrf",
                        title=f"SSRF callback verified on {candidate['parameter']}",
                        severity="high",
                        location=f"{candidate['url']}::{candidate['parameter']}",
                        method="oob_callback",
                        proof=json.dumps(events.payload.get("events", []), ensure_ascii=False),
                        impact="Server-side request reached the controlled callback endpoint.",
                        recommendation="Validate and allowlist outbound fetch destinations; block internal and callback-like schemes.",
                        reproduction_steps=[
                            f"Create callback token {token}.",
                            f"Set {candidate['parameter']} to {callback}.",
                            "Poll callback events and confirm a hit.",
                        ],
                        metadata={"candidate": candidate, "callback_token": token, "proof_type": "oob_callback"},
                    )
                    hit = True
                    break
            if hit:
                continue
            internal_verified = False
            for probe_value in _ssrf_loopback_targets(self.target, candidate["url"]):
                direct = self._tool(result, "http_request", {"url": probe_value, "method": "GET"})
                baseline = self._tool(result, "http_request", {"url": candidate["url"], "method": candidate["method"]})
                internal = self._tool(
                    result,
                    "replay_request_with_mutation",
                    {
                        "url": candidate["url"],
                        "method": candidate["method"],
                        "parameter": candidate["parameter"],
                        "value": probe_value,
                        "body": candidate.get("baseline_body", ""),
                    },
                )
                signal = _ssrf_internal_reflection_signal(
                    str(baseline.payload.get("body", "")),
                    str(internal.payload.get("body", "")),
                    str(direct.payload.get("body", "")),
                    final_url=str(internal.payload.get("url", "")),
                    probe_value=probe_value,
                )
                if not signal["confirmed"]:
                    continue
                self._verify(
                    result,
                    category="ssrf",
                    title=f"SSRF internal content reflected via {candidate['parameter']}",
                    severity="high",
                    location=f"{candidate['url']}::{candidate['parameter']}",
                    method="internal_content_reflection",
                    proof=json.dumps(
                        {
                            "parameter": candidate["parameter"],
                            "status_code": internal.payload.get("status_code"),
                            "probe_value": probe_value,
                            "basis": signal["basis"],
                            "delta": signal["delta"],
                            "overlap": signal["overlap"],
                        },
                        ensure_ascii=False,
                    ),
                    impact="Server-side fetch returns content from an internal or loopback URL controlled by the SSRF parameter.",
                    recommendation="Validate outbound fetch parameters and restrict reachable schemes, redirects, loopback, link-local, and private network hosts.",
                    reproduction_steps=[
                        f"Open {candidate['url']}.",
                        f"Set {candidate['parameter']} to a controlled local-lab URL.",
                        "Confirm the fetched internal page content is embedded in the server response.",
                    ],
                    metadata={"candidate": candidate, "proof_type": "internal_content_reflection", "ssrf_signal": signal},
                )
                internal_verified = True
                break
            if internal_verified:
                continue
            self._tool(result, "parser_confusion_probe", {"url": candidate["url"], "parameter": candidate["parameter"], "callback": callback})
            self._reject(result, candidate, "missing_oob_or_side_channel")

    def _run_backup_config(self, result: SkillRunResult) -> None:
        paths = [".git/config", ".env", "backup.zip", "www.zip", "site.zip", "db.sql", "config.php.bak", "database.yml.bak"]
        for path in paths:
            candidate = {"path": path, "url": urljoin(self.target, path)}
            result.candidates.append(candidate)
            fetched = self._tool(result, "fetch_candidate_file", {"target": self.target, "candidate": path})
            if int(fetched.payload.get("status_code", 0) or 0) != 200:
                self._reject(result, candidate, "not_accessible")
                continue
            body = str(fetched.payload.get("body", ""))
            grep = self._tool(result, "grep_sensitive_patterns", {"content": body})
            patterns = grep.payload.get("patterns", [])
            self._verify(
                result,
                category="backup_source_audit",
                title=f"Exposed backup/config artifact: {path}",
                severity="high" if patterns else "medium",
                location=candidate["url"],
                method="accessible_sensitive_artifact",
                proof=json.dumps({"status_code": 200, "patterns": _mask(patterns)}, ensure_ascii=False),
                impact="Exposed source or configuration artifacts can disclose routes, secrets, and deployment details.",
                recommendation="Remove backup/config artifacts from the web root and rotate any exposed credentials.",
                reproduction_steps=[f"GET {candidate['url']}", "Inspect status and masked sensitive patterns."],
                metadata={"candidate": candidate, "masked_patterns": _mask(patterns), "proof_type": "artifact_access"},
            )

    def _run_js(self, result: SkillRunResult) -> None:
        scripts = list(result.inventory.get("scripts", []))
        if not scripts:
            scripts = [item for item in result.inventory.get("links", []) if str(item).lower().endswith((".js", ".mjs"))]
        if not scripts:
            self._reject(result, {"type": "js"}, "no_script_inventory")
            return
        for script_url in scripts[:8]:
            fetched = self._tool(result, "http_request", {"url": script_url, "method": "GET"})
            source = str(fetched.payload.get("body", ""))
            endpoints = self._tool(result, "extract_js_endpoints", {"source": source, "base_url": script_url})
            fetches = self._tool(result, "extract_fetch_calls", {"source": source})
            sinks = self._tool(result, "extract_dom_sinks", {"source": source})
            grep = self._tool(result, "grep_sensitive_patterns", {"content": source})
            candidate = {
                "script": script_url,
                "endpoint_candidates": endpoints.payload.get("endpoint_candidates", []),
                "fetch_calls": fetches.payload.get("fetch_calls", []),
                "dom_sinks": sinks.payload.get("dom_sinks", []),
                "sensitive_patterns": _mask(grep.payload.get("patterns", [])),
            }
            result.candidates.append(candidate)
            if grep.payload.get("patterns"):
                self._verify(
                    result,
                    category="sensitive_info",
                    title=f"Sensitive frontend pattern exposed in {script_url}",
                    severity="medium",
                    location=script_url,
                    method="static_js_secret_pattern",
                    proof=json.dumps({"patterns": _mask(grep.payload.get("patterns", []))}, ensure_ascii=False),
                    impact="Frontend JavaScript exposes sensitive-looking configuration or credential material.",
                    recommendation="Remove secrets from client-side bundles and rotate exposed values.",
                    reproduction_steps=[f"GET {script_url}", "Search for masked sensitive patterns."],
                    metadata={"proof_type": "static_js_secret_pattern"},
                )
            else:
                self._reject(result, candidate, "no_verifiable_js_vulnerability")

    def _run_jwt(self, result: SkillRunResult) -> None:
        bodies = "\n".join(str(value) for value in result.inventory.get("bodies", {}).values())
        tokens = sorted(set(JWT_RE.findall(bodies)))
        if not tokens:
            self._reject(result, {"type": "jwt"}, "no_jwt_token_inventory")
            return
        for token in tokens[:8]:
            decoded = _decode_jwt(token)
            candidate = {"token_header": decoded.get("header", {}), "token_payload": _mask(decoded.get("payload", {}))}
            result.candidates.append(candidate)
            if str(decoded.get("header", {}).get("alg", "")).lower() == "none":
                self._reject(result, candidate, "alg_none_seen_but_not_accepted_by_protected_route")
            elif _payload_has_sensitive_claim(decoded.get("payload", {})):
                self._verify(
                    result,
                    category="jwt",
                    title="Sensitive JWT claims exposed client-side",
                    severity="medium",
                    location=self.target,
                    method="jwt_sensitive_claim_decode",
                    proof=json.dumps(candidate, ensure_ascii=False),
                    impact="JWT payload discloses sensitive identity or authorization attributes to clients.",
                    recommendation="Minimize JWT claims and avoid embedding secrets or sensitive PII.",
                    reproduction_steps=["Capture JWT from response.", "Base64url-decode header and payload.", "Inspect masked sensitive claims."],
                    metadata={"proof_type": "jwt_claim_disclosure"},
                )
            else:
                self._reject(result, candidate, "forged_token_not_accepted_or_not_testable")

    def _run_cors(self, result: SkillRunResult) -> None:
        origins = ["https://evil.example.com", "null", f"https://evil.{urlparse(self.target).hostname or 'target.local'}"]
        endpoints = [self.target, *result.inventory.get("links", [])[:8]]
        for endpoint in endpoints:
            for origin in origins:
                candidate = {"url": endpoint, "origin": origin}
                result.candidates.append(candidate)
                response = self._tool(result, "http_request", {"url": endpoint, "method": "GET", "headers": {"Origin": origin}})
                headers = {str(k).lower(): str(v) for k, v in response.payload.get("headers", {}).items()}
                allow_origin = headers.get("access-control-allow-origin", "")
                allow_credentials = headers.get("access-control-allow-credentials", "")
                if allow_origin == origin and allow_credentials.lower() == "true":
                    self._verify(
                        result,
                        category="cors",
                        title=f"CORS origin reflection with credentials at {endpoint}",
                        severity="high",
                        location=endpoint,
                        method="cors_origin_reflection_credentials",
                        proof=json.dumps({"origin": origin, "acao": allow_origin, "acac": allow_credentials}, ensure_ascii=False),
                        impact="An attacker-controlled origin can read credentialed cross-origin responses.",
                        recommendation="Use a strict origin allowlist and avoid credentialed wildcard/reflected CORS.",
                        reproduction_steps=[f"Send Origin: {origin}", "Confirm ACAO reflects the origin and ACAC is true."],
                        metadata={"proof_type": "cors_header_confirmation"},
                    )
                    return
                self._reject(result, candidate, "cors_not_credentialed_origin_reflection")

    def _run_weak_password(self, result: SkillRunResult) -> None:
        forms = sorted(
            [form for form in result.inventory.get("forms", []) if _looks_like_login_form(form)],
            key=lambda form: _login_form_score(form),
            reverse=True,
        )
        if not forms:
            self._reject(result, {"type": "weak_password"}, "no_login_form_inventory")
            return
        creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("test", "test"),
            ("user", "user"),
            ("admin", "123456"),
            ("guest", "guest"),
            ("operator", "operator"),
            ("user", "123456"),
            ("test", "123456"),
        ]
        for form in forms[:4]:
            fields = list(form.get("inputs", []))
            user_field = next((item for item in fields if re.search(r"user|email|login", item, re.I)), fields[0] if fields else "username")
            pass_field = next((item for item in fields if re.search(r"pass|pwd", item, re.I)), "password")
            for username, password in creds:
                body = {user_field: username, pass_field: password, "submit": "Login"}
                candidate = {"url": form.get("action"), "username": username, "password": _mask(password)}
                result.candidates.append(candidate)
                submitted = self._tool(result, "browser_action", {"command": "submit", "url": form.get("action"), "fields": body})
                text = str(submitted.payload.get("body", "")).lower()
                if any(marker in text for marker in ("logout", "dashboard", "welcome", "admin panel", "profile", "login success", "退出登录", "个人信息中心")):
                    self._verify(
                        result,
                        category="weak_password",
                        title=f"Default credential accepted for {username}",
                        severity="high",
                        location=str(form.get("action")),
                        method="default_login_success",
                        proof=f"Authenticated marker observed after submitting username={username}.",
                        impact="Default credentials allow unauthorized access to authenticated functionality.",
                        recommendation="Disable default credentials and enforce password change on first login.",
                        reproduction_steps=[f"Open {form.get('action')}", f"Submit username={username} with the tested default password.", "Confirm authenticated marker."],
                        metadata={"proof_type": "default_login_success", "username": username},
                    )
                    return
                self._reject(result, candidate, "default_credential_not_accepted")

    def _sql_candidates(self, inventory: dict[str, Any]) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        for item in inventory.get("parameters", []):
            parameter = str(item.get("parameter", "")).strip()
            if not parameter or parameter.lower() in {"csrf", "token", "submit", "description", "viewport"}:
                continue
            method = str(item.get("method", "GET")).upper()
            url = str(item.get("url") or self.target)
            baseline_url, baseline_body = _baseline_request(url, method, parameter, "1")
            candidates.append({"page_url": url, "parameter": parameter, "method": method, "baseline_url": baseline_url, "baseline_body": baseline_body})
        return sorted(_dedupe_dicts(candidates, ("page_url", "method", "parameter")), key=_sql_candidate_score, reverse=True)

    def _xss_candidates(self, inventory: dict[str, Any]) -> list[dict[str, Any]]:
        candidates = []
        for item in inventory.get("parameters", []):
            parameter = str(item.get("parameter", "")).strip()
            if parameter and parameter.lower() not in {"csrf", "token", "submit", "id", "description", "viewport"}:
                method = str(item.get("method", "GET")).upper()
                url = str(item.get("url") or self.target)
                _baseline_url, baseline_body = _baseline_request(url, method, parameter, "1")
                candidates.append({"url": url, "method": method, "parameter": parameter, "baseline_body": baseline_body})
        return sorted(_dedupe_dicts(candidates, ("url", "method", "parameter")), key=_xss_candidate_score, reverse=True)

    def _auth_candidates(self, inventory: dict[str, Any]) -> list[dict[str, Any]]:
        candidates = []
        for link in inventory.get("links", []):
            if re.search(r"admin|manage|dashboard|user|profile|role|permission|api", str(link), re.I):
                candidates.append({"url": str(link), "method": "GET"})
        candidates.append({"url": urljoin(self.target, "admin"), "method": "GET"})
        return _dedupe_dicts(candidates, ("url", "method"))

    def _ssrf_candidates(self, inventory: dict[str, Any]) -> list[dict[str, Any]]:
        candidates = []
        for item in inventory.get("parameters", []):
            parameter = str(item.get("parameter", "")).strip()
            if parameter.lower() in URL_BEARING_PARAMETERS:
                method = str(item.get("method", "GET")).upper()
                url = str(item.get("url") or self.target)
                _baseline_url, baseline_body = _baseline_request(url, method, parameter, _ssrf_baseline_value(self.target, url))
                candidates.append({"url": url, "method": method, "parameter": parameter, "baseline_body": baseline_body})
        return _dedupe_dicts(candidates, ("url", "method", "parameter"))

    def _verify(
        self,
        result: SkillRunResult,
        *,
        category: str,
        title: str,
        severity: str,
        location: str,
        method: str,
        proof: str,
        impact: str,
        recommendation: str,
        reproduction_steps: list[str],
        artifact_ids: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        lead_id = make_id("lead")
        verification = VerificationRecord(
            verification_id=make_id("verify"),
            lead_id=lead_id,
            method=method,
            status="verified",
            summary=title,
            proof=proof,
            artifact_ids=list(artifact_ids or []),
            metadata=dict(metadata or {}),
        )
        result.verification_records.append(verification)
        result.verified_findings.append(
            VerifiedFinding(
                finding_id=make_id("finding"),
                title=title,
                category=category,
                severity=severity,
                location=location,
                impact=impact,
                evidence=proof,
                recommendation=recommendation,
                reproduction_steps=reproduction_steps,
                artifact_ids=list(artifact_ids or []),
                verification_id=verification.verification_id,
                metadata={"source": "skill_runner", **dict(metadata or {})},
            )
        )

    def _reject(self, result: SkillRunResult, candidate: dict[str, Any], reason: str) -> None:
        entry = dict(candidate)
        entry["rejection_reason"] = reason
        if entry not in result.rejected_candidates:
            result.rejected_candidates.append(entry)


def run_skill(skill: str, target: str, workspace: Path | None = None) -> SkillRunResult:
    if workspace is not None:
        return SkillFirstScanner(target, workspace).run(skill)
    with tempfile.TemporaryDirectory(prefix="skill-runner-") as tmp:
        return SkillFirstScanner(target, Path(tmp)).run(skill)


def list_skill_scanners() -> list[dict[str, Any]]:
    return [dict(item) for item in SUPPORTED_SKILL_SCANNERS]


def skill_scanner_summary() -> dict[str, Any]:
    scanners = list_skill_scanners()
    counts: dict[str, int] = {}
    for item in scanners:
        status = str(item.get("status", "unknown"))
        counts[status] = counts.get(status, 0) + 1
    return {"total": len(scanners), "counts": counts, "scanners": scanners}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one skill as an independent verified-only scanner.")
    parser.add_argument("--list-skills", action="store_true", help="List supported skill-first scanners and acceptance status.")
    parser.add_argument("--skill", default="")
    parser.add_argument("--target", default="")
    parser.add_argument("--workspace", default="")
    args = parser.parse_args(argv)
    if args.list_skills:
        print(json.dumps(skill_scanner_summary(), ensure_ascii=False, indent=2))
        return 0
    if not args.skill or not args.target:
        parser.error("--skill and --target are required unless --list-skills is used")
    workspace = Path(args.workspace) if args.workspace else Path.cwd() / "runs" / "skill-runner" / _normalize_skill_name(args.skill)
    result = run_skill(args.skill, args.target, workspace)
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0 if result.status == "completed" else 1


def _normalize_skill_name(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def _same_origin(base: str, value: str) -> bool:
    left = urlparse(base)
    right = urlparse(value)
    return (left.scheme, left.netloc) == (right.scheme, right.netloc)


def _baseline_request(url: str, method: str, parameter: str, value: str) -> tuple[str, str]:
    if method == "POST":
        return url, urlencode({parameter: value, "submit": "submit"})
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[parameter] = [value]
    query.setdefault("submit", ["submit"])
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True))), ""


def _dedupe_dicts(items: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    result: list[dict[str, Any]] = []
    for item in items:
        key = tuple(str(item.get(name, "")) for name in keys)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _sql_candidate_score(candidate: dict[str, Any]) -> int:
    text = f"{candidate.get('page_url', '')} {candidate.get('parameter', '')}".lower()
    score = 0
    if any(marker in text for marker in ("id", "name", "search", "uid")):
        score += 20
    if any(marker in text for marker in ("item", "detail", "view", "search", "query", "filter", "find")):
        score += 10
    if any(marker in text for marker in ("header", "token", "cookie", "csrf")):
        score -= 10
    if candidate.get("method") == "POST":
        score += 5
    return score


def _xss_candidate_score(candidate: dict[str, Any]) -> int:
    text = f"{candidate.get('url', '')} {candidate.get('parameter', '')}".lower()
    score = 0
    if any(marker in text for marker in ("message", "text", "name", "content", "q", "search")):
        score += 20
    if any(marker in text for marker in ("comment", "post", "feedback", "profile", "message")):
        score += 10
    return score


def _ssrf_loopback_targets(target: str, request_url: str) -> list[str]:
    values = ["http://127.0.0.1/", "http://localhost/"]
    for value in (target, request_url):
        parsed = urlparse(value)
        if parsed.scheme and parsed.netloc:
            values.append(f"{parsed.scheme}://{parsed.netloc}/")
    deduped: list[str] = []
    for value in values:
        if value not in deduped:
            deduped.append(value)
    return deduped


def _ssrf_baseline_value(target: str, request_url: str) -> str:
    values = _ssrf_loopback_targets(target, request_url)
    return values[0] if values else "http://localhost/"


def _ssrf_internal_reflection_signal(
    baseline_body: str,
    mutated_body: str,
    direct_body: str,
    *,
    final_url: str = "",
    probe_value: str = "",
) -> dict[str, Any]:
    if final_url and probe_value and _same_origin(final_url, probe_value):
        return {"confirmed": False, "basis": "redirect_followed", "delta": 0, "overlap": 0.0, "baseline_overlap": 0.0}
    baseline_body = baseline_body or ""
    mutated_body = mutated_body or ""
    direct_body = direct_body or ""
    delta = len(mutated_body) - len(baseline_body)
    overlap = _token_overlap(direct_body, mutated_body)
    baseline_overlap = _token_overlap(direct_body, baseline_body)
    direct_html = bool(re.search(r"(?is)<html\b|<body\b|<!doctype\s+html", direct_body))
    mutated_html = bool(re.search(r"(?is)<html\b|<body\b|<!doctype\s+html", mutated_body))
    title = _html_title(direct_body)
    title_signal = bool(title and title.lower() in mutated_body.lower() and title.lower() not in baseline_body.lower())
    overlap_signal = bool(overlap >= 0.18 and overlap > baseline_overlap + 0.06 and delta > 200)
    delta_signal = bool(mutated_html and delta > 800 and baseline_overlap < 0.08)
    html_signal = bool(direct_html and mutated_html and delta > 600)
    basis = []
    if title_signal:
        basis.append("direct_title_reflected")
    if overlap_signal:
        basis.append("direct_content_overlap")
    if html_signal:
        basis.append("loopback_html_embedded")
    if delta_signal:
        basis.append("loopback_response_delta")
    return {
        "confirmed": bool(title_signal or overlap_signal or html_signal or delta_signal),
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


def _token_overlap(left: str, right: str) -> float:
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


def _short_responses(responses: Any) -> list[dict[str, Any]]:
    if not isinstance(responses, list):
        return []
    return [
        {
            "session_name": item.get("session_name"),
            "status_code": item.get("status_code"),
            "body_excerpt": str(item.get("body", ""))[:200],
        }
        for item in responses
        if isinstance(item, dict)
    ]


def _has_privileged_boundary(responses: Any) -> bool:
    if not isinstance(responses, list) or len(responses) < 2:
        return False
    statuses = {int(item.get("status_code", 0) or 0) for item in responses if isinstance(item, dict)}
    bodies = " ".join(str(item.get("body", "")).lower() for item in responses if isinstance(item, dict))
    return len(statuses) > 1 and any(marker in bodies for marker in ("admin", "forbidden", "dashboard", "role", "permission"))


def _looks_like_login_form(form: dict[str, Any]) -> bool:
    text = " ".join([str(form.get("action", "")), *[str(item) for item in form.get("inputs", [])]]).lower()
    return "login" in text or ("user" in text and "pass" in text)


def _login_form_score(form: dict[str, Any]) -> int:
    action = str(form.get("action", "")).lower()
    score = 0
    if "login" in action:
        score += 20
    if any(marker in action for marker in ("auth", "signin", "session", "account")):
        score += 10
    if "token" in action:
        score -= 30
    return score


def _decode_jwt(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "invalid jwt"}
    return {"header": _b64json(parts[0]), "payload": _b64json(parts[1]), "signature_present": bool(parts[2])}


def _b64json(value: str) -> dict[str, Any]:
    try:
        padded = value + "=" * (-len(value) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except Exception:
        return {}


def _payload_has_sensitive_claim(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    sensitive = {"password", "secret", "token", "api_key", "phone", "email", "role", "permission"}
    return any(str(key).lower() in sensitive for key in payload)


def _mask(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _mask(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_mask(item) for item in value]
    if isinstance(value, str):
        if len(value) <= 4:
            return "***"
        return value[:2] + "***" + value[-2:]
    return value


def _redact_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(arguments)
    for key in list(redacted):
        if re.search(r"password|token|secret|cookie|authorization", key, re.I):
            redacted[key] = _mask(redacted[key])
    return redacted


def _summarize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    summarized = dict(payload)
    if "body" in summarized:
        body = str(summarized["body"])
        summarized["body"] = body[:500]
        summarized["truncated_body"] = body
    return summarized


if __name__ == "__main__":
    raise SystemExit(main())
