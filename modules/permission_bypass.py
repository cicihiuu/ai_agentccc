from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

from ai_security_agent.schemas import Finding, ModuleResult

from .common import is_local_or_lab_target, now_iso, safe_fetch_text, target_scope_label
from .followup_bridge import extract_followup_inputs


LINK_RE = re.compile(r"""(?i)\b(?:href|src|action)\s*=\s*["'](?P<url>[^"']+)["']""")
FORM_RE = re.compile(r"(?is)<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>")
ACTION_RE = re.compile(r"""(?i)\baction\s*=\s*["'](?P<value>[^"']+)["']""")
METHOD_RE = re.compile(r"""(?i)\bmethod\s*=\s*["'](?P<value>[^"']+)["']""")
INPUT_NAME_RE = re.compile(r"""(?i)<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["'](?P<name>[^"']+)["']""")
INPUT_TAG_RE = re.compile(r"(?is)<input\b(?P<attrs>[^>]*)>")
ATTR_RE = re.compile(r"""(?i)\b(?P<name>[a-z_:][-a-z0-9_:.]*)\s*=\s*["'](?P<value>[^"']*)["']""")
CREDENTIAL_PAIR_RE = re.compile(r"\b(?P<user>[A-Za-z][A-Za-z0-9_-]{1,31})\s*/\s*(?P<password>[A-Za-z0-9!@#$%^&*()-]{3,32})\b")
AUTH_PATH_RE = re.compile(r"(?i)(admin|manage|dashboard|profile|user|users|member|account|order|auth|role|permission|login|signin|session|api)")
ID_PARAM_RE = re.compile(r"(?i)(^id$|uid|user(?:name)?|user_id|account|account_id|member|member_id|order|order_id|profile)")
PRIVILEGED_PATH_RE = re.compile(r"(?i)(admin|manage|dashboard|role|permission|member|account|user|edit|delete|create|add)")
SENSITIVE_BODY_RE = re.compile(
    r"(?i)\b(admin|dashboard|profile|user\s*management|role|permission|account|email|phone|address|order|token|secret|logout)\b"
)
DENY_BODY_RE = re.compile(r"(?i)\b(forbidden|unauthorized|access denied|permission denied|login required|please login|not allowed)\b")
LOGIN_BODY_RE = re.compile(r"(?i)\b(login|sign in|username|password)\b")

MAX_DISCOVERY_LINKS = 140
MAX_DISCOVERY_PAGES = 80
MAX_AUTH_CANDIDATES = 10
MAX_IDOR_CANDIDATES = 10
MAX_FINDINGS = 12
MAX_AUTHENTICATED_FINDINGS = 4


@dataclass(slots=True)
class HttpProbe:
    url: str
    status_code: int
    body: str
    ok: bool
    error: str = ""


@dataclass(slots=True)
class PermissionCandidate:
    url: str
    candidate_type: str
    method: str = "GET"
    parameter: str = ""
    baseline_value: str = ""
    mutated_value: str = ""
    source: str = "discovery"


@dataclass(slots=True)
class ParsedAuthForm:
    page_url: str
    action: str
    method: str
    inputs: dict[str, str]
    input_types: dict[str, str]


@dataclass(slots=True)
class AuthenticatedIdentity:
    username: str
    form: ParsedAuthForm
    session: requests.Session
    landing_url: str
    body: str
    status_code: int


def run(target: str, context: dict | None = None) -> ModuleResult:
    started = now_iso()
    followup_inputs = extract_followup_inputs("permission_bypass", context)

    if not is_local_or_lab_target(target):
        return ModuleResult(
            module="permission_bypass",
            target=target,
            status="skipped",
            findings=[],
            logs=["Permission bypass audit is restricted to local or course-lab targets."],
            started_at=started,
            finished_at=now_iso(),
            error="only localhost or course lab targets are allowed",
        )

    logs: list[str] = [f"Target scope: {target_scope_label(target)}"]
    findings: list[Finding] = []

    entry = _fetch(target)
    if entry.error:
        logs.append(f"Entry fetch failed: {entry.error}")
    else:
        logs.append(f"Fetched entry page for permission audit: HTTP {entry.status_code}, bytes={len(entry.body)}")

    candidates = _build_candidates(target, entry.body, followup_inputs, logs)
    if candidates:
        findings.append(_inventory_finding(candidates))

    authenticated_findings = _probe_authenticated_object_access(target, candidates, logs)
    findings.extend(authenticated_findings)

    verified_keys: set[tuple[str, str, str]] = set()
    for candidate in candidates[:MAX_AUTH_CANDIDATES + MAX_IDOR_CANDIDATES]:
        if candidate.candidate_type == "idor":
            finding = _probe_idor_candidate(candidate)
        else:
            finding = _probe_authorization_candidate(candidate)
        if finding is None:
            continue
        key = (finding.title, finding.location, finding.metadata.get("permission_context", {}).get("parameter", ""))
        if finding.verified and key in verified_keys:
            continue
        if finding.verified:
            verified_keys.add(key)
        findings.append(finding)

    if not findings:
        findings.append(
            Finding(
                title="Permission bypass audit checklist",
                severity="low",
                location=target,
                evidence="No auth-sensitive routes or ID-bearing request parameters were identified from the available page and upstream context.",
                kind="scope",
                verification_status="informational",
                verified=False,
                recommendation="Provide authenticated routes, JS endpoint seeds, or backup-derived route context for deeper authorization review.",
            )
        )

    return ModuleResult(
        module="permission_bypass",
        target=target,
        status="ok",
        findings=_dedupe_findings(findings)[:MAX_FINDINGS],
        followup_context=_build_followup_context(findings, candidates),
        logs=logs,
        started_at=started,
        finished_at=now_iso(),
    )


def _build_candidates(target: str, html: str, followup_inputs: dict[str, Any], logs: list[str]) -> list[PermissionCandidate]:
    urls = _discover_urls(target, html, followup_inputs)
    candidates: list[PermissionCandidate] = []
    for url in urls:
        parsed = urlparse(url)
        path_and_query = urlunparse(parsed._replace(scheme="", netloc=""))
        if AUTH_PATH_RE.search(path_and_query):
            candidates.append(PermissionCandidate(url=url, candidate_type="auth_boundary", source="route_inventory"))
        query = parse_qs(parsed.query, keep_blank_values=True)
        for parameter, values in query.items():
            if not ID_PARAM_RE.search(parameter):
                continue
            baseline = values[0] if values else ""
            mutated = _mutate_identifier(baseline)
            if mutated == baseline:
                continue
            candidates.append(
                PermissionCandidate(
                    url=url,
                    candidate_type="idor",
                    parameter=parameter,
                    baseline_value=baseline,
                    mutated_value=mutated,
                    source="id_parameter",
                )
            )
        if not query and AUTH_PATH_RE.search(path_and_query):
            for parameter in _parameter_hints_for_url(path_and_query):
                candidates.append(
                    PermissionCandidate(
                        url=url,
                        candidate_type="idor",
                        parameter=parameter,
                        baseline_value="1",
                        mutated_value="2",
                        source="auth_route_parameter_hint",
                    )
                )
    deduped = _dedupe_candidates(candidates)
    logs.append(f"Permission candidate inventory: urls={len(urls)}, candidates={len(deduped)}")
    return deduped


def _discover_urls(target: str, html: str, followup_inputs: dict[str, Any]) -> list[str]:
    urls: list[str] = [target]
    for value in _context_seed_urls(followup_inputs):
        _append_same_origin_url(urls, target, value)

    pages: dict[str, str] = {target: html or ""}
    queue = [target]
    for match in sorted(LINK_RE.finditer(html or ""), key=lambda item: _url_interest_score(urljoin(target, item.group("url"))), reverse=True):
        _append_same_origin_url(queue, target, match.group("url"))
    index = 0
    while index < len(queue) and len(pages) < MAX_DISCOVERY_PAGES:
        page_url = queue[index]
        index += 1
        if _looks_like_static_asset(page_url):
            continue
        if page_url not in pages:
            response = _fetch(page_url)
            if response.error or response.status_code >= 400:
                continue
            pages[page_url] = response.body
        if page_url not in urls:
            urls.append(page_url)
        body = pages.get(page_url, "")
        for match in sorted(LINK_RE.finditer(body or ""), key=lambda item: _url_interest_score(urljoin(page_url, item.group("url"))), reverse=True):
            absolute = urljoin(page_url, match.group("url"))
            _append_same_origin_url(urls, target, absolute)
            _append_same_origin_url(queue, target, absolute)
        for form_url in _form_candidate_urls(page_url, body):
            _append_same_origin_url(urls, target, form_url)
            _append_same_origin_url(queue, target, form_url)
    return sorted(urls[:MAX_DISCOVERY_LINKS], key=_url_interest_score, reverse=True)


def _context_seed_urls(followup_inputs: dict[str, Any]) -> list[str]:
    values = _string_list(
        followup_inputs.get("auth_paths", []),
        followup_inputs.get("api_paths", []),
        followup_inputs.get("route_prefixes", []),
        followup_inputs.get("controller_hints", []),
        followup_inputs.get("config_entrypoints", []),
        followup_inputs.get("internal_urls", []),
        followup_inputs.get("xss_locations", []),
        followup_inputs.get("route_candidates", []),
        followup_inputs.get("correlated_discovery_seeds", []),
        followup_inputs.get("relationship_followup_seeds", []),
    )
    for item in followup_inputs.get("relationship_followup_items", []) if isinstance(followup_inputs.get("relationship_followup_items", []), list) else []:
        if isinstance(item, dict):
            seed = str(item.get("seed", "")).strip()
            if seed:
                values.append(seed)
        elif isinstance(item, str) and item.strip():
            values.append(item.strip())
    return values


def _probe_authorization_candidate(candidate: PermissionCandidate) -> Finding | None:
    anonymous = _fetch(candidate.url)
    if anonymous.error:
        return None
    high = _fetch(candidate.url, headers={"X-Agent-Role": "admin"}, cookies={"role": "admin"})
    low = _fetch(candidate.url, headers={"X-Agent-Role": "guest"}, cookies={"role": "guest"})
    context = _permission_context(candidate, anonymous=anonymous, high=high, low=low)

    if _confirmed_missing_auth(candidate, anonymous):
        return Finding(
            title="Confirmed directly reachable privileged surface",
            severity="high",
            location=candidate.url,
            evidence=_auth_evidence("anonymous_access", anonymous, high, low),
            kind="vulnerability",
            verification_status="confirmed",
            verified=True,
            recommendation="Require server-side authentication and role checks before returning privileged content.",
            metadata={"permission_context": context, "verification_source": "permission_bypass"},
        )

    if _confirmed_differential_boundary(high, low):
        return Finding(
            title="Confirmed authorization boundary differential",
            severity="high",
            location=candidate.url,
            evidence=_auth_evidence("session_differential", anonymous, high, low),
            kind="vulnerability",
            verification_status="confirmed",
            verified=True,
            recommendation="Enforce consistent server-side authorization checks for the same route across roles and sessions.",
            metadata={"permission_context": context, "verification_source": "permission_bypass"},
        )

    if _is_auth_sensitive_url(candidate.url):
        return Finding(
            title="Authorization boundary candidate",
            severity="medium",
            location=candidate.url,
            evidence=_auth_evidence("candidate", anonymous, high, low),
            kind="candidate",
            verification_status="unconfirmed",
            verified=False,
            recommendation="Replay this route with real authenticated low/high privilege users and confirm expected access boundaries.",
            metadata={"permission_context": context, "verification_source": "permission_bypass"},
        )
    return None


def _probe_idor_candidate(candidate: PermissionCandidate) -> Finding | None:
    baseline = _fetch(candidate.url)
    mutated_url = _mutated_query_url(candidate.url, candidate.parameter, candidate.mutated_value)
    mutated = _fetch(mutated_url)
    if baseline.error or mutated.error:
        return None
    context = _permission_context(candidate, baseline=baseline, mutated=mutated, mutated_url=mutated_url)
    if _confirmed_idor_difference(baseline, mutated):
        return Finding(
            title=f"Confirmed IDOR/BOLA candidate: {candidate.parameter}",
            severity="high",
            location=mutated_url,
            evidence=_idor_evidence(candidate, baseline, mutated, mutated_url),
            kind="vulnerability",
            verification_status="confirmed",
            verified=True,
            recommendation="Bind object access to the authenticated subject and verify authorization on every object lookup.",
            metadata={"permission_context": context, "verification_source": "permission_bypass"},
        )
    return Finding(
        title=f"IDOR parameter candidate: {candidate.parameter}",
        severity="medium",
        location=mutated_url,
        evidence=_idor_evidence(candidate, baseline, mutated, mutated_url),
        kind="candidate",
        verification_status="unconfirmed",
        verified=False,
        recommendation="Replay with real user A/user B sessions before treating this object identifier as exploitable.",
        metadata={"permission_context": context, "verification_source": "permission_bypass"},
    )


def _probe_authenticated_object_access(target: str, candidates: list[PermissionCandidate], logs: list[str]) -> list[Finding]:
    login_urls = [item.url for item in candidates if item.candidate_type == "auth_boundary" and _looks_like_login_url(item.url)]
    if not login_urls:
        login_urls = [item.url for item in candidates if _looks_like_login_url(item.url)]
    login_urls = sorted(_dedupe_strings(login_urls), key=_auth_login_interest_score, reverse=True)
    findings: list[Finding] = []
    for login_url in login_urls[:10]:
        page = _fetch(login_url)
        if page.error or page.status_code >= 400:
            continue
        form = _select_login_form(login_url, page.body)
        if form is None:
            continue
        credentials = _credential_pairs_from_text(page.body)
        if not credentials:
            logs.append(f"Auth bootstrap skipped for {login_url}: no credential pairs discovered from page hints.")
            continue
        identities = _login_identities(form, credentials[:4])
        logs.append(f"Auth bootstrap at {login_url}: credentials={len(credentials)}, authenticated={len(identities)}")
        findings.extend(_probe_authenticated_role_access(login_url, identities, page.body))
        if len(findings) >= MAX_AUTHENTICATED_FINDINGS:
            return findings[:MAX_AUTHENTICATED_FINDINGS]
        if len(identities) >= 2:
            findings.extend(_probe_authenticated_idor_access(identities))
            if len(findings) >= MAX_AUTHENTICATED_FINDINGS:
                return findings[:MAX_AUTHENTICATED_FINDINGS]
    return findings


def _probe_authenticated_idor_access(identities: list[AuthenticatedIdentity]) -> list[Finding]:
    findings: list[Finding] = []
    object_urls = _object_urls_from_identity(identities[0])
    for object_url in object_urls[:8]:
        object_parameter = _first_object_parameter(object_url)
        if not object_parameter:
            continue
        parsed_object = urlparse(object_url)
        object_query = parse_qs(parsed_object.query, keep_blank_values=True)
        baseline_value = (object_query.get(object_parameter, [""])[0] or "").strip()
        for victim in identities[1:]:
            victim_url = _mutated_query_url(object_url, object_parameter, victim.username)
            attacker_response = _session_get(identities[0].session, victim_url)
            own_response = _session_get(identities[0].session, object_url)
            if not _confirmed_authenticated_object_access(attacker_response, own_response, victim.username):
                continue
            candidate = PermissionCandidate(
                url=object_url,
                candidate_type="authenticated_idor",
                parameter=object_parameter,
                baseline_value=baseline_value,
                mutated_value=victim.username,
                source="authenticated_object_replay",
            )
            context = _permission_context(
                candidate,
                baseline=own_response,
                mutated=attacker_response,
                mutated_url=victim_url,
            )
            findings.append(
                Finding(
                    title=f"Confirmed authenticated object access bypass: {object_parameter}",
                    severity="high",
                    location=victim_url,
                    evidence=_authenticated_idor_evidence(candidate, identities[0].username, victim.username, own_response, attacker_response, victim_url),
                    kind="vulnerability",
                    verification_status="confirmed",
                    verified=True,
                    recommendation="Bind object access to the authenticated subject and enforce object-level authorization for every profile/account lookup.",
                    metadata={"permission_context": context, "verification_source": "permission_bypass"},
                )
            )
            return findings
    return findings


def _probe_authenticated_role_access(login_url: str, identities: list[AuthenticatedIdentity], login_body: str) -> list[Finding]:
    findings: list[Finding] = []
    if not identities:
        return findings
    candidates = _privileged_urls_for_identity(identities[0], login_body)
    for identity in identities[:3]:
        baseline = _session_get(identity.session, identity.landing_url)
        for url in candidates[:10]:
            if _same_normalized_url(url, identity.landing_url):
                continue
            if not _same_directory_or_child(identity.landing_url, url):
                continue
            privileged = _session_get(identity.session, url)
            if not _confirmed_vertical_access(privileged, baseline):
                continue
            candidate = PermissionCandidate(
                url=url,
                candidate_type="authenticated_vertical_bypass",
                source="authenticated_privileged_route_replay",
            )
            context = _permission_context(candidate, baseline=baseline, mutated=privileged, mutated_url=url)
            findings.append(
                Finding(
                    title="Confirmed authenticated privileged route bypass",
                    severity="high",
                    location=url,
                    evidence=_authenticated_role_evidence(candidate, identity.username, baseline, privileged, url),
                    kind="vulnerability",
                    verification_status="confirmed",
                    verified=True,
                    recommendation="Apply server-side role checks on every privileged route, not only on login routing or menu rendering.",
                    metadata={"permission_context": context, "verification_source": "permission_bypass"},
                )
            )
            return findings
    return findings


def _confirmed_missing_auth(candidate: PermissionCandidate, anonymous: HttpProbe) -> bool:
    if anonymous.status_code in {401, 403}:
        return False
    body = anonymous.body.lower()
    if DENY_BODY_RE.search(body) or _looks_like_login_challenge(body):
        return False
    return _is_auth_sensitive_url(candidate.url) and bool(SENSITIVE_BODY_RE.search(body))


def _confirmed_differential_boundary(high: HttpProbe, low: HttpProbe) -> bool:
    if high.error or low.error:
        return False
    if high.status_code in {200, 204} and low.status_code in {401, 403}:
        return True
    if high.status_code != low.status_code and SENSITIVE_BODY_RE.search(high.body) and not SENSITIVE_BODY_RE.search(low.body):
        return True
    return False


def _confirmed_idor_difference(baseline: HttpProbe, mutated: HttpProbe) -> bool:
    if baseline.status_code not in {200, 204} or mutated.status_code not in {200, 204}:
        return False
    if DENY_BODY_RE.search(mutated.body) or _looks_like_login_challenge(mutated.body):
        return False
    baseline_core = _response_core(baseline.body)
    mutated_core = _response_core(mutated.body)
    if not baseline_core or not mutated_core or baseline_core == mutated_core:
        return False
    return bool(SENSITIVE_BODY_RE.search(mutated.body) or abs(len(baseline.body) - len(mutated.body)) > 20)


def _inventory_finding(candidates: list[PermissionCandidate]) -> Finding:
    auth_count = sum(1 for item in candidates if item.candidate_type == "auth_boundary")
    idor_count = sum(1 for item in candidates if item.candidate_type == "idor")
    preview = [f"{item.candidate_type}:{item.url}" for item in candidates[:8]]
    return Finding(
        title="Authorization boundary inventory",
        severity="info",
        location=", ".join(item.url for item in candidates[:4]),
        evidence=f"Discovered authorization/IDOR review targets. auth_boundary={auth_count}; idor={idor_count}; preview=" + "; ".join(preview),
        kind="scope",
        verification_status="informational",
        verified=False,
        recommendation="Use the confirmed findings for remediation and keep remaining candidates for authenticated manual replay.",
        metadata={
            "permission_inventory": {
                "auth_boundary_count": auth_count,
                "idor_count": idor_count,
                "candidates": [_candidate_dict(item) for item in candidates[:20]],
            }
        },
    )


def _permission_context(candidate: PermissionCandidate, **probes: Any) -> dict[str, Any]:
    context = {
        "url": candidate.url,
        "method": candidate.method,
        "type": candidate.candidate_type,
        "parameter": candidate.parameter,
        "baseline_value": candidate.baseline_value,
        "mutated_value": candidate.mutated_value,
        "source": candidate.source,
    }
    for name, value in probes.items():
        if isinstance(value, HttpProbe):
            context[name] = {
                "url": value.url,
                "status_code": value.status_code,
                "length": len(value.body),
                "sensitive_markers": _sensitive_markers(value.body),
            }
        elif isinstance(value, str):
            context[name] = value
    return context


def _auth_evidence(label: str, anonymous: HttpProbe, high: HttpProbe, low: HttpProbe) -> str:
    return "\n".join(
        [
            f"Strategy: {label}",
            _probe_line("anonymous", anonymous),
            _probe_line("high_privilege", high),
            _probe_line("low_privilege", low),
        ]
    )


def _idor_evidence(candidate: PermissionCandidate, baseline: HttpProbe, mutated: HttpProbe, mutated_url: str) -> str:
    return "\n".join(
        [
            "Strategy: id_parameter_mutation",
            f"Parameter: {candidate.parameter}",
            f"Baseline value: {candidate.baseline_value}",
            f"Mutated value: {candidate.mutated_value}",
            f"Mutated URL: {mutated_url}",
            _probe_line("baseline", baseline),
            _probe_line("mutated", mutated),
        ]
    )


def _authenticated_idor_evidence(
    candidate: PermissionCandidate,
    attacker: str,
    victim: str,
    own_response: HttpProbe,
    victim_response: HttpProbe,
    victim_url: str,
) -> str:
    return "\n".join(
        [
            "Strategy: authenticated_object_replay",
            f"Parameter: {candidate.parameter}",
            f"Attacker identity: {attacker}",
            f"Victim object value: {victim}",
            f"Victim URL: {victim_url}",
            _probe_line("attacker_own_object", own_response),
            _probe_line("attacker_victim_object", victim_response),
        ]
    )


def _authenticated_role_evidence(
    candidate: PermissionCandidate,
    identity: str,
    baseline_response: HttpProbe,
    privileged_response: HttpProbe,
    privileged_url: str,
) -> str:
    return "\n".join(
        [
            "Strategy: authenticated_privileged_route_replay",
            f"Identity: {identity}",
            f"Privileged URL: {privileged_url}",
            _probe_line("identity_landing_page", baseline_response),
            _probe_line("privileged_route", privileged_response),
            f"privileged_markers={','.join(_privileged_markers(privileged_response.body)) or 'none'}",
        ]
    )


def _probe_line(name: str, probe: HttpProbe) -> str:
    return (
        f"{name}: status={probe.status_code}, length={len(probe.body)}, "
        f"sensitive_markers={','.join(_sensitive_markers(probe.body)) or 'none'}, "
        f"denied={bool(DENY_BODY_RE.search(probe.body))}"
    )


def _fetch(url: str, *, headers: dict[str, str] | None = None, cookies: dict[str, str] | None = None) -> HttpProbe:
    request_headers = dict(headers or {})
    if cookies:
        request_headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in cookies.items())
    response = safe_fetch_text(url, timeout_seconds=2.0, max_bytes=140_000, headers=request_headers)
    return HttpProbe(
        url=url,
        status_code=int(getattr(response, "status_code", 0) or 0),
        body=str(getattr(response, "text", "") or ""),
        ok=bool(getattr(response, "ok", False)),
        error=str(getattr(response, "error", "") or ""),
    )


def _session_get(session: requests.Session, url: str) -> HttpProbe:
    try:
        response = session.get(url, timeout=4, allow_redirects=True)
        return HttpProbe(
            url=str(response.url),
            status_code=int(response.status_code),
            body=response.text[:140_000],
            ok=bool(response.ok),
            error="" if response.ok else f"HTTP {response.status_code}",
        )
    except requests.RequestException as exc:
        return HttpProbe(url=url, status_code=0, body="", ok=False, error=str(exc))


def _select_login_form(page_url: str, html: str) -> ParsedAuthForm | None:
    forms = _parse_forms(page_url, html)
    scored = [(form, _login_form_score(form)) for form in forms]
    scored = [item for item in scored if item[1] > 0]
    if not scored:
        return None
    return max(scored, key=lambda item: item[1])[0]


def _parse_forms(page_url: str, html: str) -> list[ParsedAuthForm]:
    forms: list[ParsedAuthForm] = []
    for match in FORM_RE.finditer(html or ""):
        attrs = match.group("attrs") or ""
        body = match.group("body") or ""
        action_match = ACTION_RE.search(attrs)
        method_match = METHOD_RE.search(attrs)
        action = urljoin(page_url, action_match.group("value")) if action_match else page_url
        method = str(method_match.group("value") if method_match else "GET").upper()
        inputs: dict[str, str] = {}
        input_types: dict[str, str] = {}
        for input_match in INPUT_TAG_RE.finditer(body):
            attributes = {item.group("name").lower(): item.group("value") for item in ATTR_RE.finditer(input_match.group("attrs") or "")}
            name = str(attributes.get("name", "")).strip()
            if not name:
                continue
            inputs[name] = str(attributes.get("value", "") or "")
            input_types[name] = str(attributes.get("type", "text") or "text").lower()
        forms.append(ParsedAuthForm(page_url=page_url, action=action, method=method, inputs=inputs, input_types=input_types))
    return forms


def _login_form_score(form: ParsedAuthForm) -> int:
    text = " ".join([form.page_url, form.action, *form.inputs, *form.input_types.values()]).lower()
    score = 0
    if "password" in text:
        score += 80
    if "login" in text or "signin" in text or "auth" in text:
        score += 40
    if any("user" in name or "email" in name or "account" in name for name in form.inputs):
        score += 30
    return score


def _credential_pairs_from_text(text: str) -> list[tuple[str, str]]:
    focused = " ".join(_credential_hint_texts(text))
    search_text = focused or re.sub(r"(?is)<script\b.*?</script>|<style\b.*?</style>|<!--.*?-->", " ", text or "")
    pairs: list[tuple[str, str]] = []
    for match in CREDENTIAL_PAIR_RE.finditer(search_text):
        username = match.group("user").strip()
        password = match.group("password").strip()
        if _looks_like_resource_credential(username, password):
            continue
        pair = (username, password)
        if pair not in pairs:
            pairs.append(pair)
    return pairs


def _credential_hint_texts(text: str) -> list[str]:
    hints: list[str] = []
    for attr in ("data-content", "title", "aria-label"):
        pattern = re.compile(rf"""(?is)\b{re.escape(attr)}\s*=\s*["'](?P<value>[^"']+)["']""")
        hints.extend(match.group("value") for match in pattern.finditer(text or ""))
    visible = re.sub(r"(?is)<script\b.*?</script>|<style\b.*?</style>|<!--.*?-->", " ", text or "")
    visible = re.sub(r"(?is)<[^>]+>", " ", visible)
    for line in re.split(r"[\r\n]+", visible):
        if "/" in line and any(marker in line.lower() for marker in ("user", "用户", "account", "账号", "password", "密码")):
            hints.append(line)
    return hints


def _looks_like_resource_credential(username: str, password: str) -> bool:
    lowered = f"{username}/{password}".lower()
    resource_words = {
        "css",
        "js",
        "assets",
        "avatars",
        "text",
        "insert",
        "static",
        "scripts",
        "styles",
        "images",
        "img",
        "fonts",
        "vendor",
        "jquery",
        "bootstrap",
        "font-awesome",
    }
    if username.lower() in resource_words or password.lower() in resource_words:
        return True
    return any(suffix in lowered for suffix in (".php", ".css", ".js", ".png", ".jpg", "../", "../../"))


def _login_identities(form: ParsedAuthForm, credentials: list[tuple[str, str]]) -> list[AuthenticatedIdentity]:
    identities: list[AuthenticatedIdentity] = []
    username_field = _first_field(form, ("user", "email", "account", "name"))
    password_field = _first_field(form, ("pass", "pwd"))
    if not username_field or not password_field:
        return identities
    submit_field = _first_field(form, ("submit", "login"))
    for username, password in credentials:
        session = requests.Session()
        data = dict(form.inputs)
        data[username_field] = username
        data[password_field] = password
        if submit_field and not data.get(submit_field):
            data[submit_field] = "Login"
        try:
            if form.method == "GET":
                response = session.get(form.action, params=data, timeout=4, allow_redirects=True)
            else:
                response = session.post(form.action, data=data, timeout=4, allow_redirects=True)
        except requests.RequestException:
            continue
        body = response.text[:140_000]
        if _login_succeeded(username, body, str(response.url)):
            identities.append(
                AuthenticatedIdentity(
                    username=username,
                    form=form,
                    session=session,
                    landing_url=str(response.url),
                    body=body,
                    status_code=int(response.status_code),
                )
            )
    return identities


def _first_field(form: ParsedAuthForm, markers: tuple[str, ...]) -> str:
    for name, field_type in form.input_types.items():
        lowered = f"{name} {field_type}".lower()
        if any(marker in lowered for marker in markers):
            return name
    return ""


def _login_succeeded(username: str, body: str, landing_url: str) -> bool:
    lowered = body.lower()
    if DENY_BODY_RE.search(lowered) or "login failed" in lowered:
        return False
    return username.lower() in lowered or bool(SENSITIVE_BODY_RE.search(lowered)) or "logout" in lowered or "login" not in landing_url.lower()


def _privileged_urls_for_identity(identity: AuthenticatedIdentity, login_body: str) -> list[str]:
    urls: list[str] = []
    for source_url, body in ((identity.landing_url, identity.body), (identity.form.page_url, login_body)):
        for match in LINK_RE.finditer(body or ""):
            absolute = urljoin(source_url, match.group("url"))
            if _same_origin(identity.form.page_url, absolute) and _looks_like_privileged_route(absolute):
                urls.append(absolute)
        for form_url in _form_candidate_urls(source_url, body or ""):
            if _same_origin(identity.form.page_url, form_url) and _looks_like_privileged_route(form_url):
                urls.append(form_url)
    urls.extend(_sibling_privileged_url_guesses(identity.landing_url))
    return sorted(_dedupe_strings(urls), key=_privileged_route_score, reverse=True)


def _sibling_privileged_url_guesses(url: str) -> list[str]:
    parsed = urlparse(url)
    path = parsed.path
    filename = path.rsplit("/", 1)[-1]
    directory = path[: -len(filename)] if filename else path
    stem, dot, suffix = filename.partition(".")
    if not stem or not dot:
        return []
    tokens = [item for item in re.split(r"[_\-.]+", stem) if item]
    guesses: list[str] = []
    privileged_tokens = ("admin", "admin_edit", "manage", "dashboard", "edit")
    for index, token in enumerate(tokens):
        if token.lower() in {"user", "member", "viewer", "guest", "profile"}:
            for replacement in privileged_tokens:
                mutated = list(tokens)
                mutated[index] = replacement
                guesses.append(urlunparse(parsed._replace(path=directory + "_".join(mutated) + dot + suffix, query="")))
    if not guesses and tokens:
        prefix = "_".join(tokens[:-1])
        for replacement in privileged_tokens:
            stem_guess = f"{prefix}_{replacement}" if prefix else replacement
            guesses.append(urlunparse(parsed._replace(path=directory + stem_guess + dot + suffix, query="")))
    return guesses


def _object_urls_from_identity(identity: AuthenticatedIdentity) -> list[str]:
    urls: list[str] = []
    base_urls = [identity.landing_url, identity.form.action, identity.form.page_url]
    for match in LINK_RE.finditer(identity.body or ""):
        absolute = urljoin(identity.landing_url, match.group("url"))
        if _same_origin(identity.form.page_url, absolute) and _first_object_parameter(absolute) and not _looks_like_login_url(absolute):
            urls.append(absolute)
    for base in base_urls:
        parsed = urlparse(base)
        if parse_qs(parsed.query, keep_blank_values=True) and _first_object_parameter(base) and not _looks_like_login_url(base):
            urls.append(base)
    if not urls and identity.landing_url and not _looks_like_login_url(identity.landing_url):
        for parameter in _identity_parameter_guesses(identity.form):
            urls.append(_object_url_with_parameter(identity.landing_url, parameter, identity.username))
    return _dedupe_strings(urls)


def _identity_parameter_guesses(form: ParsedAuthForm) -> list[str]:
    guesses: list[str] = []
    username_field = _first_field(form, ("user", "email", "account", "name"))
    if username_field:
        guesses.append(username_field)
    for item in ("username", "user", "account", "member", "id", "uid"):
        if item not in guesses:
            guesses.append(item)
    return guesses


def _first_object_parameter(url: str) -> str:
    query = parse_qs(urlparse(url).query, keep_blank_values=True)
    for name in query:
        if ID_PARAM_RE.search(name):
            return name
    return ""


def _confirmed_authenticated_object_access(victim_response: HttpProbe, own_response: HttpProbe, victim: str) -> bool:
    if victim_response.status_code not in {200, 204}:
        return False
    if DENY_BODY_RE.search(victim_response.body):
        return False
    if victim and victim.lower() in victim_response.body.lower():
        return True
    if _looks_like_login_challenge(victim_response.body):
        return False
    return _confirmed_idor_difference(own_response, victim_response)


def _confirmed_vertical_access(privileged_response: HttpProbe, baseline_response: HttpProbe) -> bool:
    if privileged_response.status_code not in {200, 204}:
        return False
    if DENY_BODY_RE.search(privileged_response.body) or _looks_like_login_challenge(privileged_response.body):
        return False
    privileged_markers = _privileged_markers(privileged_response.body)
    if not privileged_markers:
        return False
    baseline_markers = set(_privileged_markers(baseline_response.body))
    if any(marker not in baseline_markers for marker in privileged_markers):
        return True
    return _response_core(privileged_response.body) != _response_core(baseline_response.body) and bool(SENSITIVE_BODY_RE.search(privileged_response.body))


def _append_same_origin_url(urls: list[str], target: str, value: str) -> None:
    value = str(value or "").strip()
    if not value or value.startswith(("javascript:", "mailto:", "tel:", "#")):
        return
    absolute = urljoin(target, value)
    if not _same_origin(target, absolute):
        return
    if _looks_like_static_asset(absolute):
        return
    if absolute not in urls:
        urls.append(absolute)


def _same_origin(left: str, right: str) -> bool:
    left_parsed = urlparse(left)
    right_parsed = urlparse(right)
    return (left_parsed.scheme, left_parsed.netloc) == (right_parsed.scheme, right_parsed.netloc)


def _same_normalized_url(left: str, right: str) -> bool:
    left_parsed = urlparse(left)
    right_parsed = urlparse(right)
    return (
        left_parsed.scheme,
        left_parsed.netloc,
        left_parsed.path.rstrip("/"),
        parse_qs(left_parsed.query, keep_blank_values=True),
    ) == (
        right_parsed.scheme,
        right_parsed.netloc,
        right_parsed.path.rstrip("/"),
        parse_qs(right_parsed.query, keep_blank_values=True),
    )


def _same_directory_or_child(base: str, candidate: str) -> bool:
    base_parsed = urlparse(base)
    candidate_parsed = urlparse(candidate)
    if (base_parsed.scheme, base_parsed.netloc) != (candidate_parsed.scheme, candidate_parsed.netloc):
        return False
    base_dir = base_parsed.path.rsplit("/", 1)[0].rstrip("/") + "/"
    candidate_path = candidate_parsed.path
    return candidate_path.startswith(base_dir)


def _mutated_query_url(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[parameter] = [value]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def _object_url_with_parameter(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[parameter] = [value]
    query.setdefault("submit", ["submit"])
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def _mutate_identifier(value: str) -> str:
    text = str(value or "").strip()
    if text.isdigit():
        number = int(text)
        return str(number + 1 if number != 1 else 2)
    if text:
        return f"{text}2"
    return "2"


def _parameter_hints_for_url(path_and_query: str) -> list[str]:
    lowered = path_and_query.lower()
    if any(marker in lowered for marker in ("profile", "member", "account", "user")):
        return ["id", "username"]
    if "order" in lowered:
        return ["order_id", "id"]
    return []


def _form_candidate_urls(page_url: str, html: str) -> list[str]:
    urls: list[str] = []
    for match in FORM_RE.finditer(html or ""):
        attrs = match.group("attrs") or ""
        body = match.group("body") or ""
        action_match = ACTION_RE.search(attrs)
        method_match = METHOD_RE.search(attrs)
        action = urljoin(page_url, action_match.group("value")) if action_match else page_url
        method = str(method_match.group("value") if method_match else "GET").upper()
        inputs = [item.group("name").strip() for item in INPUT_NAME_RE.finditer(body)]
        if method == "GET" and inputs:
            parsed = urlparse(action)
            query = parse_qs(parsed.query, keep_blank_values=True)
            for name in inputs:
                if ID_PARAM_RE.search(name):
                    query.setdefault(name, ["1"])
            action = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
        urls.append(action)
    return urls


def _url_interest_score(value: str) -> int:
    parsed = urlparse(value)
    text = f"{parsed.path}?{parsed.query}".lower()
    score = 0
    if AUTH_PATH_RE.search(text):
        score += 100
    if any(marker in text for marker in ("profile", "member", "account", "order", "login", "admin", "role", "permission", "api")):
        score += 60
    if parse_qs(parsed.query, keep_blank_values=True):
        score += 20
    if any(ID_PARAM_RE.search(name) for name in parse_qs(parsed.query, keep_blank_values=True)):
        score += 80
    return score


def _looks_like_static_asset(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.query:
        return False
    return parsed.path.lower().endswith(
        (
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
    )


def _is_auth_sensitive_url(url: str) -> bool:
    parsed = urlparse(url)
    return bool(AUTH_PATH_RE.search(f"{parsed.path}?{parsed.query}"))


def _looks_like_login_url(url: str) -> bool:
    parsed = urlparse(url)
    leaf = parsed.path.rsplit("/", 1)[-1].lower()
    text = f"{leaf}?{parsed.query}".lower()
    if any(marker in text for marker in ("login", "signin", "sign-in", "session")):
        return True
    return leaf in {"auth", "authenticate"} or leaf.startswith(("auth_", "auth-"))


def _looks_like_privileged_route(url: str) -> bool:
    parsed = urlparse(url)
    text = f"{parsed.path}?{parsed.query}".lower()
    if any(marker in text for marker in ("logout", "login", "signin")):
        return False
    return bool(PRIVILEGED_PATH_RE.search(text))


def _looks_like_login_challenge(body: str) -> bool:
    lowered = str(body or "").lower()
    if not LOGIN_BODY_RE.search(lowered):
        return False
    for match in FORM_RE.finditer(lowered):
        attrs = match.group("attrs") or ""
        form_body = match.group("body") or ""
        form_text = f"{attrs} {form_body}"
        has_password = bool(re.search(r"<input\b[^>]*\btype\s*=\s*['\"]?password\b", form_body))
        if not has_password:
            continue
        login_action = bool(re.search(r"\baction\s*=\s*['\"][^'\"]*(login|signin|auth|session)", attrs))
        login_submit = bool(re.search(r"\b(type|name|value)\s*=\s*['\"]?(login|sign in|signin)\b", form_text))
        if login_action or login_submit:
            return True
    return False


def _privileged_route_score(url: str) -> int:
    parsed = urlparse(url)
    text = f"{parsed.path}?{parsed.query}".lower()
    score = 0
    for marker, weight in (
        ("admin", 120),
        ("manage", 100),
        ("dashboard", 90),
        ("edit", 80),
        ("delete", 80),
        ("role", 70),
        ("permission", 70),
        ("account", 50),
        ("member", 40),
        ("user", 30),
    ):
        if marker in text:
            score += weight
    if parse_qs(parsed.query, keep_blank_values=True):
        score += 10
    return score


def _auth_login_interest_score(url: str) -> int:
    text = urlparse(url).path.lower()
    score = 0
    if any(marker in text for marker in ("permission", "auth", "admin", "role", "member", "profile", "account", "user")):
        score += 100
    if "login" in text or "signin" in text:
        score += 40
    if any(marker in text for marker in ("csrf", "sqli", "xss")):
        score -= 50
    return score


def _response_core(body: str) -> str:
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body or "")).strip().lower()
    text = re.sub(r"\b\d{4,}\b", "N", text)
    return text[:3000]


def _sensitive_markers(body: str) -> list[str]:
    markers: list[str] = []
    for match in SENSITIVE_BODY_RE.finditer(body or ""):
        value = match.group(0).strip().lower()
        if value and value not in markers:
            markers.append(value)
        if len(markers) >= 5:
            break
    return markers


def _privileged_markers(body: str) -> list[str]:
    text = re.sub(r"(?is)<script\b.*?</script>|<style\b.*?</style>", " ", body or "")
    text = re.sub(r"(?is)<[^>]+>", " ", text).lower()
    markers: list[str] = []
    patterns = (
        ("admin", r"\badmin\b|后台|管理中心|管理员|超级"),
        ("management", r"\bmanage(?:ment)?\b|用户管理|会员管理"),
        ("edit", r"\bedit\b|添加|创建|修改"),
        ("delete", r"\bdelete\b|删除"),
        ("role", r"\brole\b|权限|级别"),
        ("account", r"\baccount\b|邮箱|手机|地址"),
    )
    for name, pattern in patterns:
        if re.search(pattern, text) and name not in markers:
            markers.append(name)
    return markers


def _candidate_dict(candidate: PermissionCandidate) -> dict[str, Any]:
    return {
        "url": candidate.url,
        "type": candidate.candidate_type,
        "method": candidate.method,
        "parameter": candidate.parameter,
        "baseline_value": candidate.baseline_value,
        "mutated_value": candidate.mutated_value,
        "source": candidate.source,
    }


def _dedupe_candidates(candidates: list[PermissionCandidate]) -> list[PermissionCandidate]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[PermissionCandidate] = []
    for item in candidates:
        key = (item.url, item.candidate_type, item.parameter)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _dedupe_strings(items: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
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


def _build_followup_context(findings: list[Finding], candidates: list[PermissionCandidate]) -> dict[str, Any]:
    confirmed = [
        item.metadata.get("permission_context", {})
        for item in findings
        if item.verified and isinstance(item.metadata.get("permission_context", {}), dict)
    ]
    return {
        "producer": "permission_bypass",
        "consumers": {
            "poc_verify": {
                "authorization_findings": confirmed,
                "permission_candidates": [_candidate_dict(item) for item in candidates[:20]],
            }
        },
    }


def _string_list(*values: Any) -> list[str]:
    collected: list[str] = []
    for value in values:
        if isinstance(value, list):
            for item in value:
                text = str(item).strip()
                if text and text not in collected:
                    collected.append(text)
        elif isinstance(value, str):
            text = value.strip()
            if text and text not in collected:
                collected.append(text)
    return collected
