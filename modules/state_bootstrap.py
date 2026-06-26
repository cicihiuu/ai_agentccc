from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import requests

from ai_security_agent.schemas import Finding, ModuleResult

from .common import is_local_or_lab_target, now_iso, safe_fetch_text, target_scope_label


FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<(input|textarea|select)\b([^>]*)>", re.IGNORECASE | re.DOTALL)
LINK_RE = re.compile(r"<a\b[^>]*href\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
ATTR_RE = re.compile(r"(?P<name>[a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(['\"])(?P<value>.*?)\2", re.DOTALL)

USERNAME_HINTS = ("username", "user", "email", "login", "account")
PASSWORD_HINTS = ("password", "pass", "passwd", "pwd")
NON_CREDENTIAL_FIELD_HINTS = ("token", "csrf", "nonce", "captcha", "submit")
LOGIN_LINK_HINTS = ("login", "signin", "sign-in", "auth")
SUCCESS_MARKERS = ("logout", "log out", "sign out", "dashboard", "welcome", "security level", "you have logged in")
STATE_PAGE_HINTS = ("security", "setting", "preference", "profile", "config", "setup")
STATE_FIELD_HINTS = ("security", "security_level", "level", "mode", "difficulty")
DEFAULT_STATE_FIELD_VALUES = {
    "security": "low",
    "security_level": "low",
    "level": "low",
    "mode": "low",
    "difficulty": "low",
}


@dataclass(slots=True)
class FormField:
    name: str
    field_type: str
    value: str = ""


@dataclass(slots=True)
class HtmlForm:
    action: str
    method: str
    fields: list[FormField]


def run(target: str, context: dict | None = None) -> ModuleResult:
    started = now_iso()
    context = context or {}
    config = _state_config(context)
    enabled = bool(config.get("enabled", True))
    logs = [f"Target scope: {target_scope_label(target)}"]

    if not enabled:
        return _result(target, started, "skipped", logs + ["State bootstrap disabled by profile config."], {})
    if not is_local_or_lab_target(target):
        return _result(
            target,
            started,
            "skipped",
            logs + ["Target is outside the local/course-lab allowlist; state bootstrap skipped."],
            {},
            error="only localhost or course lab targets are allowed",
        )

    session = requests.Session()
    entry = _session_get(session, target)
    candidate_pages = [(entry.url or target, entry.text or "")]
    for login_url in _login_candidate_urls(target, entry.url or target, entry.text or ""):
        if login_url == (entry.url or target):
            continue
        response = _session_get(session, login_url)
        candidate_pages.append((response.url or login_url, response.text or ""))

    login_result = _attempt_login(session, candidate_pages, config, logs)
    authenticated = bool(login_result.get("authenticated", False))
    if not authenticated:
        logs.append("No reusable authenticated session was established.")

    state_actions = _apply_post_login_state_actions(session, target, login_result, config, logs) if authenticated else []

    discovery_pages = []
    state_seed_urls = []
    for action in state_actions:
        state_seed_urls.extend([str(action.get("page_url", "")), str(action.get("final_url", ""))])
    for url in _dedupe(
        [
            target,
            str(login_result.get("final_url", "") or ""),
            *(str(item) for item in config.get("post_login_urls", []) if str(item).strip()),
            *state_seed_urls,
        ]
    ):
        if not url:
            continue
        response = _session_get(session, urljoin(target, url))
        if response.text:
            discovery_pages.append((response.url or url, response.text))

    discovered_urls = _discover_same_origin_urls(target, discovery_pages)
    cookie_header = _cookie_header(session)
    request_headers = {"Cookie": cookie_header} if cookie_header else {}
    request_context = {
        "request_headers": request_headers,
        "cookies": requests.utils.dict_from_cookiejar(session.cookies),
    }
    followup_context = {
        "producer": "state_bootstrap",
        "authenticated": authenticated,
        "request_context": request_context,
        "request_headers": request_headers,
        "authenticated_urls": discovered_urls,
        "discovered_urls": discovered_urls,
        "login_url": str(login_result.get("login_url", "")),
        "final_url": str(login_result.get("final_url", "")),
        "state_actions": state_actions,
        "consumers": {
            name: {
                "request_context": request_context,
                "request_headers": request_headers,
                "authenticated_urls": discovered_urls,
                "seed_urls": discovered_urls,
                "state_actions": state_actions,
            }
            for name in ("recon", "sql_scan", "xss_triage", "ssrf_triage", "permission_bypass", "js_audit", "poc_verify")
        },
    }
    logs.append(f"Authenticated session established: {authenticated}")
    logs.append(f"Post-login state actions applied: {len(state_actions)}")
    logs.append(f"Authenticated entry URLs discovered: {len(discovered_urls)}")
    finding = Finding(
        title="认证态上下文建立",
        severity="info",
        location=str(login_result.get("final_url", "") or target),
        evidence=(
            f"authenticated={authenticated}\n"
            f"cookie_count={len(request_context['cookies'])}\n"
            f"state_action_count={len(state_actions)}\n"
            f"authenticated_url_count={len(discovered_urls)}"
        ),
        kind="evidence",
        verification_status="informational",
        verified=False,
        recommendation="后续扫描模块应复用该请求上下文访问认证后入口。",
        metadata={"verification_source": "state_bootstrap"},
    )
    return ModuleResult(
        module="state_bootstrap",
        target=target,
        status="ok",
        findings=[finding],
        logs=logs,
        followup_context=followup_context,
        started_at=started,
        finished_at=now_iso(),
    )


def _result(target: str, started: str, status: str, logs: list[str], followup_context: dict[str, Any], *, error: str = "") -> ModuleResult:
    return ModuleResult(
        module="state_bootstrap",
        target=target,
        status=status,
        findings=[],
        logs=logs,
        followup_context=followup_context,
        started_at=started,
        finished_at=now_iso(),
        error=error,
    )


def _state_config(context: dict[str, Any]) -> dict[str, Any]:
    direct = context.get("state_bootstrap", {})
    if isinstance(direct, dict) and direct:
        return dict(direct)
    profile_config = context.get("profile_config", {})
    if isinstance(profile_config, dict) and isinstance(profile_config.get("state_bootstrap", {}), dict):
        return dict(profile_config.get("state_bootstrap", {}))
    return {}


def _session_get(session: requests.Session, url: str):
    try:
        return session.get(url, timeout=6, allow_redirects=True)
    except requests.RequestException:
        fallback = safe_fetch_text(url, timeout_seconds=3.0, max_bytes=120_000)
        return _ResponseLike(fallback.url, fallback.text, fallback.status_code)


def _attempt_login(session: requests.Session, pages: list[tuple[str, str]], config: dict[str, Any], logs: list[str]) -> dict[str, Any]:
    forms = []
    for page_url, html in pages:
        for form in _parse_forms(page_url, html):
            if _is_login_form(form):
                forms.append((page_url, form))
    if not forms:
        logs.append("No password-bearing login form was detected.")
        return {"authenticated": False}

    credentials = _credential_candidates(config)
    if not credentials:
        logs.append("No credential candidates configured for state bootstrap.")
        return {"authenticated": False, "login_url": forms[0][0]}

    for page_url, form in forms[:3]:
        action_url = urljoin(page_url, form.action or page_url)
        for credential in credentials[:6]:
            data = _form_payload(form, credential)
            try:
                method = (form.method or "POST").upper()
                if method == "GET":
                    response = session.request(method, action_url, params=data, timeout=6, allow_redirects=True)
                else:
                    response = session.request(method, action_url, data=data, timeout=6, allow_redirects=True)
            except requests.RequestException as exc:
                logs.append(f"Login form submission failed: {exc}")
                continue
            if _login_succeeded(response, action_url):
                logs.append(f"Authenticated session established through a password form at {page_url}.")
                return {"authenticated": True, "login_url": page_url, "final_url": response.url}
    return {"authenticated": False, "login_url": forms[0][0]}


def _apply_post_login_state_actions(
    session: requests.Session,
    target: str,
    login_result: dict[str, Any],
    config: dict[str, Any],
    logs: list[str],
) -> list[dict[str, Any]]:
    action_config = _post_login_state_config(config)
    if not bool(action_config.get("enabled", True)):
        return []

    actions: list[dict[str, Any]] = []
    max_pages = int(action_config.get("max_pages", 8) or 8)
    max_actions = int(action_config.get("max_actions", 2) or 2)
    for page_url in _state_candidate_urls(session, target, login_result, action_config)[:max_pages]:
        response = _session_get(session, page_url)
        html = response.text or ""
        effective_page_url = response.url or page_url
        for form in _parse_forms(effective_page_url, html):
            if _is_login_form(form):
                continue
            payload, overridden = _state_form_payload(form, action_config)
            if not payload or not overridden:
                continue
            action_url = urljoin(effective_page_url, form.action or effective_page_url)
            method = (form.method or "POST").upper()
            try:
                if method == "GET":
                    result = session.request(method, action_url, params=payload, timeout=6, allow_redirects=True)
                else:
                    result = session.request(method, action_url, data=payload, timeout=6, allow_redirects=True)
            except requests.RequestException as exc:
                logs.append(f"Post-login state form submission failed: {exc}")
                continue
            action = {
                "page_url": effective_page_url,
                "action_url": action_url,
                "final_url": getattr(result, "url", action_url),
                "method": method,
                "status_code": int(getattr(result, "status_code", 0) or 0),
                "overridden_fields": sorted(overridden),
                "submitted_field_count": len(payload),
            }
            actions.append(action)
            logs.append(f"Post-login state form submitted at {effective_page_url}; fields={','.join(sorted(overridden))}.")
            if len(actions) >= max_actions:
                return actions
    if bool(action_config.get("log_when_missing", False)):
        logs.append("No post-login state form matched configured state field hints.")
    return actions


def _post_login_state_config(config: dict[str, Any]) -> dict[str, Any]:
    raw = config.get("post_login_state_actions", {})
    if isinstance(raw, dict):
        action_config = dict(raw)
    elif raw is True:
        action_config = {"enabled": True}
    else:
        action_config = {}
    action_config.setdefault("enabled", True)
    action_config.setdefault("candidate_paths", ["/security.php", "/security", "/settings", "/settings/security", "/profile/security", "/preferences", "/config"])
    action_config.setdefault("field_values", DEFAULT_STATE_FIELD_VALUES)
    action_config.setdefault("form_field_hints", STATE_FIELD_HINTS)
    action_config.setdefault("link_hints", STATE_PAGE_HINTS)
    return action_config


def _state_candidate_urls(
    session: requests.Session,
    target: str,
    login_result: dict[str, Any],
    action_config: dict[str, Any],
) -> list[str]:
    urls: list[str] = []
    for raw_path in action_config.get("candidate_paths", []):
        path = str(raw_path or "").strip()
        if path:
            urls.append(urljoin(target, path))

    link_hints = tuple(str(item).strip().lower() for item in action_config.get("link_hints", []) if str(item).strip())
    for seed in _dedupe([target, str(login_result.get("final_url", "") or "")]):
        if not seed:
            continue
        response = _session_get(session, urljoin(target, seed))
        page_url = response.url or seed
        for href in LINK_RE.findall(response.text or ""):
            absolute = urljoin(page_url, href)
            if _origin(absolute) == _origin(target) and any(hint in absolute.lower() for hint in link_hints):
                urls.append(absolute)
    return _dedupe(urls)


def _state_form_payload(form: HtmlForm, action_config: dict[str, Any]) -> tuple[dict[str, str], set[str]]:
    raw_values = action_config.get("field_values", DEFAULT_STATE_FIELD_VALUES)
    field_values = {}
    if isinstance(raw_values, dict):
        field_values = {str(key).strip().lower(): str(value) for key, value in raw_values.items() if str(key).strip() and str(value).strip()}
    hints = tuple(str(item).strip().lower() for item in action_config.get("form_field_hints", STATE_FIELD_HINTS) if str(item).strip())
    default_value = str(action_config.get("default_value", "low") or "low")
    payload: dict[str, str] = {}
    overridden: set[str] = set()
    for field in form.fields:
        if not field.name:
            continue
        lower = field.name.lower()
        if lower in field_values:
            payload[field.name] = field_values[lower]
            overridden.add(field.name)
            continue
        if field.field_type not in {"hidden", "submit", "button", "image"} and any(hint in lower for hint in hints):
            payload[field.name] = default_value
            overridden.add(field.name)
            continue
        if field.field_type in {"checkbox", "radio"}:
            continue
        if field.field_type in {"submit", "hidden"} or field.value:
            payload[field.name] = field.value
    return payload, overridden


def _credential_candidates(config: dict[str, Any]) -> list[dict[str, str]]:
    raw = config.get("credential_candidates", [])
    credentials: list[dict[str, str]] = []
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            username = str(item.get("username", "")).strip()
            password = str(item.get("password", "")).strip()
            if username and password:
                credentials.append({"username": username, "password": password})
    if not credentials and bool(config.get("allow_common_lab_credentials", True)):
        credentials.append({"username": "admin", "password": "password"})
    return credentials


def _form_payload(form: HtmlForm, credential: dict[str, str]) -> dict[str, str]:
    payload: dict[str, str] = {}
    username_field = _first_field(form, USERNAME_HINTS)
    password_field = _first_field(form, PASSWORD_HINTS, field_type="password") or _first_field(form, PASSWORD_HINTS)
    for field in form.fields:
        if not field.name:
            continue
        if field.name == username_field:
            payload[field.name] = credential["username"]
        elif field.name == password_field:
            payload[field.name] = credential["password"]
        elif field.field_type in {"submit", "hidden"} or field.value:
            payload[field.name] = field.value
    return payload


def _first_field(form: HtmlForm, hints: tuple[str, ...], *, field_type: str = "") -> str:
    for field in form.fields:
        lower = field.name.lower()
        if field_type and field.field_type != field_type:
            continue
        if not field_type and (field.field_type in {"hidden", "submit", "button", "image"} or any(token in lower for token in NON_CREDENTIAL_FIELD_HINTS)):
            continue
        if any(hint in lower for hint in hints):
            return field.name
    return ""


def _is_login_form(form: HtmlForm) -> bool:
    return any(field.field_type == "password" or any(hint in field.name.lower() for hint in PASSWORD_HINTS) for field in form.fields)


def _login_succeeded(response: requests.Response, action_url: str) -> bool:
    body = (response.text or "").lower()
    if any(marker in body for marker in SUCCESS_MARKERS):
        return True
    if "login failed" in body or "invalid password" in body or "incorrect" in body:
        return False
    if not _has_password_form(response.text or "") and "login" not in urlparse(response.url or action_url).path.lower():
        return True
    return False


def _has_password_form(html: str) -> bool:
    return any(_is_login_form(form) for form in _parse_forms("", html))


def _login_candidate_urls(target: str, page_url: str, html: str) -> list[str]:
    urls = [page_url]
    for href in LINK_RE.findall(html or ""):
        absolute = urljoin(page_url, href)
        lower = absolute.lower()
        if any(hint in lower for hint in LOGIN_LINK_HINTS):
            urls.append(absolute)
    urls.extend(urljoin(target, path) for path in ("login", "login/", "login.php", "signin", "signin/"))
    return _dedupe(urls)[:10]


def _discover_same_origin_urls(target: str, pages: list[tuple[str, str]]) -> list[str]:
    origin = _origin(target)
    urls: list[str] = []
    for page_url, html in pages:
        if page_url:
            urls.append(page_url)
        for href in LINK_RE.findall(html or ""):
            absolute = urljoin(page_url or target, href)
            if _origin(absolute) == origin and not _skip_url(absolute):
                urls.append(absolute)
    return _dedupe(urls)[:80]


def _parse_forms(page_url: str, html: str) -> list[HtmlForm]:
    forms: list[HtmlForm] = []
    for attrs, body in FORM_RE.findall(html or ""):
        parsed = _parse_attrs(attrs)
        fields = []
        for _tag, tag_attrs in TAG_RE.findall(body):
            field_attrs = _parse_attrs(tag_attrs)
            name = field_attrs.get("name", "").strip()
            if not name:
                continue
            fields.append(
                FormField(
                    name=name,
                    field_type=field_attrs.get("type", "text").strip().lower() or "text",
                    value=field_attrs.get("value", "").strip(),
                )
            )
        forms.append(HtmlForm(action=parsed.get("action", page_url), method=parsed.get("method", "POST").upper(), fields=fields))
    return forms


def _parse_attrs(attrs: str) -> dict[str, str]:
    return {str(match.group("name")).lower(): str(match.group("value")) for match in ATTR_RE.finditer(attrs or "")}


def _cookie_header(session: requests.Session) -> str:
    return "; ".join(f"{cookie.name}={cookie.value}" for cookie in session.cookies)


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    return (parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port)


def _skip_url(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    if "logout" in path:
        return True
    query_keys = {key.lower() for key in parse_qs(parsed.query, keep_blank_values=True)}
    if path.endswith("security.php") and query_keys & {"phpids", "test", "security", "seclev_submit", "user_token"}:
        return True
    return any(path.endswith(suffix) for suffix in (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map"))


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        key = str(value or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(key)
    return result


@dataclass(slots=True)
class _ResponseLike:
    url: str
    text: str
    status_code: int = 0
