from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import product
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

from ai_security_agent.schemas import Finding, ModuleResult

from .common import is_local_or_lab_target, now_iso, safe_fetch_text, target_scope_label
from .followup_bridge import extract_followup_inputs


COMMON_USERNAMES = ("admin", "root", "test", "guest", "demo", "user")
COMMON_PASSWORDS = ("admin", "123456", "password", "guest", "test", "000000", "user")
MAX_DISCOVERY_PAGES = 60
MAX_LOGIN_FORMS = 12
MAX_CREDENTIAL_ATTEMPTS_PER_FORM = 12

LINK_RE = re.compile(r"""(?i)\b(?:href|src|action)\s*=\s*["'](?P<url>[^"']+)["']""")
FORM_RE = re.compile(r"(?is)<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>")
ACTION_RE = re.compile(r"""(?i)\baction\s*=\s*["'](?P<value>[^"']*)["']""")
METHOD_RE = re.compile(r"""(?i)\bmethod\s*=\s*["'](?P<value>[^"']+)["']""")
INPUT_TAG_RE = re.compile(r"(?is)<input\b(?P<attrs>[^>]*)>")
ATTR_RE = re.compile(r"""(?i)\b(?P<name>[a-z_:][-a-z0-9_:.]*)\s*=\s*["'](?P<value>[^"']*)["']""")
PASSWORD_FIELD_RE = re.compile(r"""(?is)<input\b[^>]*\btype\s*=\s*["']?password["']?[^>]*>""")
LOGIN_MARKER_RE = re.compile(r"\b(login|log in|signin|sign in|username|user name|password|administrator|admin panel)\b", re.IGNORECASE)
DEFAULT_CRED_RE = re.compile(r"\b(admin/admin|admin:admin|admin/123456|default password|demo account|test account)\b", re.IGNORECASE)
CREDENTIAL_PAIR_RE = re.compile(r"\b(?P<user>[A-Za-z][A-Za-z0-9_-]{1,31})\s*[/：:]\s*(?P<password>[A-Za-z0-9!@#$%^&*()._-]{3,32})\b")
SUCCESS_RE = re.compile(
    r"(?i)\b(logout|sign out|dashboard|profile|admin panel|welcome|login success|member center|account|管理中心|退出登录|个人信息|欢迎)\b"
)
FAILURE_RE = re.compile(r"(?i)\b(login failed|invalid|incorrect|wrong password|try again|认证失败|登录失败|密码错误|用户名错误)\b")
DENY_RE = re.compile(r"(?i)\b(forbidden|unauthorized|access denied|permission denied|not allowed)\b")


@dataclass(slots=True)
class LoginForm:
    page_url: str
    action: str
    method: str
    inputs: dict[str, str]
    input_types: dict[str, str]
    source: str = "html_form"


@dataclass(slots=True)
class LoginAttempt:
    username: str
    password: str
    url: str
    final_url: str
    status_code: int
    body: str
    error: str = ""


def run(target: str, context: dict | None = None) -> ModuleResult:
    started = now_iso()
    logs: list[str] = []
    if not is_local_or_lab_target(target):
        return ModuleResult(
            module="weak_password",
            target=target,
            status="skipped",
            findings=[],
            logs=["Target is outside the local/course-lab allowlist; weak password audit skipped."],
            started_at=started,
            finished_at=now_iso(),
            error="only localhost or course lab targets are allowed",
        )

    logs.append(f"Target scope: {target_scope_label(target)}")
    followup_inputs = extract_followup_inputs("weak_password", context)
    pages = _discover_login_pages(target, followup_inputs, logs)
    forms = _discover_login_forms(pages)
    logs.append(f"Weak-password login inventory: pages={len(pages)}, forms={len(forms)}")

    findings: list[Finding] = []
    verified_keys: set[tuple[str, str]] = set()
    for form in forms[:MAX_LOGIN_FORMS]:
        credentials = _credential_candidates(form, pages.get(form.page_url, ""))
        if not credentials:
            findings.append(_login_surface_candidate(form, pages.get(form.page_url, ""), []))
            continue
        verified = _verify_form(form, credentials, logs)
        if verified is not None:
            key = (verified.location, verified.metadata.get("weak_password_context", {}).get("username", ""))
            if key not in verified_keys:
                verified_keys.add(key)
                findings.append(verified)
            continue
        findings.append(_login_surface_candidate(form, pages.get(form.page_url, ""), credentials))

    if not findings:
        findings.append(
            Finding(
                title="Weak password login-surface inventory",
                severity="info",
                location=target,
                evidence="No reachable login form with password input was identified from entry pages and upstream context.",
                kind="scope",
                verification_status="informational",
                verified=False,
                recommendation="Provide login entrypoints or upstream route seeds for deeper weak-password validation.",
            )
        )

    return ModuleResult(
        module="weak_password",
        target=target,
        status="ok",
        findings=_dedupe_findings(findings)[:6],
        followup_context=_build_followup_context(findings, forms),
        logs=logs,
        started_at=started,
        finished_at=now_iso(),
    )


def _discover_login_pages(target: str, followup_inputs: dict[str, Any], logs: list[str]) -> dict[str, str]:
    urls = _seed_urls(target, followup_inputs)
    pages: dict[str, str] = {}
    index = 0
    while index < len(urls) and len(pages) < MAX_DISCOVERY_PAGES:
        url = urls[index]
        index += 1
        if _looks_like_static_asset(url) or url in pages:
            continue
        response = safe_fetch_text(url, timeout_seconds=2.0, max_bytes=120_000)
        if not response.ok:
            continue
        body = str(response.text or "")
        pages[url] = body
        if len(pages) <= 10:
            logs.append(f"Fetched weak-password candidate page: {url} HTTP {response.status_code}")
        for match in LINK_RE.finditer(body):
            absolute = urljoin(url, match.group("url"))
            if _same_origin(target, absolute) and (_looks_like_login_url(absolute) or _body_has_login_cue(body)):
                _append_unique(urls, absolute)
    return pages


def _seed_urls(target: str, followup_inputs: dict[str, Any]) -> list[str]:
    urls = [
        target,
        urljoin(target, "/login"),
        urljoin(target, "/login.php"),
        urljoin(target, "/signin"),
        urljoin(target, "/admin"),
        urljoin(target, "/admin/login"),
        urljoin(target, "/admin/login.php"),
        urljoin(target, "/user/login"),
        urljoin(target, "/account/login"),
    ]
    for value in _context_seed_urls(followup_inputs):
        absolute = urljoin(target, value)
        if _same_origin(target, absolute):
            _append_unique(urls, absolute)
    return urls


def _context_seed_urls(followup_inputs: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("auth_paths", "api_paths", "route_prefixes", "config_entrypoints", "correlated_discovery_seeds", "relationship_followup_seeds"):
        raw = followup_inputs.get(key, [])
        if isinstance(raw, list):
            values.extend(str(item).strip() for item in raw if str(item).strip())
        elif isinstance(raw, str) and raw.strip():
            values.append(raw.strip())
    return values


def _discover_login_forms(pages: dict[str, str]) -> list[LoginForm]:
    forms: list[LoginForm] = []
    for page_url, body in pages.items():
        for form in _parse_forms(page_url, body):
            if _looks_like_login_form(form, body):
                forms.append(form)
    forms.sort(key=_login_form_score, reverse=True)
    return _dedupe_forms(forms)


def _parse_forms(page_url: str, html: str) -> list[LoginForm]:
    forms: list[LoginForm] = []
    for match in FORM_RE.finditer(html or ""):
        attrs = match.group("attrs") or ""
        body = match.group("body") or ""
        action_match = ACTION_RE.search(attrs)
        method_match = METHOD_RE.search(attrs)
        action_value = action_match.group("value") if action_match else ""
        action = urljoin(page_url, action_value) if action_value else page_url
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
        forms.append(LoginForm(page_url=page_url, action=action, method=method, inputs=inputs, input_types=input_types))
    return forms


def _looks_like_login_form(form: LoginForm, page_body: str = "") -> bool:
    if not any("pass" in name.lower() or kind == "password" for name, kind in form.input_types.items()):
        return False
    text = " ".join([form.page_url, form.action, *form.inputs, *form.input_types.values(), page_body[:2000]]).lower()
    return bool(LOGIN_MARKER_RE.search(text) or _looks_like_login_url(form.action) or _looks_like_login_url(form.page_url))


def _login_form_score(form: LoginForm) -> int:
    text = " ".join([form.page_url, form.action, *form.inputs, *form.input_types.values()]).lower()
    score = 0
    if "password" in text or "pass" in text:
        score += 80
    if any(marker in text for marker in ("login", "signin", "auth", "session")):
        score += 50
    if any("user" in name or "email" in name or "account" in name for name in form.inputs):
        score += 30
    if any(marker in text for marker in ("admin", "manage", "dashboard")):
        score += 20
    return score


def _credential_candidates(form: LoginForm, page_body: str) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    for pair in _credential_pairs_from_text(page_body):
        _append_unique_pair(candidates, pair)
    username_field = _username_field(form)
    page_text = f"{form.page_url} {form.action}".lower()
    base_users = list(COMMON_USERNAMES)
    if any(marker in page_text for marker in ("admin", "manage", "dashboard")) and "admin" not in base_users:
        base_users.insert(0, "admin")
    for username, password in product(base_users, COMMON_PASSWORDS):
        if username_field and username_field.lower() in {"email", "mail"} and "@" not in username:
            continue
        _append_unique_pair(candidates, (username, password))
    return candidates[:MAX_CREDENTIAL_ATTEMPTS_PER_FORM]


def _credential_pairs_from_text(text: str) -> list[tuple[str, str]]:
    focused = " ".join(_credential_hint_texts(text))
    search_text = focused or re.sub(r"(?is)<script\b.*?</script>|<style\b.*?</style>|<!--.*?-->", " ", text or "")
    pairs: list[tuple[str, str]] = []
    for match in CREDENTIAL_PAIR_RE.finditer(search_text):
        pair = (match.group("user").strip(), match.group("password").strip())
        if _looks_like_resource_pair(*pair):
            continue
        _append_unique_pair(pairs, pair)
    return pairs


def _credential_hint_texts(text: str) -> list[str]:
    hints: list[str] = []
    for attr in ("data-content", "title", "aria-label"):
        pattern = re.compile(rf"""(?is)\b{re.escape(attr)}\s*=\s*["'](?P<value>[^"']+)["']""")
        hints.extend(match.group("value") for match in pattern.finditer(text or ""))
    visible = re.sub(r"(?is)<script\b.*?</script>|<style\b.*?</style>|<!--.*?-->", " ", text or "")
    visible = re.sub(r"(?is)<[^>]+>", " ", visible)
    for line in re.split(r"[\r\n]+", visible):
        lowered = line.lower()
        if "/" in line and any(marker in lowered for marker in ("user", "account", "password", "admin", "账号", "用户", "密码")):
            hints.append(line)
    return hints


def _verify_form(form: LoginForm, credentials: list[tuple[str, str]], logs: list[str]) -> Finding | None:
    username_field = _username_field(form)
    password_field = _password_field(form)
    if not username_field or not password_field:
        return None
    for username, password in credentials[:MAX_CREDENTIAL_ATTEMPTS_PER_FORM]:
        attempt = _submit_login(form, username_field, password_field, username, password)
        if attempt.error:
            logs.append(f"Weak-password attempt failed for {form.action}: {attempt.error}")
            continue
        if _login_successful(attempt, username):
            context = _weak_password_context(form, attempt, username, password)
            return Finding(
                title=f"Weak/default credential accepted for {username}",
                severity="high",
                location=form.action,
                evidence=_weak_password_evidence(form, attempt, username, password),
                kind="vulnerability",
                verification_status="confirmed",
                verified=True,
                recommendation="Disable default credentials, require password rotation, and add rate limiting/lockout on login endpoints.",
                metadata={"weak_password_context": context, "verification_source": "weak_password"},
            )
    return None


def _submit_login(form: LoginForm, username_field: str, password_field: str, username: str, password: str) -> LoginAttempt:
    data = dict(form.inputs)
    data[username_field] = username
    data[password_field] = password
    submit_field = _submit_field(form)
    if submit_field and not data.get(submit_field):
        data[submit_field] = "Login"
    session = requests.Session()
    try:
        if form.method == "GET":
            parsed = urlparse(form.action)
            query = parse_qs(parsed.query, keep_blank_values=True)
            for key, value in data.items():
                query[key] = [value]
            request_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
            response = session.get(request_url, timeout=4, allow_redirects=True)
        else:
            response = session.post(form.action, data=data, timeout=4, allow_redirects=True)
    except requests.RequestException as exc:
        return LoginAttempt(username=username, password=password, url=form.action, final_url=form.action, status_code=0, body="", error=str(exc))
    return LoginAttempt(
        username=username,
        password=password,
        url=form.action,
        final_url=str(response.url),
        status_code=int(response.status_code),
        body=str(response.text or "")[:140_000],
    )


def _login_successful(attempt: LoginAttempt, username: str) -> bool:
    if attempt.status_code not in {200, 204}:
        return False
    body = attempt.body.lower()
    if DENY_RE.search(body) or FAILURE_RE.search(body):
        return False
    if _looks_like_login_challenge(body) and "logout" not in body:
        return False
    if username and username.lower() in body and SUCCESS_RE.search(body):
        return True
    if _url_path_changed(attempt.url, attempt.final_url) and SUCCESS_RE.search(body):
        return True
    return bool(SUCCESS_RE.search(body) and "password" not in _response_core(body)[:800])


def _login_surface_candidate(form: LoginForm, page_body: str, credentials: list[tuple[str, str]]) -> Finding:
    default_hint = bool(DEFAULT_CRED_RE.search(page_body or ""))
    evidence = "\n".join(
        [
            f"Login page: {form.page_url}",
            f"Action: {form.action}",
            f"Method: {form.method}",
            f"Username field: {_username_field(form) or 'not parsed'}",
            f"Password field: {_password_field(form) or 'password field detected'}",
            f"Default-credential hint in page: {'yes' if default_hint else 'no'}",
            f"Credential candidates attempted/queued: {len(credentials)}",
            "No accepted credential was confirmed for this surface.",
        ]
    )
    return Finding(
        title="Weak password login surface candidate",
        severity="medium" if default_hint else "low",
        location=form.action,
        evidence=evidence,
        kind="candidate" if default_hint else "evidence",
        verification_status="unconfirmed" if default_hint else "informational",
        verified=False,
        recommendation="Review login hardening, default credentials, password policy, and lockout/rate-limit controls.",
        metadata={"weak_password_context": _form_context(form)},
    )


def _weak_password_context(form: LoginForm, attempt: LoginAttempt, username: str, password: str) -> dict[str, Any]:
    return {
        "page_url": form.page_url,
        "action": form.action,
        "method": form.method,
        "username_field": _username_field(form),
        "password_field": _password_field(form),
        "username": username,
        "masked_password": _mask(password),
        "final_url": attempt.final_url,
        "status_code": attempt.status_code,
        "source": "bounded_login_submission",
    }


def _form_context(form: LoginForm) -> dict[str, Any]:
    return {
        "page_url": form.page_url,
        "action": form.action,
        "method": form.method,
        "username_field": _username_field(form),
        "password_field": _password_field(form),
        "source": form.source,
    }


def _weak_password_evidence(form: LoginForm, attempt: LoginAttempt, username: str, password: str) -> str:
    markers = _success_markers(attempt.body)
    return "\n".join(
        [
            "Strategy: bounded_login_submission",
            f"Login page: {form.page_url}",
            f"Action: {form.action}",
            f"Method: {form.method}",
            f"Username field: {_username_field(form)}",
            f"Password field: {_password_field(form)}",
            f"Accepted username: {username}",
            f"Accepted password: {_mask(password)}",
            f"Final URL: {attempt.final_url}",
            f"Status: {attempt.status_code}",
            f"Authenticated markers: {', '.join(markers) or 'success signal'}",
        ]
    )


def _username_field(form: LoginForm) -> str:
    for name, field_type in form.input_types.items():
        lowered = f"{name} {field_type}".lower()
        if any(marker in lowered for marker in ("user", "email", "account", "login", "name")):
            return name
    for name, field_type in form.input_types.items():
        if field_type not in {"password", "hidden", "submit", "button"}:
            return name
    return ""


def _password_field(form: LoginForm) -> str:
    for name, field_type in form.input_types.items():
        lowered = f"{name} {field_type}".lower()
        if "pass" in lowered or "pwd" in lowered:
            return name
    return ""


def _submit_field(form: LoginForm) -> str:
    for name, field_type in form.input_types.items():
        if field_type in {"submit", "button"} or "submit" in name.lower() or "login" in name.lower():
            return name
    return ""


def _looks_like_login_url(url: str) -> bool:
    parsed = urlparse(url)
    leaf = parsed.path.rsplit("/", 1)[-1].lower()
    text = f"{leaf}?{parsed.query}".lower()
    if any(marker in text for marker in ("login", "signin", "sign-in", "session")):
        return True
    return leaf in {"auth", "authenticate"} or leaf.startswith(("auth_", "auth-"))


def _body_has_login_cue(body: str) -> bool:
    return bool(PASSWORD_FIELD_RE.search(body or "") and LOGIN_MARKER_RE.search(body or ""))


def _looks_like_login_challenge(body: str) -> bool:
    lowered = str(body or "").lower()
    for match in FORM_RE.finditer(lowered):
        attrs = match.group("attrs") or ""
        form_body = match.group("body") or ""
        has_password = bool(re.search(r"<input\b[^>]*\btype\s*=\s*['\"]?password\b", form_body))
        if not has_password:
            continue
        form_text = f"{attrs} {form_body}"
        login_action = bool(re.search(r"\baction\s*=\s*['\"][^'\"]*(login|signin|auth|session)", attrs))
        login_submit = bool(re.search(r"\b(type|name|value)\s*=\s*['\"]?(login|sign in|signin)\b", form_text))
        if login_action or login_submit:
            return True
    return False


def _success_markers(body: str) -> list[str]:
    markers: list[str] = []
    for match in SUCCESS_RE.finditer(body or ""):
        value = match.group(0).strip().lower()
        if value and value not in markers:
            markers.append(value)
        if len(markers) >= 5:
            break
    return markers


def _response_core(body: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body or "")).strip().lower()


def _url_path_changed(left: str, right: str) -> bool:
    left_parsed = urlparse(left)
    right_parsed = urlparse(right)
    return (left_parsed.scheme, left_parsed.netloc, left_parsed.path) != (right_parsed.scheme, right_parsed.netloc, right_parsed.path)


def _same_origin(left: str, right: str) -> bool:
    left_parsed = urlparse(left)
    right_parsed = urlparse(right)
    return (left_parsed.scheme, left_parsed.netloc) == (right_parsed.scheme, right_parsed.netloc)


def _looks_like_static_asset(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.query:
        return False
    return parsed.path.lower().endswith((".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf"))


def _looks_like_resource_pair(username: str, password: str) -> bool:
    lowered = f"{username}/{password}".lower()
    resource_words = {
        "css",
        "js",
        "assets",
        "avatars",
        "jquery",
        "bootstrap",
        "font-awesome",
        "static",
        "scripts",
        "styles",
        "images",
        "img",
        "fonts",
        "vendor",
    }
    if username.lower() in resource_words or password.lower() in resource_words:
        return True
    return any(suffix in lowered for suffix in (".php", ".css", ".js", ".png", ".jpg", "../", "../../"))


def _mask(value: str) -> str:
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= 2:
        return "*" * len(text)
    return text[0] + "*" * max(1, len(text) - 2) + text[-1]


def _dedupe_forms(forms: list[LoginForm]) -> list[LoginForm]:
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    deduped: list[LoginForm] = []
    for form in forms:
        key = (form.action, form.method, tuple(sorted(form.inputs)))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(form)
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


def _append_unique(values: list[str], value: str) -> None:
    value = str(value or "").strip()
    if value and value not in values:
        values.append(value)


def _append_unique_pair(values: list[tuple[str, str]], pair: tuple[str, str]) -> None:
    if pair[0] and pair[1] and pair not in values:
        values.append(pair)


def _build_followup_context(findings: list[Finding], forms: list[LoginForm]) -> dict[str, Any]:
    confirmed = [
        item.metadata.get("weak_password_context", {})
        for item in findings
        if item.verified and isinstance(item.metadata.get("weak_password_context", {}), dict)
    ]
    return {
        "producer": "weak_password",
        "consumers": {
            "poc_verify": {
                "weak_password_findings": confirmed,
                "login_forms": [_form_context(item) for item in forms[:20]],
            }
        },
    }
