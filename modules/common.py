from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
import base64
import re

from ai_security_agent.integrations.http import fetch_bytes as http_fetch_bytes


AUTHORIZED_DEMO_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".test",
    ".example",
    ".invalid",
    ".internal",
    ".lan",
    ".home",
)
DOCKER_LAB_HOSTS = {
    "host.docker.internal",
    "gateway.docker.internal",
    "docker.internal",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def is_authorized_demo_target(target: str) -> bool:
    host = (urlparse(target).hostname or "").strip().lower()
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host:
            return True
        return host.endswith(AUTHORIZED_DEMO_HOST_SUFFIXES)
    return bool(address.is_private or address.is_loopback or address.is_link_local or address.is_reserved)


def is_docker_backed_lab_target(target: str) -> bool:
    host = (urlparse(target).hostname or "").lower()
    return host in DOCKER_LAB_HOSTS or host.endswith(".docker.internal")


def target_scope_label(target: str) -> str:
    host = (urlparse(target).hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return "local"
    if is_docker_backed_lab_target(target):
        return "docker-backed lab"
    if is_authorized_demo_target(target):
        return "course lab"
    return "external"


def is_local_or_lab_target(target: str) -> bool:
    return target_scope_label(target) != "external"


@dataclass(slots=True)
class FetchResult:
    url: str
    status_code: int = 0
    headers: dict[str, str] | None = None
    text: str = ""
    error: str = ""
    elapsed_ms: int = 0

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400 and not self.error


@dataclass(slots=True)
class BinaryFetchResult:
    url: str
    status_code: int = 0
    headers: dict[str, str] | None = None
    content: bytes = b""
    error: str = ""
    elapsed_ms: int = 0

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400 and not self.error

    def text(self, *, fallback_charset: str = "utf-8") -> str:
        charset = _charset_from_content_type((self.headers or {}).get("content-type", "")) or fallback_charset
        return self.content.decode(charset, errors="replace")


def safe_fetch_text(target: str, *, timeout_seconds: float = 2.0, max_bytes: int = 120_000, headers: dict[str, str] | None = None) -> FetchResult:
    result = safe_fetch_bytes(target, timeout_seconds=timeout_seconds, max_bytes=max_bytes, headers=headers)
    if not result.ok:
        return FetchResult(
            url=result.url,
            status_code=result.status_code,
            headers=result.headers,
            error=result.error,
            elapsed_ms=result.elapsed_ms,
        )
    return FetchResult(
        url=result.url,
        status_code=result.status_code,
        headers=result.headers,
        text=result.text(),
        elapsed_ms=result.elapsed_ms,
    )


def safe_fetch_bytes(target: str, *, timeout_seconds: float = 2.0, max_bytes: int = 120_000, headers: dict[str, str] | None = None) -> BinaryFetchResult:
    if not is_local_or_lab_target(target):
        return BinaryFetchResult(url=target, error="target is outside the local/course-lab allowlist")
    exchange = http_fetch_bytes(target, timeout_seconds=timeout_seconds, max_bytes=max_bytes, headers=headers)
    return BinaryFetchResult(
        url=exchange.url,
        status_code=exchange.status_code,
        headers=exchange.headers,
        content=exchange.body,
        error=exchange.error,
        elapsed_ms=exchange.elapsed_ms,
    )


def resolve_target_url(base_url: str, maybe_relative: str) -> str:
    return urljoin(base_url, maybe_relative)


def _charset_from_content_type(content_type: str) -> str:
    for part in content_type.split(";"):
        key, _, value = part.strip().partition("=")
        if key.lower() == "charset" and value:
            return value.strip()
    return ""


def get_skill_bundle(context: dict | None) -> dict:
    if not isinstance(context, dict):
        return {}
    value = context.get("skill_bundle", {})
    return dict(value) if isinstance(value, dict) else {}


def get_support_skills(context: dict | None) -> list[dict]:
    if not isinstance(context, dict):
        return []
    values = context.get("support_skills", [])
    if not isinstance(values, list):
        return []
    return [dict(item) for item in values if isinstance(item, dict)]


def get_report_contract(context: dict | None) -> dict:
    if not isinstance(context, dict):
        return {}
    value = context.get("report_contract", {})
    return dict(value) if isinstance(value, dict) else {}


def compress_text(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def encode_text_preview(value: str, *, limit: int = 6000) -> str:
    snippet = str(value or "")[:limit]
    return base64.b64encode(snippet.encode("utf-8", errors="replace")).decode("ascii")
