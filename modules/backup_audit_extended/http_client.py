from __future__ import annotations

from dataclasses import dataclass

from ai_security_agent.integrations.http import fetch_bytes as http_fetch_bytes
from ai_security_agent.integrations.http import fetch_many_text as http_fetch_many_text
from ai_security_agent.integrations.http import fetch_text as http_fetch_text

from ..common import is_local_or_lab_target, now_iso


DEFAULT_HEADERS = {"User-Agent": "recon-backup-agent/1.0"}


@dataclass(slots=True)
class FetchResult:
    url: str
    status_code: int = 0
    headers: dict[str, str] | None = None
    text: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400 and not self.error


@dataclass(slots=True)
class BinaryFetchResult:
    url: str
    status_code: int = 0
    headers: dict[str, str] | None = None
    content: bytes = b""
    truncated: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400 and not self.error


def fetch_text(url: str, timeout: float = 8, max_bytes: int = 32768) -> FetchResult:
    if not is_local_or_lab_target(url):
        return FetchResult(url=url, error="target is outside the local/course-lab allowlist")
    exchange = http_fetch_text(url, timeout_seconds=timeout, max_bytes=max_bytes, headers=DEFAULT_HEADERS)
    return FetchResult(
        url=exchange.url,
        status_code=exchange.status_code,
        headers=exchange.headers,
        text=exchange.text,
        error=exchange.error,
    )


def fetch_bytes(url: str, timeout: float = 8, max_bytes: int = 1_048_576) -> BinaryFetchResult:
    if not is_local_or_lab_target(url):
        return BinaryFetchResult(url=url, error="target is outside the local/course-lab allowlist")
    exchange = http_fetch_bytes(url, timeout_seconds=timeout, max_bytes=max_bytes, headers=DEFAULT_HEADERS)
    return BinaryFetchResult(
        url=exchange.url,
        status_code=exchange.status_code,
        headers=exchange.headers,
        content=exchange.body,
        truncated=len(exchange.body) >= max_bytes,
        error=exchange.error,
    )


def fetch_many_text(urls: list[str], timeout: float = 8, max_bytes: int = 32768, max_connections: int = 8) -> list[FetchResult]:
    exchanges = http_fetch_many_text(
        urls,
        timeout_seconds=timeout,
        max_bytes=max_bytes,
        max_connections=max_connections,
        headers=DEFAULT_HEADERS,
    )
    return [
        FetchResult(
            url=item.url,
            status_code=item.status_code,
            headers=item.headers,
            text=item.text,
            error=item.error,
        )
        for item in exchanges
    ]
