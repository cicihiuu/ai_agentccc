from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import requests


DEFAULT_HEADERS = {
    "User-Agent": "ai-security-agent/1.0",
    "Accept": "text/html,application/javascript,text/plain,application/json,*/*;q=0.8",
}


@dataclass(slots=True)
class HTTPExchange:
    url: str
    method: str = "GET"
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str = ""
    elapsed_ms: int = 0
    request_headers: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400 and not self.error

    @property
    def text(self) -> str:
        if not self.body:
            return ""
        charset = _charset_from_content_type(self.headers.get("content-type", "")) or "utf-8"
        return self.body.decode(charset, errors="replace")

    def to_evidence(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "status": self.status_code,
            "response_length": len(self.body),
            "headers": _selected_headers(self.headers),
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
        }


def fetch_text(
    url: str,
    *,
    method: str = "GET",
    body: str = "",
    headers: dict[str, str] | None = None,
    timeout_seconds: float = 8.0,
    max_bytes: int = 120_000,
) -> HTTPExchange:
    return _fetch_sync(url, method=method, body=body, headers=headers, timeout_seconds=timeout_seconds, max_bytes=max_bytes)


def fetch_bytes(
    url: str,
    *,
    method: str = "GET",
    body: str = "",
    headers: dict[str, str] | None = None,
    timeout_seconds: float = 8.0,
    max_bytes: int = 120_000,
) -> HTTPExchange:
    return _fetch_sync(url, method=method, body=body, headers=headers, timeout_seconds=timeout_seconds, max_bytes=max_bytes)


def fetch_many_text(
    urls: list[str],
    *,
    timeout_seconds: float = 8.0,
    max_bytes: int = 120_000,
    max_connections: int = 8,
    headers: dict[str, str] | None = None,
) -> list[HTTPExchange]:
    return asyncio.run(
        _fetch_many(
            urls,
            timeout_seconds=timeout_seconds,
            max_bytes=max_bytes,
            max_connections=max_connections,
            headers=headers,
        )
    )


def fetch_many_bytes(
    urls: list[str],
    *,
    timeout_seconds: float = 8.0,
    max_bytes: int = 120_000,
    max_connections: int = 8,
    headers: dict[str, str] | None = None,
) -> list[HTTPExchange]:
    return fetch_many_text(
        urls,
        timeout_seconds=timeout_seconds,
        max_bytes=max_bytes,
        max_connections=max_connections,
        headers=headers,
    )


def _fetch_sync(
    url: str,
    *,
    method: str,
    body: str,
    headers: dict[str, str] | None,
    timeout_seconds: float,
    max_bytes: int,
) -> HTTPExchange:
    request_headers = dict(DEFAULT_HEADERS)
    if headers:
        request_headers.update(headers)
    started = time.perf_counter()
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=request_headers,
            data=body if method.upper() in {"POST", "PUT", "PATCH", "DELETE"} else None,
            timeout=timeout_seconds,
            allow_redirects=True,
            stream=True,
        )
        body = bytearray()
        for chunk in response.iter_content(chunk_size=4096):
            if not chunk:
                continue
            remaining = max_bytes - len(body)
            if remaining <= 0:
                break
            body.extend(chunk[:remaining])
            if len(body) >= max_bytes:
                break
        return HTTPExchange(
            url=str(response.url),
            method=method.upper(),
            status_code=int(response.status_code),
            headers={str(key).lower(): str(value) for key, value in response.headers.items()},
            body=bytes(body),
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            request_headers=request_headers,
            error="" if response.ok else f"HTTP {response.status_code}",
        )
    except requests.RequestException as exc:
        return HTTPExchange(
            url=url,
            method=method.upper(),
            error=str(exc),
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            request_headers=request_headers,
        )
    except Exception as exc:
        return HTTPExchange(
            url=url,
            method=method.upper(),
            error=str(exc),
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            request_headers=request_headers,
        )


async def _fetch_many(
    urls: list[str],
    *,
    timeout_seconds: float,
    max_bytes: int,
    max_connections: int,
    headers: dict[str, str] | None,
) -> list[HTTPExchange]:
    try:
        import aiohttp
    except ModuleNotFoundError:
        return [fetch_text(url, timeout_seconds=timeout_seconds, max_bytes=max_bytes, headers=headers) for url in urls]

    request_headers = dict(DEFAULT_HEADERS)
    if headers:
        request_headers.update(headers)
    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    connector = aiohttp.TCPConnector(limit=max_connections, ssl=False)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=request_headers) as session:
        return await asyncio.gather(
            *[_fetch_one_async(session, url, max_bytes=max_bytes, request_headers=request_headers) for url in urls]
        )


async def _fetch_one_async(session, url: str, *, max_bytes: int, request_headers: dict[str, str]) -> HTTPExchange:
    started = time.perf_counter()
    try:
        async with session.get(url, allow_redirects=True) as response:
            body = bytearray()
            async for chunk in response.content.iter_chunked(4096):
                if not chunk:
                    continue
                remaining = max_bytes - len(body)
                if remaining <= 0:
                    break
                body.extend(chunk[:remaining])
                if len(body) >= max_bytes:
                    break
            return HTTPExchange(
                url=str(response.url),
                method="GET",
                status_code=int(response.status),
                headers={str(key).lower(): str(value) for key, value in response.headers.items()},
                body=bytes(body),
                elapsed_ms=int((time.perf_counter() - started) * 1000),
                request_headers=request_headers,
                error="" if 200 <= response.status < 400 else f"HTTP {response.status}",
            )
    except Exception as exc:
        return HTTPExchange(
            url=url,
            method="GET",
            error=str(exc),
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            request_headers=request_headers,
        )


def _charset_from_content_type(content_type: str) -> str:
    for part in str(content_type).split(";"):
        key, _, value = part.strip().partition("=")
        if key.lower() == "charset" and value:
            return value.strip()
    return ""


def _selected_headers(headers: dict[str, str]) -> dict[str, str]:
    selected = {}
    for key in ("content-type", "content-length", "server", "set-cookie", "access-control-allow-origin"):
        if key in headers:
            selected[key] = headers[key]
    return selected

