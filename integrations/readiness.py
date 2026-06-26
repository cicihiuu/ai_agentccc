from __future__ import annotations

import importlib.util
import shutil
import sys
from dataclasses import dataclass
from typing import Any

from ai_security_agent.integrations.archive_extract import inspect_archive_tools
from ai_security_agent.integrations.http import fetch_text
from ai_security_agent.integrations.js_runtime import inspect_js_runtime
from ai_security_agent.integrations.mcp_client import inspect_mcp_servers
from ai_security_agent.integrations.sqlmap import inspect_sqlmap


@dataclass(slots=True)
class ReadinessItem:
    name: str
    ok: bool
    required: bool
    message: str


def build_profile_readiness(profile: Any) -> list[ReadinessItem]:
    items = [
        ReadinessItem("python", sys.version_info >= (3, 10), True, f"python={sys.version.split()[0]}"),
        ReadinessItem("langchain", _module_available("langchain"), profile.orchestration.engine == "langgraph", _module_message("langchain")),
        ReadinessItem("langgraph", _module_available("langgraph"), profile.orchestration.engine == "langgraph", _module_message("langgraph")),
        ReadinessItem("requests", _module_available("requests"), True, _module_message("requests")),
        ReadinessItem("aiohttp", _module_available("aiohttp"), profile.http_clients.async_backend == "aiohttp", _module_message("aiohttp")),
        ReadinessItem("jinja2", _module_available("jinja2"), profile.reporting.html_engine == "jinja2", _module_message("jinja2")),
        ReadinessItem("reportlab", _module_available("reportlab"), profile.reporting.pdf_engine == "reportlab", _module_message("reportlab")),
    ]
    if profile.llm.enabled and profile.provider_name == "ollama":
        items.append(_ollama_readiness(profile.base_url or "http://127.0.0.1:11434"))
    if profile.sqlmap.enabled:
        ok, message = inspect_sqlmap(profile.sqlmap.binary)
        items.append(ReadinessItem("sqlmap", ok, False, message))
    if profile.javascript.node_binary:
        ok, message = inspect_js_runtime(
            profile.javascript.node_binary,
            profile.javascript.espree_entry,
            profile.javascript.beautifier_entry,
        )
        items.append(ReadinessItem("javascript", ok, True, message))
    if profile.archive_extract.enabled:
        ok, message = inspect_archive_tools(profile.archive_extract.patool_binary, profile.archive_extract.unrar_binary)
        items.append(ReadinessItem("archive_extract", ok, False, message))
    if profile.sandbox.enabled:
        docker = shutil.which("docker")
        items.append(ReadinessItem("docker", bool(docker), True, docker or "docker binary not found"))
    if profile.mcp.enabled:
        ok, message = inspect_mcp_servers(profile.mcp.servers, profile.mcp.required_tools)
        items.append(ReadinessItem("mcp", ok, True, message))
    return items


def _module_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _module_message(name: str) -> str:
    return f"{name} available" if _module_available(name) else f"{name} not installed"


def _ollama_readiness(base_url: str) -> ReadinessItem:
    exchange = fetch_text(f"{base_url.rstrip('/')}/api/tags", timeout_seconds=2.0, max_bytes=8192)
    if exchange.ok:
        return ReadinessItem("ollama", True, True, f"Ollama ready at {base_url}")
    return ReadinessItem("ollama", False, True, f"Ollama check failed at {base_url}: {exchange.error or exchange.status_code}")
