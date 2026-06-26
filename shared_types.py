from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class LLMSettings:
    enabled: bool = False
    provider_name: str = "deepseek"
    model_id: str = ""
    base_url: str = ""
    api_key_env: str = ""
    timeout_seconds: float = 15.0
    max_retries: int = 2
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any] | None,
        *,
        legacy_provider_name: str = "",
        legacy_model_id: str = "",
        legacy_base_url: str = "",
        legacy_api_key_env: str = "",
    ) -> "LLMSettings":
        payload = dict(data or {})
        provider_name = str(payload.get("provider_name", "")).strip() or legacy_provider_name or "deepseek"
        model_id = str(payload.get("model_id", "")).strip() or legacy_model_id
        base_url = str(payload.get("base_url", "")).strip() or legacy_base_url
        api_key_env = str(payload.get("api_key_env", "")).strip() or legacy_api_key_env
        enabled_value = payload.get("enabled")
        enabled = bool(enabled_value) if enabled_value is not None else bool(payload) or any(
            [legacy_provider_name.strip(), legacy_model_id.strip(), legacy_base_url.strip(), legacy_api_key_env.strip()]
        )
        return cls(
            enabled=enabled,
            provider_name=provider_name,
            model_id=model_id,
            base_url=base_url,
            api_key_env=api_key_env,
            timeout_seconds=float(payload.get("timeout_seconds", 15.0) or 15.0),
            max_retries=int(payload.get("max_retries", 2) or 0),
            headers=_string_mapping(payload.get("headers", {})),
        )

    def validate(self) -> None:
        if not self.provider_name:
            raise ValueError("llm.provider_name is required")
        if self.timeout_seconds <= 0:
            raise ValueError("llm.timeout_seconds must be positive")
        if self.max_retries < 0:
            raise ValueError("llm.max_retries must be non-negative")


@dataclass(slots=True)
class MCPServerSpec:
    name: str
    transport: str = "stdio"
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MCPServerSpec":
        return cls(
            name=str(data.get("name", "")).strip(),
            transport=str(data.get("transport", "stdio")).strip() or "stdio",
            command=str(data.get("command", "")).strip(),
            args=_string_list(data.get("args", [])),
            env=_string_mapping(data.get("env", {})),
            enabled=bool(data.get("enabled", True)),
        )

    def validate(self) -> None:
        if not self.name:
            raise ValueError("mcp.servers[].name is required")
        if self.transport not in {"stdio"}:
            raise ValueError(f"invalid mcp transport: {self.transport}")
        if not self.command:
            raise ValueError("mcp.servers[].command is required")


def _string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(item).strip() for item in values if str(item).strip()]


def _string_mapping(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}
