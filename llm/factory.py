from __future__ import annotations

import os
from typing import Any

from .base import LLMProvider
from .ollama import OllamaProvider
from .openai_compatible import OpenAICompatibleProvider
from .provider_registry import get_provider_spec, provider_api_key_envs


def create_provider(provider_name: str, *, base_url: str = "") -> LLMProvider:
    spec = get_provider_spec(provider_name)
    if spec.name == "ollama":
        return OllamaProvider(base_url or spec.base_url)
    if spec.openai_compatible:
        return OpenAICompatibleProvider(spec, base_url=base_url or spec.base_url)
    raise ValueError(f"unsupported provider: {provider_name}")


def create_provider_from_config(config: Any | None, *, agent_mode: str = "rule_based") -> LLMProvider | None:
    if config is None:
        return None
    if agent_mode == "rule_based":
        return None
    enabled = getattr(config, "enabled", None)
    if enabled is None:
        enabled = getattr(config, "llm_enabled", False)
    if not bool(enabled):
        return None

    provider_name = str(getattr(config, "provider_name", "")).strip()
    spec = get_provider_spec(provider_name)
    base_url = str(getattr(config, "base_url", "")).strip() or spec.base_url
    timeout_seconds = float(getattr(config, "timeout_seconds", 15.0) or 15.0)
    max_retries = int(getattr(config, "max_retries", 2) or 0)
    headers = dict(getattr(config, "headers", {}) or {})
    api_key_env = str(getattr(config, "api_key_env", "")).strip() or spec.api_key_env

    if spec.name == "ollama":
        return OllamaProvider(base_url, timeout_seconds=timeout_seconds)
    if spec.openai_compatible:
        env_candidates = provider_api_key_envs(spec, api_key_env)
        if env_candidates and not any(os.environ.get(name, "").strip() for name in env_candidates):
            return None
        return OpenAICompatibleProvider(
            spec,
            base_url=base_url,
            api_key_env=api_key_env,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            headers=headers,
        )
    raise ValueError(f"unsupported provider: {provider_name}")
