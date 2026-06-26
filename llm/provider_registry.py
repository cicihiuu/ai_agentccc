from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ProviderSpec:
    name: str
    base_url: str
    api_key_env: str
    default_model: str
    openai_compatible: bool = False
    wire_api: str = "chat_completions"
    api_key_env_aliases: tuple[str, ...] = ()


PROVIDER_SPECS: dict[str, ProviderSpec] = {
    "ollama": ProviderSpec(
        name="ollama",
        base_url="http://127.0.0.1:11434",
        api_key_env="",
        default_model="qwen2.5-coder",
        openai_compatible=False,
    ),
    "hunyuan": ProviderSpec(
        name="hunyuan",
        base_url="https://tokenhub.tencentmaas.com/v1",
        api_key_env="TOKENHUB_API_KEY",
        default_model="hy3-preview",
        openai_compatible=True,
        wire_api="chat_completions",
    ),
    "deepseek": ProviderSpec(
        name="deepseek",
        base_url="https://api.deepseek.com",
        api_key_env="DEEPSEEK_API_KEY",
        default_model="deepseek-v4-flash",
        openai_compatible=True,
        wire_api="chat_completions",
    ),
}


def get_provider_spec(name: str) -> ProviderSpec:
    normalized = (name or "ollama").strip().lower()
    try:
        return PROVIDER_SPECS[normalized]
    except KeyError as exc:
        raise ValueError(f"unsupported provider: {name}") from exc


def provider_api_key_envs(spec: ProviderSpec, preferred_env: str = "") -> list[str]:
    candidates: list[str] = []
    for item in (preferred_env, spec.api_key_env, *spec.api_key_env_aliases):
        value = str(item or "").strip()
        if value and value not in candidates:
            candidates.append(value)
    return candidates
