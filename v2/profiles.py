from __future__ import annotations

from pathlib import Path

import yaml

from .models import AgentProfile


def load_profile(path: Path) -> AgentProfile:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return AgentProfile(
        name=str(payload.get("name", "")).strip(),
        role=str(payload.get("role", "")).strip(),
        description=str(payload.get("description", "")).strip(),
        goal=str(payload.get("goal", "")).strip(),
        skill_names=[str(item).strip() for item in payload.get("skill_names", []) if str(item).strip()],
        default_tools=[str(item).strip() for item in payload.get("default_tools", []) if str(item).strip()],
        llm_enabled=bool(payload.get("llm_enabled", True)),
        provider_name=str(payload.get("provider_name", "deepseek")).strip() or "deepseek",
        model_id=str(payload.get("model_id", "")).strip(),
        base_url=str(payload.get("base_url", "")).strip(),
        api_key_env=str(payload.get("api_key_env", "")).strip(),
        max_iterations=int(payload.get("max_iterations", 16) or 16),
        max_step_iterations=int(payload.get("max_step_iterations", 4) or 4),
        max_parallel_steps=int(payload.get("max_parallel_steps", 4) or 4),
        max_parallel_subagents=int(payload.get("max_parallel_subagents", 2) or 2),
        state_bootstrap=dict(payload.get("state_bootstrap", {})) if isinstance(payload.get("state_bootstrap", {}), dict) else {},
    )
