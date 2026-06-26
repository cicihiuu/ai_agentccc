from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class LLMError(RuntimeError):
    """Raised when an LLM provider cannot return a usable response."""


@dataclass(slots=True)
class LLMResponse:
    text: str
    model_id: str
    provider: str


class LLMProvider(Protocol):
    def complete(self, prompt: str, *, model_id: str = "", max_tokens: int = 1024) -> LLMResponse:
        """Return a text completion for a planning/report prompt."""


class NullLLMProvider:
    def complete(self, prompt: str, *, model_id: str = "", max_tokens: int = 1024) -> LLMResponse:
        raise LLMError("LLM provider is not configured")
