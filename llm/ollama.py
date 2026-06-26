from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .base import LLMError, LLMResponse


class OllamaProvider:
    def __init__(self, base_url: str | None = None, *, timeout_seconds: float = 8.0):
        self.base_url = (base_url or os.environ.get("OLLAMA_BASE_URL") or "http://127.0.0.1:11434").rstrip("/")
        self.timeout_seconds = timeout_seconds

    def complete(self, prompt: str, *, model_id: str = "", max_tokens: int = 1024) -> LLMResponse:
        model = model_id or os.environ.get("OLLAMA_MODEL") or "qwen2.5-coder"
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": 0.2,
            },
        }
        request = Request(
            f"{self.base_url}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise LLMError(f"Ollama 请求失败：{exc}") from exc

        text = str(data.get("response", "")).strip()
        if not text:
            raise LLMError("Ollama 返回了空内容")
        return LLMResponse(text=text, model_id=model, provider="ollama")
