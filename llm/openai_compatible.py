from __future__ import annotations

import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .base import LLMError, LLMResponse
from .provider_registry import ProviderSpec, provider_api_key_envs


class OpenAICompatibleProvider:
    def __init__(
        self,
        spec: ProviderSpec,
        *,
        base_url: str | None = None,
        api_key_env: str | None = None,
        timeout_seconds: float = 15.0,
        max_retries: int = 2,
        headers: dict[str, str] | None = None,
    ):
        self.spec = spec
        self.base_url = (base_url or spec.base_url).rstrip("/")
        self.api_key_env = (api_key_env or spec.api_key_env).strip()
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.headers = dict(headers or {})

    def complete(self, prompt: str, *, model_id: str = "", max_tokens: int = 1024) -> LLMResponse:
        resolved_env, api_key = self._resolve_api_key()
        if provider_api_key_envs(self.spec, self.api_key_env) and not api_key:
            raise LLMError(f"missing api key env: {resolved_env or self.api_key_env}")

        model = model_id or self.spec.default_model
        payload = self._build_payload(model=model, prompt=prompt, max_tokens=max_tokens)
        url = self._request_url()
        headers = {"Content-Type": "application/json", **self.headers}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            request = Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
            try:
                with urlopen(request, timeout=self.timeout_seconds) as response:
                    data = json.loads(response.read().decode("utf-8"))
                text = _extract_message_text(data)
                if not text:
                    raise LLMError("model returned empty content")
                return LLMResponse(text=text, model_id=model, provider=self.spec.name)
            except HTTPError as exc:
                last_exc = exc
                if exc.code not in {429, 500, 502, 503, 504} or attempt >= self.max_retries:
                    raise LLMError(f"{self.spec.name} request failed: HTTP {exc.code}") from exc
            except (URLError, OSError, TimeoutError, json.JSONDecodeError, LLMError) as exc:
                last_exc = exc
                if attempt >= self.max_retries:
                    if isinstance(exc, LLMError):
                        raise
                    raise LLMError(f"{self.spec.name} request failed: {exc}") from exc
            time.sleep(0.8 * (attempt + 1))
        raise LLMError(f"{self.spec.name} request failed: {last_exc}")

    def _resolve_api_key(self) -> tuple[str, str]:
        for env_name in provider_api_key_envs(self.spec, self.api_key_env):
            value = os.environ.get(env_name, "").strip()
            if value:
                return env_name, value
        return self.api_key_env, ""

    def _build_payload(self, *, model: str, prompt: str, max_tokens: int) -> dict[str, object]:
        if self.spec.wire_api == "responses":
            return {
                "model": model,
                "input": prompt,
                "max_output_tokens": max_tokens,
            }
        return {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": max_tokens,
        }

    def _request_url(self) -> str:
        if self.spec.wire_api == "responses":
            if self.base_url.endswith("/v1"):
                return f"{self.base_url}/responses"
            return f"{self.base_url}/v1/responses"
        if self.spec.name == "deepseek" and not self.base_url.endswith("/v1"):
            return f"{self.base_url}/v1/chat/completions"
        return f"{self.base_url}/chat/completions"


def _extract_message_text(data: dict) -> str:
    output_text = data.get("output_text", "")
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    output = data.get("output", [])
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content", [])
            if not isinstance(content, list):
                continue
            for chunk in content:
                if not isinstance(chunk, dict):
                    continue
                text = chunk.get("text", "")
                if isinstance(text, str) and text.strip():
                    return text.strip()

    choices = data.get("choices", [])
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0] if isinstance(choices[0], dict) else {}
    message = first.get("message", {})
    if isinstance(message, dict):
        content = message.get("content", "")
        if isinstance(content, str):
            return content.strip()
    content = first.get("text", "")
    return str(content).strip()
