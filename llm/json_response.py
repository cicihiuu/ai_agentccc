from __future__ import annotations

import json
import re

from .base import LLMError, LLMProvider
from .prompts import build_json_repair_prompt


def extract_json_object(text: str) -> dict:
    candidates = _candidate_payloads(text)
    last_error: Exception | None = None
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError as exc:
            last_error = exc
            repaired = _repair_json(candidate)
            if repaired == candidate:
                continue
            try:
                payload = json.loads(repaired)
            except json.JSONDecodeError as repaired_exc:
                last_error = repaired_exc
                continue
        if not isinstance(payload, dict):
            raise LLMError("LLM 返回结果必须是 JSON 对象")
        return payload

    if last_error is None:
        raise LLMError("LLM 响应中未找到 JSON 对象")
    raise LLMError(f"LLM 返回的 JSON 无法解析: {last_error}") from last_error


def complete_json_object(
    provider: LLMProvider,
    prompt: str,
    *,
    model_id: str,
    max_tokens: int,
    schema_hint: str,
) -> dict:
    response = provider.complete(prompt, model_id=model_id, max_tokens=max_tokens)
    try:
        return extract_json_object(response.text)
    except LLMError:
        repaired = provider.complete(
            build_json_repair_prompt(response.text, schema_hint),
            model_id=model_id,
            max_tokens=min(max_tokens, 900),
        )
        return extract_json_object(repaired.text)


def _candidate_payloads(text: str) -> list[str]:
    stripped = (text or "").strip()
    if not stripped:
        return []

    lines = stripped.splitlines()
    if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    stripped = "\n".join(lines).strip()

    candidates: list[str] = []
    if stripped.startswith("{") and stripped.endswith("}"):
        candidates.append(stripped)

    balanced = _extract_balanced_json_blocks(stripped)
    candidates.extend(item for item in balanced if item not in candidates)
    return candidates


def _extract_balanced_json_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    depth = 0
    start = -1
    in_string = False
    escape_next = False
    for index, char in enumerate(text):
        if in_string:
            if escape_next:
                escape_next = False
            elif char == "\\":
                escape_next = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            if depth == 0:
                continue
            depth -= 1
            if depth == 0 and start != -1:
                blocks.append(text[start : index + 1].strip())
                start = -1
    return blocks


def _repair_json(text: str) -> str:
    repaired = text.strip()
    repaired = repaired.replace("“", '"').replace("”", '"').replace("’", "'").replace("‘", "'")
    repaired = repaired.replace("：", ":").replace("，", ",")
    repaired = re.sub(r",(\s*[}\]])", r"\1", repaired)
    repaired = re.sub(r"(?m)^\s*//.*$", "", repaired)
    return repaired.strip()
