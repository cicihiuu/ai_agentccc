from __future__ import annotations

import json
import sys
from pathlib import Path

from ai_security_agent.integrations.http import fetch_text
from ai_security_agent.integrations.js_runtime import run_js_helper


PROJECT_ROOT = Path(__file__).resolve().parents[3]
NODE_HELPER = PROJECT_ROOT / "scripts" / "js_audit_node_helper.js"


TOOLS = [
    {"name": "fetch_url", "description": "Fetch a URL and return text plus metadata."},
    {"name": "extract_links", "description": "Fetch a URL and extract href/src/action values."},
    {"name": "beautify_js", "description": "Beautify JS using the local node helper."},
    {"name": "parse_js_ast", "description": "Parse JS and return AST summaries using the local node helper."},
]


def main() -> int:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        request = json.loads(line)
        response = handle_request(request)
        sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    return 0


def handle_request(request: dict[str, object]) -> dict[str, object]:
    request_id = request.get("id")
    method = str(request.get("method", ""))
    params = dict(request.get("params", {})) if isinstance(request.get("params", {}), dict) else {}
    try:
        if method == "initialize":
            return _ok(request_id, {"name": "web-tools", "version": "1.0"})
        if method == "tools/list":
            return _ok(request_id, {"tools": TOOLS})
        if method == "tools/call":
            tool_name = str(params.get("name", ""))
            arguments = dict(params.get("arguments", {})) if isinstance(params.get("arguments", {}), dict) else {}
            return _ok(request_id, _call_tool(tool_name, arguments))
        return _error(request_id, f"unsupported method: {method}")
    except Exception as exc:
        return _error(request_id, str(exc))


def _call_tool(name: str, arguments: dict[str, object]) -> dict[str, object]:
    if name == "fetch_url":
        url = str(arguments.get("url", "")).strip()
        result = fetch_text(url, timeout_seconds=float(arguments.get("timeout_seconds", 8.0) or 8.0))
        return {"url": result.url, "status": result.status_code, "text": result.text[:16000], "evidence": result.to_evidence(), "error": result.error}
    if name == "extract_links":
        import re

        url = str(arguments.get("url", "")).strip()
        result = fetch_text(url)
        matches = re.findall(r"""(?:href|src|action)\s*=\s*['"]([^'"]+)['"]""", result.text, re.IGNORECASE)
        return {"url": result.url, "status": result.status_code, "links": matches[:80], "evidence": result.to_evidence(), "error": result.error}
    if name in {"beautify_js", "parse_js_ast"}:
        source = str(arguments.get("source", ""))
        payload = {"scripts": [{"location": str(arguments.get("location", "inline")), "source_b64": _b64(source)}]}
        data = run_js_helper("node", NODE_HELPER, payload)
        script_item = next(iter(data.get("scripts", [])), {}) if isinstance(data.get("scripts", []), list) else {}
        return {"parser": data.get("parser", ""), "beautifier": data.get("beautifier", ""), "script": script_item}
    raise RuntimeError(f"unsupported tool: {name}")


def _b64(value: str) -> str:
    import base64

    return base64.b64encode(value.encode("utf-8", errors="replace")).decode("ascii")


def _ok(request_id: object, result: dict[str, object]) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: object, message: str) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"message": message}}


if __name__ == "__main__":
    raise SystemExit(main())
