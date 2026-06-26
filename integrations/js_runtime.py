from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def inspect_js_runtime(node_binary: str, espree_entry: str, beautifier_entry: str) -> tuple[bool, str]:
    resolved = shutil.which(node_binary) or node_binary
    if not shutil.which(node_binary) and not Path(resolved).exists():
        return False, f"node binary not found: {node_binary}"
    missing: list[str] = []
    root = Path(__file__).resolve().parents[3]
    node_modules = root / "node_modules"
    if not (node_modules / "espree").exists() and espree_entry == "espree":
        missing.append("espree")
    if not (node_modules / "js-beautify").exists() and beautifier_entry == "js-beautify":
        missing.append("js-beautify")
    if missing:
        return False, f"missing node modules: {', '.join(missing)}"
    return True, f"node runtime ready: {resolved}"


def run_js_helper(node_binary: str, helper_path: str | Path, payload: dict[str, object], *, timeout_seconds: float = 20.0) -> dict[str, object]:
    resolved = shutil.which(node_binary) or node_binary
    completed = subprocess.run(
        [resolved, str(helper_path)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or "node helper failed").strip())
    return json.loads(completed.stdout or "{}")
