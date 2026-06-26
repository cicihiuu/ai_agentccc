from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass(slots=True)
class SQLMapExecutionResult:
    command: list[str]
    executable: str
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    parsed: dict[str, object] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def inspect_sqlmap(binary: str) -> tuple[bool, str]:
    resolved = shutil.which(binary) or binary
    if not shutil.which(binary) and not resolved:
        return False, f"sqlmap binary not found: {binary}"
    try:
        completed = subprocess.run(
            [resolved, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except OSError as exc:
        return False, f"sqlmap check failed: {exc}"
    output = (completed.stdout or completed.stderr or "").strip()
    return completed.returncode == 0, output or "sqlmap detected"


def run_sqlmap_command(command: list[str], *, binary: str = "sqlmap", timeout_seconds: float = 45.0) -> SQLMapExecutionResult:
    resolved = shutil.which(binary) or binary
    built = [resolved, *command]
    try:
        completed = subprocess.run(
            built,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        parsed = _parse_sqlmap_output(completed.stdout, completed.stderr)
        return SQLMapExecutionResult(
            command=built,
            executable=resolved,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            parsed=parsed,
        )
    except subprocess.TimeoutExpired as exc:
        return SQLMapExecutionResult(
            command=built,
            executable=resolved,
            timed_out=True,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            parsed={"timed_out": True},
        )
    except OSError as exc:
        return SQLMapExecutionResult(command=built, executable=resolved, stderr=str(exc), parsed={"error": str(exc)})


def _parse_sqlmap_output(stdout: str, stderr: str) -> dict[str, object]:
    text = "\n".join(part for part in [stdout, stderr] if part)
    lowered = text.lower()
    return {
        "injection_confirmed": "is vulnerable" in lowered or "parameter" in lowered and "injectable" in lowered,
        "dbms": _extract_after_marker(text, "back-end DBMS:"),
        "payloads": [line.strip() for line in text.splitlines() if "payload:" in line.lower()][:8],
        "summary": text[:2400],
    }


def _extract_after_marker(text: str, marker: str) -> str:
    for line in text.splitlines():
        if marker.lower() in line.lower():
            return line.split(":", 1)[-1].strip()
    return ""
