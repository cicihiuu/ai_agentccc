from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class DockerSandboxResult:
    command: list[str]
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    parsed: dict[str, object] | None = None
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def run_poc_in_docker(
    *,
    docker_binary: str,
    image: str,
    script_path: str | Path,
    artifacts_dir: str | Path,
    timeout_seconds: float = 20.0,
    network_mode: str = "bridge",
    cpu_limit: str = "1.0",
    mem_limit: str = "512m",
    env_names: list[str] | None = None,
) -> DockerSandboxResult:
    resolved = shutil.which(docker_binary) or docker_binary
    script = Path(script_path).resolve()
    artifacts = Path(artifacts_dir).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    command = [
        resolved,
        "run",
        "--rm",
        "--network",
        network_mode,
        "--cpus",
        str(cpu_limit),
        "--memory",
        str(mem_limit),
        "--read-only",
    ]
    for name in env_names or []:
        if name and all(ch.isalnum() or ch == "_" for ch in name):
            command.extend(["-e", name])
    command.extend([
        "-v",
        f"{script}:/workspace/poc.py:ro",
        "-v",
        f"{artifacts}:/workspace/artifacts:rw",
        image,
        "python",
        "/workspace/poc.py",
    ])
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds, check=False)
        parsed = None
        try:
            parsed = json.loads((completed.stdout or "").strip() or "{}")
        except json.JSONDecodeError:
            parsed = {"raw_stdout": (completed.stdout or "")[:4000]}
        return DockerSandboxResult(
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            parsed=parsed,
        )
    except subprocess.TimeoutExpired as exc:
        return DockerSandboxResult(command=command, stdout=exc.stdout or "", stderr=exc.stderr or "", timed_out=True)
