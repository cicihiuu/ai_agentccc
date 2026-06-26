from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ai_security_agent.shared_types import MCPServerSpec


class MCPClientError(RuntimeError):
    pass


@dataclass(slots=True)
class MCPServerInventory:
    server: str
    tools: list[str]


class MCPClient:
    def __init__(self, server: MCPServerSpec):
        self.server = server
        self.process: subprocess.Popen[str] | None = None
        self._seq = 0

    def __enter__(self) -> "MCPClient":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def start(self) -> None:
        if self.process is not None:
            return
        command = [self.server.command, *self.server.args]
        project_root = Path(__file__).resolve().parents[3]
        env = os.environ.copy()
        pythonpath = env.get("PYTHONPATH", "")
        extra_path = str(project_root / "src")
        env["PYTHONPATH"] = extra_path if not pythonpath else extra_path + os.pathsep + pythonpath
        env.update(self.server.env)
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(project_root),
            env=env,
        )
        self.call("initialize", {"client": "ai_security_agent"})

    def close(self) -> None:
        if self.process is None:
            return
        try:
            if self.process.stdin:
                self.process.stdin.close()
        finally:
            try:
                if self.process.poll() is None:
                    self.process.terminate()
                    self.process.wait(timeout=3)
            except Exception:
                try:
                    self.process.kill()
                    self.process.wait(timeout=1)
                except Exception:
                    pass
            for stream_name in ("stdout", "stderr"):
                stream = getattr(self.process, stream_name, None)
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass
            self.process = None

    def list_tools(self) -> list[str]:
        response = self.call("tools/list", {})
        tools = response.get("tools", [])
        if not isinstance(tools, list):
            return []
        return [str(item.get("name", "")) for item in tools if isinstance(item, dict)]

    def call_tool(self, name: str, arguments: dict[str, object]) -> dict[str, object]:
        response = self.call("tools/call", {"name": name, "arguments": arguments})
        return dict(response)

    def call(self, method: str, params: dict[str, object]) -> dict[str, object]:
        if self.process is None or self.process.stdin is None or self.process.stdout is None:
            raise MCPClientError("MCP process not started")
        self._seq += 1
        payload = {"jsonrpc": "2.0", "id": self._seq, "method": method, "params": params}
        self.process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            stderr = ""
            if self.process.stderr:
                try:
                    stderr = self.process.stderr.read()
                except Exception:
                    stderr = ""
            raise MCPClientError(f"MCP server returned no data for {method}. {stderr.strip()}")
        response = json.loads(line)
        if "error" in response:
            raise MCPClientError(str(response["error"]))
        result = response.get("result", {})
        return dict(result) if isinstance(result, dict) else {}


def inspect_mcp_servers(servers: list[MCPServerSpec], required_tools: list[str]) -> tuple[bool, str]:
    if not servers:
        return False, "no MCP servers configured"
    inventories: list[MCPServerInventory] = []
    for server in servers:
        if not server.enabled:
            continue
        client: MCPClient | None = None
        try:
            client = MCPClient(server)
            client.start()
            inventories.append(MCPServerInventory(server=server.name, tools=client.list_tools()))
        except Exception as exc:
            return False, f"MCP server {server.name} failed: {exc}"
        finally:
            if client is not None:
                client.close()
    available = {tool for item in inventories for tool in item.tools}
    missing = [tool for tool in required_tools if tool not in available]
    if missing:
        return False, f"MCP tools missing: {', '.join(missing)}"
    summary = ", ".join(f"{item.server}=[{', '.join(item.tools)}]" for item in inventories) or "no enabled MCP servers"
    return True, summary
