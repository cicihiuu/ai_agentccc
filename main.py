from __future__ import annotations

import argparse

import uvicorn


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the AI Security Agent workbench server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--app-dir", default="src")
    args = parser.parse_args(argv)
    uvicorn.run("ai_security_agent.api.app:app", host=args.host, port=args.port, app_dir=args.app_dir)
    return 0
