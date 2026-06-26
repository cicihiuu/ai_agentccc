from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import FileResponse, JSONResponse, Response
    from fastapi.staticfiles import StaticFiles
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("FastAPI 未安装，请先执行：pip install -r requirements.txt") from exc

from ai_security_agent.i18n import to_user_message
from ai_security_agent.service import AgentService


PROJECT_ROOT = Path(__file__).resolve().parents[3]
STATIC_DIR = Path(__file__).resolve().parent / "static"
NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}
FRONTEND_SIGNATURE = "parallel-main-agent-continue-v1"


class NoCacheStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope) -> Response:
        response = await super().get_response(path, scope)
        response.headers.update(NO_CACHE_HEADERS)
        return response


app = FastAPI(title="AI Security Agent Workbench", version="3.0.0")
agent_service = AgentService(project_root=PROJECT_ROOT)

app.mount("/static", NoCacheStaticFiles(directory=STATIC_DIR), name="static")
app.mount("/runs", NoCacheStaticFiles(directory=PROJECT_ROOT / "runs"), name="runs")


@app.get("/")
def index() -> FileResponse:
    headers = dict(NO_CACHE_HEADERS)
    headers["X-Workbench-Frontend-Signature"] = FRONTEND_SIGNATURE
    return FileResponse(STATIC_DIR / "index.html", headers=headers)


@app.get("/api/health")
def health() -> JSONResponse:
    return JSONResponse(
        {
            "ok": True,
            "service": "ai_security_agent_workbench",
            "frontend_signature": FRONTEND_SIGNATURE,
            "project_root": str(PROJECT_ROOT),
        },
        headers=NO_CACHE_HEADERS,
    )


@app.get("/api/profiles")
def profiles() -> list[dict[str, Any]]:
    return agent_service.list_profiles()


async def _create_scan(request: Request) -> dict[str, Any]:
    payload = await request.json()
    target = str(payload.get("target", "")).strip()
    if not target:
        raise HTTPException(status_code=400, detail="缺少目标地址。")
    try:
        return agent_service.create_scan(
            target,
            profile_name=str(payload.get("profile_name", "blackbox_web")).strip() or "blackbox_web",
            module_bundle=str(payload.get("module_bundle", "full")).strip() or "full",
            task_mode=str(payload.get("task_mode", "")).strip(),
            provider_name=str(payload.get("provider_name", "")).strip(),
            model_id=str(payload.get("model_id", "")).strip(),
            base_url=str(payload.get("base_url", "")).strip(),
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=to_user_message(str(exc))) from exc


@app.post("/api/scans")
async def create_scan(request: Request) -> dict[str, Any]:
    return await _create_scan(request)


def _get_scan(scan_id: str) -> dict[str, Any]:
    try:
        return agent_service.get_scan(scan_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="未找到对应扫描。") from exc


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> dict[str, Any]:
    return _get_scan(scan_id)


def _step_scan(scan_id: str) -> dict[str, Any]:
    try:
        return agent_service.step_scan(scan_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=to_user_message(str(exc))) from exc


@app.post("/api/scans/{scan_id}/step")
def step_scan(scan_id: str) -> dict[str, Any]:
    return _step_scan(scan_id)


def _continue_scan(scan_id: str) -> dict[str, Any]:
    try:
        return agent_service.continue_scan(scan_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=to_user_message(str(exc))) from exc


@app.post("/api/scans/{scan_id}/continue")
def continue_scan(scan_id: str) -> dict[str, Any]:
    return _continue_scan(scan_id)


async def _approve_manual_confirmation(scan_id: str, verification_id: str, request: Request) -> dict[str, Any]:
    payload = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    try:
        return agent_service.approve_manual_confirmation(
            scan_id,
            verification_id,
            note=str(payload.get("note", "")).strip(),
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=to_user_message(str(exc))) from exc


@app.post("/api/scans/{scan_id}/approve/{verification_id}")
async def approve_manual_confirmation(scan_id: str, verification_id: str, request: Request) -> dict[str, Any]:
    return await _approve_manual_confirmation(scan_id, verification_id, request)


async def _deny_manual_confirmation(scan_id: str, verification_id: str, request: Request) -> dict[str, Any]:
    payload = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    try:
        return agent_service.deny_manual_confirmation(
            scan_id,
            verification_id,
            note=str(payload.get("note", "")).strip(),
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=to_user_message(str(exc))) from exc


@app.post("/api/scans/{scan_id}/deny/{verification_id}")
async def deny_manual_confirmation(scan_id: str, verification_id: str, request: Request) -> dict[str, Any]:
    return await _deny_manual_confirmation(scan_id, verification_id, request)


def _write_report(scan_id: str) -> dict[str, Any]:
    try:
        return agent_service.generate_report(scan_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=to_user_message(str(exc))) from exc


@app.post("/api/scans/{scan_id}/report")
def write_report(scan_id: str) -> dict[str, Any]:
    return _write_report(scan_id)
