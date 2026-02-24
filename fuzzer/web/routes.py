"""Page routes, htmx partials, agent chat endpoint, and WebSocket for the web UI."""

from __future__ import annotations

import asyncio
import functools
import json
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

logger = logging.getLogger(__name__)

_HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_HERE / "templates"))

router = APIRouter()


# ---------------------------------------------------------------------------
# Page routes (full HTML pages)
# ---------------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    jobs = request.app.state.jobs
    all_jobs = jobs.list_jobs()
    running = [j for j in all_jobs if j.status == "running"]
    completed = [j for j in all_jobs if j.status == "completed"]
    failed = [j for j in all_jobs if j.status == "failed"]

    runner = jobs.runner
    protocols = runner.list_protocols()

    return templates.TemplateResponse("index.html", {
        "request": request,
        "total_jobs": len(all_jobs),
        "running_jobs": len(running),
        "completed_jobs": len(completed),
        "failed_jobs": len(failed),
        "protocol_count": len(protocols),
    })


@router.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    return templates.TemplateResponse("chat.html", {"request": request})


@router.get("/jobs", response_class=HTMLResponse)
async def jobs_page(request: Request):
    return templates.TemplateResponse("jobs.html", {"request": request})


@router.get("/jobs/{job_id}", response_class=HTMLResponse)
async def job_detail_page(job_id: str, request: Request):
    job = request.app.state.jobs.get(job_id)
    if job is None:
        return HTMLResponse("<h1>Job not found</h1>", status_code=404)
    return templates.TemplateResponse("job_detail.html", {
        "request": request,
        "job": job,
    })


@router.get("/capabilities", response_class=HTMLResponse)
async def capabilities_page(request: Request):
    return templates.TemplateResponse("capabilities.html", {"request": request})


# ---------------------------------------------------------------------------
# htmx partials (HTML fragments)
# ---------------------------------------------------------------------------

@router.get("/partials/health", response_class=HTMLResponse)
async def health_partial(request: Request):
    return templates.TemplateResponse("partials/_health_badge.html", {
        "request": request,
        "status": "ok",
    })


@router.get("/partials/jobs", response_class=HTMLResponse)
async def jobs_partial(request: Request, status: Optional[str] = None):
    jobs = request.app.state.jobs.list_jobs(status=status)
    return templates.TemplateResponse("partials/_job_list.html", {
        "request": request,
        "jobs": jobs,
    })


@router.get("/partials/jobs/{job_id}", response_class=HTMLResponse)
async def job_detail_partial(job_id: str, request: Request):
    job = request.app.state.jobs.get(job_id)
    if job is None:
        return HTMLResponse("<p>Job not found.</p>", status_code=404)
    return templates.TemplateResponse("partials/_job_detail_card.html", {
        "request": request,
        "job": job,
    })


@router.get("/partials/capabilities/{category}", response_class=HTMLResponse)
async def capabilities_partial(category: str, request: Request):
    runner = request.app.state.jobs.runner
    items: list[str] = []
    if category == "protocols":
        items = runner.list_protocols()
    elif category == "attack_profiles":
        items = runner.list_attack_profiles()
    elif category == "fuzz_modes":
        items = runner.list_fuzz_modes()

    return templates.TemplateResponse("partials/_capabilities_list.html", {
        "request": request,
        "category": category,
        "items": items,
    })


# ---------------------------------------------------------------------------
# Agent chat endpoint
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    message: str
    session_id: str


@router.post("/agent/chat")
async def agent_chat(body: ChatRequest, request: Request):
    """Run the LangGraph agent with a user message."""
    session_mgr = request.app.state.agent_sessions
    session = session_mgr.get_or_create(body.session_id)

    try:
        loop = asyncio.get_event_loop()
        messages = await loop.run_in_executor(
            None, functools.partial(session.run, body.message)
        )
        return {"messages": messages}
    except RuntimeError as e:
        return {"messages": [{"role": "assistant", "content": str(e)}]}
    except Exception as e:
        logger.exception("Agent chat error")
        return {"messages": [{"role": "assistant", "content": f"Error: {e}"}]}


# ---------------------------------------------------------------------------
# WebSocket — real-time job status push
# ---------------------------------------------------------------------------

@router.websocket("/ws/jobs")
async def ws_jobs(websocket: WebSocket):
    """Push job status changes to connected clients every 2 seconds."""
    await websocket.accept()
    last_snapshot: dict[str, str] = {}

    try:
        while True:
            jobs = websocket.app.state.jobs.list_jobs()
            snapshot = {j.id: j.status for j in jobs}

            if snapshot != last_snapshot:
                changes = []
                for j in jobs:
                    changes.append({
                        "id": j.id,
                        "type": j.type,
                        "status": j.status,
                        "created_at": j.created_at.isoformat(),
                    })
                await websocket.send_text(json.dumps({"jobs": changes}))
                last_snapshot = snapshot

            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.debug("WebSocket connection closed")
