"""FastAPI application factory for NetworkFuzzer."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI

# Load .env from project root (auto-detected or explicit)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

from fuzzer.agent.runner import FuzzerRunner
from fuzzer.api.jobs import JobManager
from fuzzer.api.routers.capabilities import router as capabilities_router
from fuzzer.api.routers.fuzz import router as fuzz_router
from fuzzer.api.routers.jobs import router as jobs_router
from fuzzer.api.routers.replay import router as replay_router
from fuzzer.web import mount_web_ui
from fuzzer.web.agent_session import AgentSessionManager


def create_app(project_root: Optional[str] = None) -> FastAPI:
    """Create and configure the FastAPI application."""

    runner = FuzzerRunner(project_root=project_root)
    job_manager = JobManager(runner=runner)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        job_manager.shutdown()

    app = FastAPI(
        title="NetworkFuzzer API",
        version="0.1.0",
        description="REST API for NetworkFuzzer — network traffic fuzzing and generation",
        lifespan=lifespan,
    )

    app.state.runner = runner
    app.state.jobs = job_manager
    app.state.agent_sessions = AgentSessionManager(project_root=project_root)

    app.include_router(fuzz_router, prefix="/fuzz", tags=["Fuzzing"])
    app.include_router(replay_router, prefix="", tags=["Replay"])
    app.include_router(capabilities_router, prefix="", tags=["Capabilities"])
    app.include_router(jobs_router, prefix="/jobs", tags=["Jobs"])

    @app.get("/health", tags=["Health"])
    async def health():
        return {"status": "ok"}

    mount_web_ui(app)

    return app


# Convenience for: uvicorn fuzzer.api.app:app --reload
app = create_app()
