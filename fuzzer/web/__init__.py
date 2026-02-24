"""NetworkFuzzer Web UI — htmx + Alpine.js frontend for the FastAPI backend."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from fuzzer.web.routes import router as web_router

_HERE = Path(__file__).resolve().parent


def mount_web_ui(app: FastAPI) -> None:
    """Wire the web UI into an existing FastAPI application.

    - Mounts static files at /ui/static
    - Includes all page and partial routes under /ui
    """
    app.mount(
        "/ui/static",
        StaticFiles(directory=str(_HERE / "static")),
        name="web_static",
    )
    app.include_router(web_router, prefix="/ui", tags=["Web UI"])
