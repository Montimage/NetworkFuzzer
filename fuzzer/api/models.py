"""Pydantic response schemas for the NetworkFuzzer API."""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel

# Re-export request schemas from Phase 1 for convenience
from fuzzer.agent.schemas import (  # noqa: F401
    CompileRuleInput,
    GANGenerateInput,
    ListCapabilitiesInput,
    ReplayInput,
    RLFuzzInput,
)


class RunResultResponse(BaseModel):
    """Serialized result of a CLI invocation."""

    success: bool
    exit_code: int
    stdout: str
    stderr: str
    output_dir: Optional[str] = None
    duration_seconds: float


class JobResponse(BaseModel):
    """Full job status and result."""

    id: str
    type: str
    status: str
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    params: Dict
    result: Optional[RunResultResponse] = None
    error: Optional[str] = None


class JobSubmittedResponse(BaseModel):
    """Returned immediately when a job is submitted."""

    job_id: str
    status: str
    message: str


class CapabilitiesResponse(BaseModel):
    """List of items for a capability category."""

    category: str
    items: List[str]


class SyncResultResponse(BaseModel):
    """Result for synchronous endpoints (compile, replay)."""

    success: bool
    exit_code: int
    stdout: str
    stderr: str
    output_dir: Optional[str] = None
    duration_seconds: float
