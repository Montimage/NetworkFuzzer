"""Job management endpoints — list, get, cancel."""

from typing import List, Optional

from fastapi import APIRouter, HTTPException, Request

from fuzzer.api.models import JobResponse, RunResultResponse

router = APIRouter()


def _job_to_response(job) -> JobResponse:
    result = None
    if job.result is not None:
        result = RunResultResponse(
            success=job.result.success,
            exit_code=job.result.exit_code,
            stdout="\n".join(job.result.stdout.splitlines()[-50:]),
            stderr="\n".join(job.result.stderr.splitlines()[-20:]),
            output_dir=job.result.output_dir,
            duration_seconds=job.result.duration_seconds,
        )
    return JobResponse(
        id=job.id,
        type=job.type,
        status=job.status,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        params=job.params,
        result=result,
        error=job.error,
    )


@router.get("", response_model=List[JobResponse])
async def list_jobs(request: Request, status: Optional[str] = None):
    """List all jobs, optionally filtered by status."""
    jobs = request.app.state.jobs.list_jobs(status=status)
    return [_job_to_response(j) for j in jobs]


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(job_id: str, request: Request):
    """Get a single job by ID with full result."""
    job = request.app.state.jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
    return _job_to_response(job)


@router.delete("/{job_id}", response_model=JobResponse)
async def cancel_job(job_id: str, request: Request):
    """Cancel a pending or running job (best-effort)."""
    job = request.app.state.jobs.cancel(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
    return _job_to_response(job)
