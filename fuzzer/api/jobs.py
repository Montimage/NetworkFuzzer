"""In-memory async job manager using ThreadPoolExecutor."""

from __future__ import annotations

import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from fuzzer.agent.runner import FuzzerRunner, RunResult


@dataclass
class Job:
    """Represents a background fuzzing job."""

    id: str
    type: str
    status: str  # pending | running | completed | failed | cancelled
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    params: dict = field(default_factory=dict)
    result: Optional[RunResult] = None
    error: Optional[str] = None
    _future: Optional[Future] = field(default=None, repr=False)


class JobManager:
    """Manages background fuzzing jobs via a thread pool."""

    def __init__(self, runner: FuzzerRunner, max_workers: int = 4):
        self._jobs: dict[str, Job] = {}
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._runner = runner

    @property
    def runner(self) -> FuzzerRunner:
        return self._runner

    def submit(self, job_type: str, func: Callable[..., RunResult], params: dict) -> Job:
        """Submit a new background job. Returns the Job immediately."""
        job = Job(
            id=uuid.uuid4().hex[:12],
            type=job_type,
            status="pending",
            created_at=datetime.now(timezone.utc),
            params=params,
        )
        self._jobs[job.id] = job

        def _execute() -> None:
            job.status = "running"
            job.started_at = datetime.now(timezone.utc)
            try:
                job.result = func()
                job.status = "completed"
            except Exception as e:
                job.status = "failed"
                job.error = str(e)
            finally:
                job.completed_at = datetime.now(timezone.utc)

        future = self._executor.submit(_execute)
        job._future = future
        return job

    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def list_jobs(self, status: Optional[str] = None) -> list[Job]:
        jobs = list(self._jobs.values())
        if status:
            jobs = [j for j in jobs if j.status == status]
        return sorted(jobs, key=lambda j: j.created_at, reverse=True)

    def cancel(self, job_id: str) -> Optional[Job]:
        """Best-effort cancellation. Returns the job or None if not found."""
        job = self._jobs.get(job_id)
        if job is None:
            return None
        if job._future and job._future.cancel():
            job.status = "cancelled"
            job.completed_at = datetime.now(timezone.utc)
        elif job.status == "pending":
            job.status = "cancelled"
            job.completed_at = datetime.now(timezone.utc)
        return job

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False)
