"""Replay and compile endpoints — synchronous by default."""

from typing import Union

from fastapi import APIRouter, Query, Request

from fuzzer.api.models import (
    CompileRuleInput,
    JobSubmittedResponse,
    ReplayInput,
    SyncResultResponse,
)

router = APIRouter()


def _to_sync_response(result) -> SyncResultResponse:
    return SyncResultResponse(
        success=result.success,
        exit_code=result.exit_code,
        stdout="\n".join(result.stdout.splitlines()[-50:]),
        stderr="\n".join(result.stderr.splitlines()[-20:]),
        output_dir=result.output_dir,
        duration_seconds=result.duration_seconds,
    )


@router.post("/replay", response_model=Union[SyncResultResponse, JobSubmittedResponse])
async def replay(
    body: ReplayInput,
    request: Request,
    async_mode: bool = Query(False, alias="async"),
):
    """Replay PCAP traffic. Use ?async=true to run as a background job."""
    jobs = request.app.state.jobs

    if async_mode:
        def run():
            return jobs.runner.run_replay(
                pcap_file=body.pcap_file,
                config_file=body.config_file,
                interface=body.interface,
                extra_params=body.extra_params,
            )

        job = jobs.submit("replay", run, body.model_dump())
        return JobSubmittedResponse(
            job_id=job.id,
            status=job.status,
            message="Replay job submitted",
        )

    result = jobs.runner.run_replay(
        pcap_file=body.pcap_file,
        config_file=body.config_file,
        interface=body.interface,
        extra_params=body.extra_params,
    )
    return _to_sync_response(result)


@router.post("/compile", response_model=SyncResultResponse)
async def compile_rule(body: CompileRuleInput, request: Request):
    """Compile an XML rule to a .so plugin."""
    result = request.app.state.jobs.runner.run_compile(
        input_xml=body.input_xml,
        output_so=body.output_so,
    )
    return _to_sync_response(result)
