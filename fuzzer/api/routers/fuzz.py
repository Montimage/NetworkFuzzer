"""Fuzzing endpoints — all async (job-based) since they're long-running."""

from fastapi import APIRouter, Request

from fuzzer.api.models import GANGenerateInput, JobSubmittedResponse, RLFuzzInput

router = APIRouter()


@router.post("/rl", response_model=JobSubmittedResponse)
async def fuzz_rl(body: RLFuzzInput, request: Request):
    """Submit an RL-guided protocol fuzzing job."""
    jobs = request.app.state.jobs

    def run():
        return jobs.runner.run_rl_fuzz(
            protocol=body.protocol,
            target_host=body.target_host,
            target_port=body.target_port,
            fuzz_mode=body.fuzz_mode,
            timesteps=body.timesteps,
            algorithm=body.algorithm,
            called_ae=body.called_ae,
            calling_ae=body.calling_ae,
            test=body.test,
            n_test=body.n_test,
            exploration_rate=body.exploration_rate,
            output_dir=body.output_dir,
        )

    job = jobs.submit("rl_fuzz", run, body.model_dump())
    return JobSubmittedResponse(
        job_id=job.id,
        status=job.status,
        message=f"RL fuzzing job submitted ({body.protocol}, {body.fuzz_mode}, {body.timesteps} steps)",
    )


@router.post("/gan", response_model=JobSubmittedResponse)
async def fuzz_gan(body: GANGenerateInput, request: Request):
    """Submit a GAN-based traffic generation job."""
    jobs = request.app.state.jobs

    def run():
        return jobs.runner.run_gan_generate(
            mode=body.mode,
            attack_type=body.attack_type,
            samples=body.samples,
            epochs=body.epochs,
            target_host=body.target_host,
            target_port=body.target_port,
            pcap_output=body.pcap_output,
        )

    job = jobs.submit("gan_generate", run, body.model_dump())
    return JobSubmittedResponse(
        job_id=job.id,
        status=job.status,
        message=f"GAN generation job submitted ({body.mode}, {body.samples} samples)",
    )


@router.post("/byte-model", response_model=JobSubmittedResponse)
async def fuzz_byte_model(body: GANGenerateInput, request: Request):
    """Submit a byte-model Transformer generation job."""
    jobs = request.app.state.jobs

    model_path = body.model_path or "fuzzer/data/models/byte_model_latest.pt"

    def run():
        return jobs.runner.run_byte_model(
            model_path=model_path,
            strategy=body.strategy,
            temperature=body.temperature,
            samples=body.samples,
            output_dir=body.pcap_output,
        )

    job = jobs.submit("byte_model", run, body.model_dump())
    return JobSubmittedResponse(
        job_id=job.id,
        status=job.status,
        message=f"Byte-model generation job submitted ({body.samples} samples)",
    )
