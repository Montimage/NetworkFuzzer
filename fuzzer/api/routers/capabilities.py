"""Discovery endpoint for listing available protocols, profiles, and modes."""

from fastapi import APIRouter, HTTPException, Request

from fuzzer.api.models import CapabilitiesResponse

router = APIRouter()

VALID_CATEGORIES = {"protocols", "attack_profiles", "fuzz_modes"}


@router.get("/capabilities/{category}", response_model=CapabilitiesResponse)
async def list_capabilities(category: str, request: Request):
    """List available protocols, attack_profiles, or fuzz_modes."""
    if category not in VALID_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category '{category}'. Must be one of: {', '.join(sorted(VALID_CATEGORIES))}",
        )

    runner = request.app.state.jobs.runner

    if category == "protocols":
        items = runner.list_protocols()
    elif category == "attack_profiles":
        items = runner.list_attack_profiles()
    else:
        items = runner.list_fuzz_modes()

    return CapabilitiesResponse(category=category, items=items)
