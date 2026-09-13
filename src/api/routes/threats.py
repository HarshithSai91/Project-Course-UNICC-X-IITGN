from fastapi import APIRouter

from src.contracts.chunk_schema import ThreatMatchResponse
from src.schemas.api_schemas import ThreatMatchRequest
from src.services.pipeline import run_threat_match_pipeline

router = APIRouter()


@router.post("/threats/match", response_model=ThreatMatchResponse)
async def match_threats(request: ThreatMatchRequest) -> ThreatMatchResponse:
    """
    H-1.6: Master Threat Matching Route.
    Thin wrapper delegating to the pipeline service.
    """
    return await run_threat_match_pipeline(
        query=request.query,
        top_k=request.top_k,
    )
