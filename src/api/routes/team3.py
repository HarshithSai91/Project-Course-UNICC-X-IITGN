from fastapi import APIRouter
from src.core.interfaces import get_backend
from src.adapters.team3_adapter import adapt_team3_results
from src.schemas.api_schemas import Team3OutputRequest
from src.adapters.team3_adapter import Team3Result

router = APIRouter()

@router.post("/team3/format", response_model=list[Team3Result])
async def team3_format(request: Team3OutputRequest) -> list:
    """
    Team 3 handoff: converts internal RankedChunk retrieval results
    to the external Team 3 3-field representation.
    """
    backend = get_backend()
    # Retrieve through existing Team 2 backend (mock or real adapter)
    ranked = await backend.hybrid_search(query=request.query, top_k=request.top_k)
    return adapt_team3_results(ranked, top_k=request.top_k)
