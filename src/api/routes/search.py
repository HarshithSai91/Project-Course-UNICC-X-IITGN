
from fastapi import APIRouter

from src.contracts.chunk_schema import RankedChunk
from src.core.interfaces import get_backend
from src.schemas.api_schemas import HybridSearchRequest

router = APIRouter()

@router.post("/search/hybrid", response_model=list[RankedChunk])
async def hybrid_search(request: HybridSearchRequest) -> list[RankedChunk]:
    """
    H-1.5: Hybrid Search Route.
    Thin wrapper returning scored and filtered evidence passages via the Search module.
    """
    # Delegate entirely to Suhani's dual-channel search / RRF pipeline.
    backend = get_backend()
    results = await backend.hybrid_search(query=request.query, top_k=request.top_k)
    return results
