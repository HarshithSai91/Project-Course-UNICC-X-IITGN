
from fastapi import APIRouter

from src.contracts.chunk_schema import ThreatChunk
from src.core.interfaces import mock_entity_lookup
from src.schemas.api_schemas import EntityLookupRequest

router = APIRouter()

@router.post("/entities/lookup", response_model=list[ThreatChunk])
async def entity_lookup(request: EntityLookupRequest) -> list[ThreatChunk]:
    """
    H-1.4: Direct Entity Lookup Route.
    Thin wrapper executing sub-millisecond IOC queries via the Search & Relevance module.
    """
    # Simply delegate to the retrieval boundary; no duplicated logic here.
    results = await mock_entity_lookup(ioc=request.ioc, ioc_type=request.ioc_type)
    return results
