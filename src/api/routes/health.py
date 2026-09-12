from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

class HealthResponse(BaseModel):
    status: str
    vector_db: str
    graph_db: str
    model_status: str

from src.core.config import get_settings

settings = get_settings()

@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    # Check the retrieval backend setting
    if settings.RETRIEVAL_BACKEND == "mock":
        return HealthResponse(
            status="healthy",
            vector_db="mocked",
            graph_db="mocked",
            model_status="ready"
        )
    
    # In a real live implementation, we'd ping the databases via the RetrievalBackend protocol
    return HealthResponse(
        status="healthy",
        vector_db="unknown (live)",
        graph_db="unknown (live)",
        model_status="ready"
    )
