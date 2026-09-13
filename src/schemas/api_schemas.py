
from pydantic import BaseModel, Field


class EntityLookupRequest(BaseModel):
    ioc: str = Field(..., description="The indicator of compromise to look up")
    ioc_type: str | None = Field(None, description="The type of the IOC (e.g., 'ipv4', 'hash', 'domain')")


class HybridSearchRequest(BaseModel):
    query: str = Field(..., description="The natural language or technical query")
    top_k: int = Field(50, description="Number of initial candidates to retrieve")


class Team3OutputRequest(BaseModel):
    query: str = Field(..., description="Query to retrieve historical chunks")
    top_k: int = Field(5, ge=3, le=5, description="Top 3-5 historical chunks for Team 3")


class ThreatMatchRequest(BaseModel):
    query: str = Field(..., description="The threat query string or incident report text")
    alpha: float = Field(0.5, description="Dynamic alpha routing parameter between dense and sparse search")
    top_k: int = Field(5, description="Number of final threat matches to return")
