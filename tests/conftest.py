"""
Shared pytest fixtures for the Threat Retrieval & Matching Subsystem.
"""

from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient

from src.contracts.chunk_schema import EntitySchema, RankedChunk, ThreatChunk
from src.main import app


@pytest.fixture
def async_client() -> AsyncClient:
    """Pre-configured async HTTP client for API testing."""
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


def make_ranked_chunk(
    chunk_id: str,
    text: str = "Sample text",
    entities: EntitySchema | None = None,
    vector_score: float = 0.5,
    bm25_score: float = 0.5,
    rrf_score: float = 0.5,
    reranker_score: float = 0.5,
    stix_relationships: list[str] | None = None,
    doc_id: str | None = None,
    doc_title: str = "Test Document",
    source_org: str = "TestOrg",
    page_number: int | None = 1,
    section_header: str = "Header",
) -> RankedChunk:
    """Factory for creating RankedChunk test fixtures with sensible defaults."""
    if entities is None:
        entities = EntitySchema()
    chunk = ThreatChunk(
        chunk_id=chunk_id,
        doc_id=doc_id or f"doc_{chunk_id}",
        doc_title=doc_title,
        source_org=source_org,
        published_date=datetime.now(UTC),
        page_number=page_number,
        section_header=section_header,
        text=text,
        entities=entities,
    )
    return RankedChunk(
        chunk=chunk,
        vector_score=vector_score,
        bm25_score=bm25_score,
        rrf_score=rrf_score,
        reranker_score=reranker_score,
        stix_relationships=stix_relationships or [],
        is_stitched=False,
    )
