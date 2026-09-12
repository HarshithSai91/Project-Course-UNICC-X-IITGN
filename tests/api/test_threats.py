from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from src.contracts.chunk_schema import EntitySchema, RankedChunk, ThreatChunk
from src.main import app


def _make_ranked_chunk(
    chunk_id: str = "chunk_1",
    entities: EntitySchema | None = None,
    reranker_score: float = 0.8,
) -> RankedChunk:
    if entities is None:
        entities = EntitySchema(
            cves=["CVE-2024-1234"],
            mitre_techniques=["T1059"],
            ips=["10.0.0.1"],
        )
    chunk = ThreatChunk(
        chunk_id=chunk_id,
        doc_id="doc_1",
        doc_title="Test",
        source_org="Org",
        published_date=datetime.now(UTC),
        page_number=1,
        section_header="Header",
        text="Attack used CVE-2024-1234 and T1059 from 10.0.0.1",
        entities=entities,
    )
    return RankedChunk(
        chunk=chunk,
        vector_score=0.5,
        bm25_score=0.5,
        rrf_score=0.5,
        reranker_score=reranker_score,
        stix_relationships=[],
        is_stitched=False,
    )


@pytest.mark.asyncio
async def test_threat_matching_endpoint_empty() -> None:
    """Original Phase 2 test — mock returns [], response should be empty matches."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        payload = {"query": "Suspicious login attempt", "alpha": 0.5, "top_k": 5}
        response = await ac.post("/api/v1/threats/match", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert "query_threat_id" in data
    assert data["top_matches"] == []
    assert "pipeline_profile" in data
    assert "total_ms" in data["pipeline_profile"]


@pytest.mark.asyncio
async def test_threat_matching_endpoint_with_data() -> None:
    """Patch mock_hybrid_search to return synthetic chunks and verify full response."""
    mock_chunks = [
        _make_ranked_chunk("chunk_1", reranker_score=0.9),
        _make_ranked_chunk("chunk_2", reranker_score=0.4),
    ]
    mock_fn = AsyncMock(return_value=mock_chunks)

    with patch("src.services.pipeline.mock_hybrid_search", mock_fn):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            payload = {
                "query": "CVE-2024-1234 T1059 from 10.0.0.1",
                "alpha": 0.5,
                "top_k": 5,
            }
            response = await ac.post("/api/v1/threats/match", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert len(data["top_matches"]) == 2

    # Verify sorted by composite score descending
    scores = [m["composite_score"] for m in data["top_matches"]]
    assert scores == sorted(scores, reverse=True)

    # Verify confidence tier is valid
    valid_tiers = {"EXACT", "STRONG", "PARTIAL", "WEAK", "UNSUPPORTED"}
    for match in data["top_matches"]:
        assert match["confidence_tier"] in valid_tiers

    # Verify attribution is present
    top = data["top_matches"][0]
    assert "attribution" in top
    assert "matching_iocs" in top["attribution"]
    assert "matching_cves" in top["attribution"]
    assert "matching_mitre_techniques" in top["attribution"]

    # Verify citations are populated
    assert "citations" in top
    assert len(top["citations"]) >= 1
    citation = top["citations"][0]
    assert "doc_id" in citation
    assert "doc_title" in citation
    assert "text_snippet" in citation
    assert "matched_spans" in citation

    # Verify pipeline profile
    assert "pipeline_profile" in data
    profile = data["pipeline_profile"]
    assert profile["total_ms"] > 0
    assert "parse_ms" in profile
    assert "retrieval_ms" in profile
    assert "scoring_ms" in profile
    assert "citation_ms" in profile
    assert "sort_ms" in profile


@pytest.mark.asyncio
async def test_threat_matching_endpoint_validation() -> None:
    """Missing required 'query' field should return 422."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.post("/api/v1/threats/match", json={})

    assert response.status_code == 422
