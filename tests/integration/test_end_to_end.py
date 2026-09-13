"""
End-to-end integration tests for the Threat Matching Subsystem.

These tests exercise the full HTTP path: request → route → pipeline → response,
with realistic multi-chunk, multi-entity retrieval scenarios.
"""

from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from src.contracts.chunk_schema import
from src.core.interfaces import MockRetrievalBackend CyberEntities, IOCEntities, EntitySchema, RankedChunk
from src.main import app
from tests.conftest import make_ranked_chunk

ENDPOINT = "/api/v1/threats/match"


def _build_diverse_candidates() -> list[RankedChunk]:
    """Build a realistic set of candidates spanning all confidence tiers."""
    return [
        # High overlap: CVE + MITRE + IP → should score EXACT
        make_ranked_chunk(
            chunk_id="apt29_report_chunk1",
            text="APT29 exploited CVE-2024-1234 using T1059 from 10.0.0.1 to deploy Cobalt Strike",
            entities=CyberEntities(
                cves=["CVE-2024-1234"],
                mitre_ttps=["T1059"],
                iocs=IOCEntities(ipv4=["10.0.0.1"]),
                malware_families=["Cobalt Strike"],
            ),
            reranker_score=1.0,
            doc_title="APT29 Campaign Analysis",
            source_org="MITRE",
        ),
        # Moderate overlap: CVE + MITRE but different IP → STRONG
        make_ranked_chunk(
            chunk_id="apt29_report_chunk2",
            text="CVE-2024-1234 was also associated with T1059 in a separate incident",
            entities=CyberEntities(
                cves=["CVE-2024-1234"],
                mitre_ttps=["T1059"],
            ),
            reranker_score=0.85,
            doc_title="CVE Analysis Report",
            source_org="NVD",
        ),
        # Partial overlap: only CVE matches
        make_ranked_chunk(
            chunk_id="nvd_entry_chunk",
            text="CVE-2024-1234 affects multiple products",
            entities=CyberEntities(
                cves=["CVE-2024-1234"],
            ),
            reranker_score=0.75,
            doc_title="NVD Entry",
            source_org="NIST",
        ),
        # Weak overlap: no entity overlap, moderate reranker
        make_ranked_chunk(
            chunk_id="generic_report_chunk",
            text="General threat landscape overview for Q1 2024",
            entities=CyberEntities(),
            reranker_score=0.45,
            doc_title="Quarterly Report",
            source_org="CrowdStrike",
        ),
        # Minimal relevance
        make_ranked_chunk(
            chunk_id="unrelated_chunk",
            text="System maintenance scheduled for next week",
            entities=CyberEntities(),
            reranker_score=0.05,
            doc_title="Internal Memo",
            source_org="IT Ops",
        ),
    ]


@pytest.mark.asyncio
async def test_e2e_full_pipeline_round_trip() -> None:
    """Full round trip: query with entities → sorted results with citations and profiling."""
    mock_fn = AsyncMock(return_value=_build_diverse_candidates())

    with patch("src.core.interfaces.get_backend", return_value=MockRetrievalBackend())), mock_fn):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(ENDPOINT, json={
                "query": "APT29 used CVE-2024-1234 and T1059 from 10.0.0.1",
                "top_k": 5,
            })

    assert response.status_code == 200
    data = response.json()

    # All 5 candidates returned
    assert len(data["top_matches"]) == 5

    # Sorted descending by composite score
    scores = [m["composite_score"] for m in data["top_matches"]]
    assert scores == sorted(scores, reverse=True)

    # Top match should be the high-overlap chunk
    assert data["top_matches"][0]["chunk_id"] == "apt29_report_chunk1"

    # Every match has citations
    for match in data["top_matches"]:
        assert isinstance(match["citations"], list)
        assert len(match["citations"]) >= 1

    # Pipeline profile present and valid
    profile = data["pipeline_profile"]
    assert profile["total_ms"] > 0
    assert all(
        profile[k] >= 0
        for k in ["parse_ms", "retrieval_ms", "scoring_ms", "citation_ms", "sort_ms"]
    )


@pytest.mark.asyncio
async def test_e2e_empty_query_returns_semantic_ranking() -> None:
    """Query with no parseable entities still returns results ranked by semantic score."""
    candidates = [
        make_ranked_chunk("high_sem", reranker_score=0.9, entities=CyberEntities()),
        make_ranked_chunk("low_sem", reranker_score=0.1, entities=CyberEntities()),
    ]
    mock_fn = AsyncMock(return_value=candidates)

    with patch("src.core.interfaces.get_backend", return_value=MockRetrievalBackend())), mock_fn):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(ENDPOINT, json={
                "query": "suspicious network activity detected",
                "top_k": 5,
            })

    data = response.json()
    assert len(data["top_matches"]) == 2
    # Higher reranker score → higher composite → first position
    assert data["top_matches"][0]["chunk_id"] == "high_sem"


@pytest.mark.asyncio
async def test_e2e_top_k_truncation() -> None:
    """Large candidate set is properly truncated to top_k."""
    candidates = [
        make_ranked_chunk(f"chunk_{i}", reranker_score=1.0 - i * 0.04)
        for i in range(20)
    ]
    mock_fn = AsyncMock(return_value=candidates)

    with patch("src.core.interfaces.get_backend", return_value=MockRetrievalBackend())), mock_fn):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(ENDPOINT, json={
                "query": "test query",
                "top_k": 3,
            })

    data = response.json()
    assert len(data["top_matches"]) == 3
    # Top 3 should be the highest scoring
    scores = [m["composite_score"] for m in data["top_matches"]]
    assert scores == sorted(scores, reverse=True)


@pytest.mark.asyncio
async def test_e2e_all_confidence_tiers_reachable() -> None:
    """Verify all 5 confidence tiers can appear in a single response."""
    mock_fn = AsyncMock(return_value=_build_diverse_candidates())

    with patch("src.core.interfaces.get_backend", return_value=MockRetrievalBackend())), mock_fn):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(ENDPOINT, json={
                "query": "CVE-2024-1234 T1059 10.0.0.1 Cobalt Strike",
                "top_k": 10,
            })

    data = response.json()
    tiers = {m["confidence_tier"] for m in data["top_matches"]}
    valid_tiers = {"EXACT", "STRONG", "PARTIAL", "WEAK", "UNSUPPORTED"}
    # All returned tiers must be valid
    assert tiers.issubset(valid_tiers)
    # At least 3 different tiers should be present (we have diverse candidates)
    assert len(tiers) >= 3


@pytest.mark.asyncio
async def test_e2e_citation_integrity() -> None:
    """Every citation's doc_id should correspond to the chunk's parent document."""
    mock_fn = AsyncMock(return_value=_build_diverse_candidates())

    with patch("src.core.interfaces.get_backend", return_value=MockRetrievalBackend())), mock_fn):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(ENDPOINT, json={
                "query": "CVE-2024-1234 T1059 10.0.0.1",
                "top_k": 5,
            })

    data = response.json()
    for match in data["top_matches"]:
        chunk_id = match["chunk_id"]
        for citation in match["citations"]:
            # Our make_ranked_chunk sets doc_id = f"doc_{chunk_id}"
            assert citation["doc_id"] == f"doc_{chunk_id}"
            assert citation["text_snippet"] is not None
            assert len(citation["text_snippet"]) > 0


@pytest.mark.asyncio
async def test_e2e_latency_header_present() -> None:
    """X-Process-Time-ms header should be present and > 0."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.post(ENDPOINT, json={
            "query": "test",
            "top_k": 5,
        })

    assert response.status_code == 200
    assert "x-process-time-ms" in response.headers
    latency = float(response.headers["x-process-time-ms"])
    assert latency > 0
