from datetime import UTC, datetime

import pytest

from src.contracts.chunk_schema import EntitySchema, RankedChunk, ThreatChunk
from src.services.pipeline import run_threat_match_pipeline


def _make_ranked_chunk(
    chunk_id: str,
    entities: EntitySchema | None = None,
    vector_score: float = 0.5,
    bm25_score: float = 0.5,
    rrf_score: float = 0.5,
    reranker_score: float = 0.5,
    stix_relationships: list[str] | None = None,
    text: str | None = None,
) -> RankedChunk:
    if entities is None:
        entities = EntitySchema()
    chunk = ThreatChunk(
        chunk_id=chunk_id,
        doc_id=f"doc_{chunk_id}",
        doc_title=f"Title {chunk_id}",
        source_org="TestOrg",
        published_date=datetime.now(UTC),
        page_number=1,
        section_header="Header",
        text=text or f"Sample text for {chunk_id}",
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


async def _mock_retrieval_with_data(query: str, top_k: int) -> list[RankedChunk]:
    """Fake retrieval returning 3 chunks with known entities and scores."""
    return [
        _make_ranked_chunk(
            chunk_id="chunk_high",
            entities=EntitySchema(
                cves=["CVE-2024-1234"],
                mitre_techniques=["T1059"],
                ips=["10.0.0.1"],
            ),
            reranker_score=0.95,
            text="Attack exploited CVE-2024-1234 using T1059 from 10.0.0.1",
        ),
        _make_ranked_chunk(
            chunk_id="chunk_mid",
            entities=EntitySchema(
                cves=["CVE-2024-1234"],
                mitre_techniques=["T1003"],
            ),
            reranker_score=0.6,
            text="CVE-2024-1234 linked to T1003 credential dumping",
        ),
        _make_ranked_chunk(
            chunk_id="chunk_low",
            entities=EntitySchema(),
            reranker_score=0.2,
            text="Generic threat intelligence report with no specific indicators",
        ),
    ]


@pytest.mark.asyncio
async def test_pipeline_returns_sorted_matches() -> None:
    query = "Attacker exploited CVE-2024-1234 using T1059 from 10.0.0.1"
    result = await run_threat_match_pipeline(
        query=query, top_k=10, retrieval_fn=_mock_retrieval_with_data
    )
    assert len(result.top_matches) == 3
    # Verify sorted descending by composite score
    scores = [m.composite_score for m in result.top_matches]
    assert scores == sorted(scores, reverse=True)


@pytest.mark.asyncio
async def test_pipeline_truncates_to_top_k() -> None:
    query = "CVE-2024-1234 T1059"
    result = await run_threat_match_pipeline(
        query=query, top_k=2, retrieval_fn=_mock_retrieval_with_data
    )
    assert len(result.top_matches) == 2


@pytest.mark.asyncio
async def test_pipeline_confidence_tiers_are_valid() -> None:
    query = "CVE-2024-1234 T1059 10.0.0.1"
    result = await run_threat_match_pipeline(
        query=query, top_k=10, retrieval_fn=_mock_retrieval_with_data
    )
    valid_tiers = {"EXACT", "STRONG", "PARTIAL", "WEAK", "UNSUPPORTED"}
    for match in result.top_matches:
        assert match.confidence_tier in valid_tiers


@pytest.mark.asyncio
async def test_pipeline_attribution_populated() -> None:
    query = "CVE-2024-1234 T1059 10.0.0.1"
    result = await run_threat_match_pipeline(
        query=query, top_k=10, retrieval_fn=_mock_retrieval_with_data
    )
    top_match = result.top_matches[0]
    # chunk_high has CVE-2024-1234, T1059, 10.0.0.1 — all should match
    assert "CVE-2024-1234" in top_match.attribution.matching_cves
    assert "T1059" in top_match.attribution.matching_mitre_techniques
    assert "10.0.0.1" in top_match.attribution.matching_iocs


@pytest.mark.asyncio
async def test_pipeline_profile_populated() -> None:
    query = "test"
    result = await run_threat_match_pipeline(
        query=query, top_k=5, retrieval_fn=_mock_retrieval_with_data
    )
    profile = result.pipeline_profile
    assert profile.total_ms > 0
    assert profile.parse_ms >= 0
    assert profile.retrieval_ms >= 0
    assert profile.scoring_ms >= 0
    assert profile.citation_ms >= 0
    assert profile.sort_ms >= 0


@pytest.mark.asyncio
async def test_pipeline_empty_retrieval() -> None:
    async def empty_retrieval(query: str, top_k: int) -> list[RankedChunk]:
        return []

    result = await run_threat_match_pipeline(
        query="test", top_k=5, retrieval_fn=empty_retrieval
    )
    assert result.top_matches == []
    assert result.pipeline_profile.total_ms >= 0


@pytest.mark.asyncio
async def test_pipeline_query_threat_id_format() -> None:
    query = "test"
    result = await run_threat_match_pipeline(
        query=query, top_k=5, retrieval_fn=_mock_retrieval_with_data
    )
    assert result.query_threat_id.startswith("query_")


@pytest.mark.asyncio
async def test_pipeline_high_overlap_scores_higher() -> None:
    """chunk_high has more entity overlap with the query than chunk_low."""
    query = "CVE-2024-1234 T1059 10.0.0.1"
    result = await run_threat_match_pipeline(
        query=query, top_k=10, retrieval_fn=_mock_retrieval_with_data
    )
    high = next(m for m in result.top_matches if m.chunk_id == "chunk_high")
    low = next(m for m in result.top_matches if m.chunk_id == "chunk_low")
    assert high.composite_score > low.composite_score


@pytest.mark.asyncio
async def test_pipeline_citations_populated() -> None:
    """Citations should be populated when entities match."""
    query = "CVE-2024-1234 T1059 10.0.0.1"
    result = await run_threat_match_pipeline(
        query=query, top_k=10, retrieval_fn=_mock_retrieval_with_data
    )
    top_match = result.top_matches[0]
    assert len(top_match.citations) == 1

    citation = top_match.citations[0]
    assert citation.doc_id == "doc_chunk_high"
    assert citation.doc_title == "Title chunk_high"
    assert citation.source_org == "TestOrg"
    assert citation.text_snippet is not None
    assert len(citation.text_snippet) > 0


@pytest.mark.asyncio
async def test_pipeline_citation_spans_present() -> None:
    """Citations should include character offset spans for matched entities."""
    query = "CVE-2024-1234 T1059 10.0.0.1"
    result = await run_threat_match_pipeline(
        query=query, top_k=10, retrieval_fn=_mock_retrieval_with_data
    )
    top_match = result.top_matches[0]
    citation = top_match.citations[0]
    # chunk_high text contains CVE-2024-1234, T1059, 10.0.0.1
    assert len(citation.matched_spans) > 0
    span_entities = {s.entity for s in citation.matched_spans}
    assert "CVE-2024-1234" in span_entities
    assert "T1059" in span_entities
    assert "10.0.0.1" in span_entities
