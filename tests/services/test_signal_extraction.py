from datetime import UTC, datetime

from src.contracts.chunk_schema import EntitySchema, RankedChunk, ThreatChunk
from src.services.signal_extraction import (
    compute_cve_score,
    compute_ioc_score,
    compute_semantic_score,
    compute_ttp_score,
)


def _make_ranked_chunk(
    entities: EntitySchema | None = None,
    vector_score: float = 0.0,
    bm25_score: float = 0.0,
    rrf_score: float = 0.0,
    reranker_score: float = 0.0,
    stix_relationships: list[str] | None = None,
) -> RankedChunk:
    """Helper to build a RankedChunk with minimal boilerplate."""
    if entities is None:
        entities = EntitySchema()
    chunk = ThreatChunk(
        chunk_id="test_chunk",
        doc_id="doc_1",
        doc_title="Test Doc",
        source_org="TestOrg",
        published_date=datetime.now(UTC),
        page_number=1,
        section_header="Header",
        text="Sample text",
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


# --- IOC Score ---

def test_ioc_full_overlap() -> None:
    query = EntitySchema(ips=["10.0.0.1"], hashes=["abc123"])
    ranked = _make_ranked_chunk(EntitySchema(ips=["10.0.0.1"], hashes=["abc123"]))
    assert compute_ioc_score(query, ranked) == 1.0


def test_ioc_partial_overlap() -> None:
    query = EntitySchema(ips=["10.0.0.1", "10.0.0.2"])
    ranked = _make_ranked_chunk(EntitySchema(ips=["10.0.0.1", "10.0.0.3"]))
    # Jaccard: {10.0.0.1} / {10.0.0.1, 10.0.0.2, 10.0.0.3} = 1/3
    score = compute_ioc_score(query, ranked)
    assert abs(score - 1 / 3) < 0.001


def test_ioc_no_overlap() -> None:
    query = EntitySchema(ips=["10.0.0.1"])
    ranked = _make_ranked_chunk(EntitySchema(ips=["10.0.0.2"]))
    assert compute_ioc_score(query, ranked) == 0.0


def test_ioc_both_empty() -> None:
    query = EntitySchema()
    ranked = _make_ranked_chunk(EntitySchema())
    assert compute_ioc_score(query, ranked) == 0.0


# --- TTP Score ---

def test_ttp_full_overlap() -> None:
    query = EntitySchema(mitre_techniques=["T1059", "T1003"])
    ranked = _make_ranked_chunk(EntitySchema(mitre_techniques=["T1059", "T1003"]))
    assert compute_ttp_score(query, ranked) == 1.0


def test_ttp_partial_overlap() -> None:
    query = EntitySchema(mitre_techniques=["T1059"])
    ranked = _make_ranked_chunk(
        EntitySchema(mitre_techniques=["T1059", "T1003"])
    )
    # Jaccard = 1/2 = 0.5
    assert compute_ttp_score(query, ranked) == 0.5


def test_ttp_no_overlap() -> None:
    query = EntitySchema(mitre_techniques=["T1059"])
    ranked = _make_ranked_chunk(EntitySchema(mitre_techniques=["T1003"]))
    assert compute_ttp_score(query, ranked) == 0.0


# --- Semantic Score ---

def test_semantic_uses_reranker() -> None:
    ranked = _make_ranked_chunk(vector_score=0.5, reranker_score=0.85)
    assert compute_semantic_score(ranked) == 0.85


def test_semantic_fallback_to_vector() -> None:
    ranked = _make_ranked_chunk(vector_score=0.7, reranker_score=0.0)
    assert compute_semantic_score(ranked) == 0.7


def test_semantic_clamped() -> None:
    ranked = _make_ranked_chunk(reranker_score=1.5)
    assert compute_semantic_score(ranked) == 1.0


# --- CVE Score ---

def test_cve_full_overlap() -> None:
    query = EntitySchema(cves=["CVE-2024-1234"])
    ranked = _make_ranked_chunk(EntitySchema(cves=["CVE-2024-1234"]))
    assert compute_cve_score(query, ranked) == 1.0


def test_cve_case_insensitive() -> None:
    query = EntitySchema(cves=["cve-2024-1234"])
    ranked = _make_ranked_chunk(EntitySchema(cves=["CVE-2024-1234"]))
    assert compute_cve_score(query, ranked) == 1.0


def test_cve_no_overlap() -> None:
    query = EntitySchema(cves=["CVE-2024-1234"])
    ranked = _make_ranked_chunk(EntitySchema(cves=["CVE-2023-0000"]))
    assert compute_cve_score(query, ranked) == 0.0


def test_cve_both_empty() -> None:
    query = EntitySchema()
    ranked = _make_ranked_chunk(EntitySchema())
    assert compute_cve_score(query, ranked) == 0.0
