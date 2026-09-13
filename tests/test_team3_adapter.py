from datetime import datetime, timezone
from src.contracts.chunk_schema import ThreatChunk, RankedChunk, CyberEntities
from src.adapters.team3_adapter import adapt_team3_results, Team3Result


def test_team3_maps_document_id_content_score():
    chunk = ThreatChunk(
        chunk_id="c1", doc_id="DOC-001", doc_title="T", source_org="NVD",
        published_date=datetime.now(timezone.utc), text="Sample content here.",
        entities=CyberEntities(),
    )
    ranked = RankedChunk(chunk=chunk, rrf_score=0.94)
    result = adapt_team3_results([ranked], top_k=3)
    assert len(result) == 1
    assert result[0].document_id == "DOC-001"
    assert result[0].content == "Sample content here."
    assert result[0].relevance_score == 0.94
    assert isinstance(result[0], Team3Result)


def test_team3_preserves_order_and_topk():
    chunks = [
        ThreatChunk(chunk_id=f"c{i}", doc_id=f"D{i}", doc_title="T", source_org="X",
                    published_date=datetime.now(timezone.utc), text=f"text{i}", entities=CyberEntities())
        for i in range(6)
    ]
    ranked = [
        RankedChunk(chunk=chunks[i], rrf_score=0.9 - i * 0.05)
        for i in range(6)
    ]
    result = adapt_team3_results(ranked, top_k=5)
    assert len(result) == 5
    assert result[0].relevance_score == 0.9
    assert result[4].relevance_score == 0.7


def test_team3_topk_bounds():
    chunk = ThreatChunk(chunk_id="c", doc_id="d", doc_title="t", source_org="s",
                        published_date=datetime.now(timezone.utc), text="t", entities=CyberEntities())
    # top_k parameter clamped to valid 3-5 range, but result length limited by input
    result = adapt_team3_results([RankedChunk(chunk=chunk, rrf_score=0.5)], top_k=2)
    assert len(result) == 1  # only 1 chunk available; parameter clamped to 3 but no extra data invented
    result5 = adapt_team3_results([RankedChunk(chunk=chunk, rrf_score=0.5)], top_k=10)
    assert len(result5) == 1


def test_team3_empty():
    assert adapt_team3_results([], top_k=3) == []


def test_team3_no_mutation_of_original():
    chunk = ThreatChunk(chunk_id="c", doc_id="d", doc_title="t", source_org="s",
                        published_date=datetime.now(timezone.utc), text="original", entities=CyberEntities())
    original_text = chunk.text
    adapt_team3_results([RankedChunk(chunk=chunk, rrf_score=0.8)], top_k=3)
    assert chunk.text == original_text
    assert chunk.doc_id == "d"
