from datetime import datetime, timezone
from src.contracts.chunk_schema import CyberEntities, IOCEntities, RankedChunk, ThreatChunk
from src.services.signal_extraction import compute_ioc_score, compute_ttp_score, compute_cve_score, compute_semantic_score

def test_semantic_uses_reranker():
    chunk = ThreatChunk(chunk_id="t", doc_id="d", doc_title="t", source_org="s",
                        published_date=datetime.now(timezone.utc), text="x", entities=CyberEntities())
    ranked = RankedChunk(chunk=chunk, reranker_score=0.85)
    assert compute_semantic_score(ranked) == 0.85
