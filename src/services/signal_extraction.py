"""
H-2 Sub-Score Signal Extraction.

Computes the four component signals fed into the composite scorer:
  IOC, TTP, Semantic, CVE.

All set-overlap signals use Jaccard similarity → [0.0, 1.0].
"""

from src.contracts.chunk_schema import EntitySchema, RankedChunk


def _jaccard(a: set[str], b: set[str]) -> float:
    """Jaccard similarity of two sets. Returns 0.0 when both are empty."""
    if not a and not b:
        return 0.0
    intersection = a & b
    union = a | b
    return len(intersection) / len(union)


def compute_ioc_score(query_entities: EntitySchema, chunk: RankedChunk) -> float:
    """
    IOC overlap: Jaccard similarity of (IPs ∪ hashes) between query and chunk.
    """
    query_iocs = set(query_entities.ips) | {h.lower() for h in query_entities.hashes}
    chunk_iocs = set(chunk.chunk.entities.ips) | {
        h.lower() for h in chunk.chunk.entities.hashes
    }
    return _jaccard(query_iocs, chunk_iocs)


def compute_ttp_score(query_entities: EntitySchema, chunk: RankedChunk) -> float:
    """
    TTP overlap: Jaccard similarity of MITRE technique IDs.
    """
    query_ttps = set(query_entities.mitre_techniques)
    chunk_ttps = set(chunk.chunk.entities.mitre_techniques)
    base = _jaccard(query_ttps, chunk_ttps)

    return round(base, 4)


def compute_semantic_score(chunk: RankedChunk) -> float:
    """
    Semantic signal: use the reranker score as the best available
    post-retrieval semantic relevance indicator.

    Falls back to the raw vector_score if reranker_score is 0.
    Clamps to [0.0, 1.0].
    """
    score = chunk.reranker_score if chunk.reranker_score > 0.0 else chunk.vector_score
    return max(0.0, min(score, 1.0))


def compute_cve_score(query_entities: EntitySchema, chunk: RankedChunk) -> float:
    """
    CVE overlap: Jaccard similarity of CVE IDs between query and chunk.
    CVE IDs are compared case-insensitively.
    """
    query_cves = {c.upper() for c in query_entities.cves}
    chunk_cves = {c.upper() for c in chunk.chunk.entities.cves}
    return _jaccard(query_cves, chunk_cves)
