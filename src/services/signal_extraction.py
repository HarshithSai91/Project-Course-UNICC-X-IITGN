"""
H-2 Sub-Score Signal Extraction.

Computes the four component signals fed into the composite scorer:
  IOC, TTP, Semantic, CVE.

All set-overlap signals use Jaccard similarity -> [0.0, 1.0].
"""

from src.contracts.chunk_schema import CyberEntities, RankedChunk


def _jaccard(a: set[str], b: set[str]) -> float:
    """Jaccard similarity of two sets. Returns 0.0 when both are empty."""
    if not a and not b:
        return 0.0
    intersection = a & b
    union = a | b
    return len(intersection) / len(union)


def _extract_iocs(entities: CyberEntities) -> set[str]:
    """Collect all IOC strings from upstream CyberEntities."""
    iocs: set[str] = set()
    iocs.update(entities.iocs.ipv4)
    iocs.update(entities.iocs.ipv6)
    iocs.update(entities.iocs.domains)
    iocs.update(entities.iocs.urls)
    iocs.update(entities.iocs.sha256)
    iocs.update(entities.iocs.md5)
    return iocs


def compute_ioc_score(query_entities: CyberEntities, chunk: RankedChunk) -> float:
    """
    IOC overlap: Jaccard similarity of IOC strings between query and chunk.
    Consumes upstream iocs structure (ipv4/ipv6/domains/urls/sha256/md5).
    """
    query_iocs = _extract_iocs(query_entities)
    chunk_iocs = _extract_iocs(chunk.chunk.entities)
    return _jaccard(query_iocs, chunk_iocs)


def compute_ttp_score(query_entities: CyberEntities, chunk: RankedChunk) -> float:
    """
    TTP overlap: Jaccard similarity of MITRE technique IDs.
    Uses upstream mitre_ttps field.
    """
    query_ttps = set(query_entities.mitre_ttps)
    chunk_ttps = set(chunk.chunk.entities.mitre_ttps)
    return round(_jaccard(query_ttps, chunk_ttps), 4)


def compute_semantic_score(chunk: RankedChunk) -> float:
    """
    Semantic signal: use the reranker score as the best available
    post-retrieval semantic relevance indicator.

    Falls back to the raw vector_score if reranker_score is 0.
    Clamps to [0.0, 1.0].
    """
    score = chunk.reranker_score if chunk.reranker_score > 0.0 else chunk.vector_score
    return max(0.0, min(score, 1.0))


def compute_cve_score(query_entities: CyberEntities, chunk: RankedChunk) -> float:
    """
    CVE overlap: Jaccard similarity of CVE IDs between query and chunk.
    CVE IDs are compared case-insensitively.
    """
    query_cves = {c.upper() for c in query_entities.cves}
    chunk_cves = {c.upper() for c in chunk.chunk.entities.cves}
    return _jaccard(query_cves, chunk_cves)
