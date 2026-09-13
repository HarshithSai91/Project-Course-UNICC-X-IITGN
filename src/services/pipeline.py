"""
H-1.6 / H-2 Threat Matching Pipeline Service.

Orchestrates the full pipeline:
  Query → Parse → Retrieve → Score → Classify → Attribute → Cite → Rank → Response

Extracted from the route handler for testability.
"""

import time
from collections.abc import Callable, Coroutine
from typing import Any

from src.contracts.chunk_schema import (
    MatchResult,
    PipelineProfile,
    RankedChunk,
    ThreatMatchResponse,
)
from src.core.interfaces import get_backend
from src.services.attribution import extract_feature_attribution
from src.services.citation import build_evidence_citation
from src.services.classifier import classify_threat_confidence
from src.services.query_parser import parse_query_entities
from src.services.scoring import calculate_composite_score
from src.services.signal_extraction import (
    compute_cve_score,
    compute_ioc_score,
    compute_semantic_score,
    compute_ttp_score,
)

# Type alias for the retrieval function signature
RetrievalFn = Callable[[str, int], Coroutine[Any, Any, list[RankedChunk]]]


async def run_threat_match_pipeline(
    query: str,
    top_k: int = 5,
    retrieval_fn: RetrievalFn | None = None,
) -> ThreatMatchResponse:
    """
    Execute the full threat matching pipeline.

    Args:
        query: The threat query string or incident report text.
        top_k: Number of final threat matches to return.
        retrieval_fn: Async callable returning list[RankedChunk].
                      Defaults to mock_hybrid_search (swappable for testing
                      or real integration).

    Returns:
        ThreatMatchResponse with ranked matches, citations, and profiling.
    """
    if retrieval_fn is None:
        backend = get_backend()
        retrieval_fn = backend.hybrid_search

    pipeline_start = time.perf_counter()

    # Step 1: Parse query into structured entities
    parse_start = time.perf_counter()
    query_entities = parse_query_entities(query)
    parse_ms = (time.perf_counter() - parse_start) * 1000

    # Step 2: Retrieve candidate chunks
    retrieval_start = time.perf_counter()
    retrieval_k = max(top_k * 10, 50)
    ranked_chunks = await retrieval_fn(query, retrieval_k)
    retrieval_ms = (time.perf_counter() - retrieval_start) * 1000

    # Step 3: Score, classify, and attribute each chunk
    scoring_start = time.perf_counter()
    total_citation_time = 0.0
    matches: list[MatchResult] = []

    for ranked in ranked_chunks:
        # Compute the four sub-scores
        ioc_score = compute_ioc_score(query_entities, ranked)
        ttp_score = compute_ttp_score(query_entities, ranked)
        semantic_score = compute_semantic_score(ranked)
        cve_score = compute_cve_score(query_entities, ranked)

        # Composite score
        composite = calculate_composite_score(
            ioc_score=ioc_score,
            ttp_score=ttp_score,
            semantic_score=semantic_score,
            cve_score=cve_score,
        )

        # Confidence classification
        tier = classify_threat_confidence(composite)

        # Feature attribution
        attribution = extract_feature_attribution(
            query_entities=query_entities,
            chunk=ranked.chunk,
        )

        # Evidence citation with provenance and character offsets
        cit_start = time.perf_counter()
        citation = build_evidence_citation(
            chunk=ranked.chunk,
            attribution=attribution,
        )
        total_citation_time += (time.perf_counter() - cit_start)

        matches.append(
            MatchResult(
                chunk_id=ranked.chunk.chunk_id,
                composite_score=composite,
                confidence_tier=tier,
                attribution=attribution,
                citations=[citation],
            )
        )

    # Total time for the whole scoring loop
    loop_ms = (time.perf_counter() - scoring_start) * 1000
    citation_ms = total_citation_time * 1000
    scoring_ms = loop_ms - citation_ms  # Pure scoring/attribution time

    # Step 4: Sort by composite score descending, truncate to top_k
    sort_start = time.perf_counter()
    matches.sort(key=lambda m: m.composite_score, reverse=True)
    matches = matches[:top_k]
    sort_ms = (time.perf_counter() - sort_start) * 1000

    total_ms = (time.perf_counter() - pipeline_start) * 1000

    return ThreatMatchResponse(
        query_threat_id=f"query_{int(time.time())}",
        top_matches=matches,
        pipeline_profile=PipelineProfile(
            parse_ms=round(parse_ms, 2),
            retrieval_ms=round(retrieval_ms, 2),
            scoring_ms=round(scoring_ms, 2),
            citation_ms=round(citation_ms, 2),
            sort_ms=round(sort_ms, 2),
            total_ms=round(total_ms, 2),
        ),
    )
