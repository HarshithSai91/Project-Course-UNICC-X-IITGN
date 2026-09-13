"""
Team 3 output adapter — boundary between Team 2 (Harshith) and Team 3.

Converts existing internal RankedChunk retrieval results into the
external Team 3 representation without performing retrieval or reranking.

Preserves retrieval ranking order (sorted by upstream RRF score).
Maps relevance_score to the actual RRF fusion score (rrf_score) from
Suhani's HybridSearcher result.
"""

from __future__ import annotations
from pydantic import BaseModel
from typing import List

from src.contracts.chunk_schema import RankedChunk


class Team3Result(BaseModel):
    document_id: str
    relevance_score: float
    content: str


def adapt_team3_results(
    ranked_chunks: list[RankedChunk],
    top_k: int = 5,
) -> list[Team3Result]:
    """
    Convert Team 2 RankedChunk retrieval output to Team 3 format.
    Preserves upstream ranking order (RRF); does not recalculate scores.
    """
    if top_k < 3:
        top_k = 3
    if top_k > 5:
        top_k = 5
    # Preserve existing retrieval order produced by upstream adapter
    # (already sorted by rrf_score descending from HybridSearcher)
    selected = ranked_chunks[:top_k]
    return [
        Team3Result(
            document_id=chunk.chunk.doc_id if chunk.chunk.doc_id else chunk.chunk.chunk_id,
            relevance_score=float(chunk.rrf_score),
            content=chunk.chunk.text[:2000],  # snippet; full text available in chunk
        )
        for chunk in selected
    ]
