"""
Integration boundary interfaces for the Threat Retrieval & Matching Subsystem.

Defines the typed Protocol that teammates (Koushik, Suhani) implement,
plus a MockRetrievalBackend for development and testing.

To swap to a live backend:
  1. Implement the RetrievalBackend protocol in your module.
  2. Set RETRIEVAL_BACKEND=live in your environment.
  3. Register your implementation in main.py lifespan.
"""

from typing import Protocol, runtime_checkable

from src.contracts.chunk_schema import RankedChunk, ThreatChunk


@runtime_checkable
class RetrievalBackend(Protocol):
    """
    Typed contract for the upstream retrieval layer.

    Koushik's ML Platform provides entity lookup.
    Suhani's Search & Relevance module provides hybrid search.
    """

    async def hybrid_search(self, query: str, top_k: int = 50) -> list[RankedChunk]:
        """Execute hybrid (dense + sparse) retrieval with RRF and reranking."""
        ...

    async def entity_lookup(
        self, ioc: str, ioc_type: str | None = None
    ) -> list[ThreatChunk]:
        """Execute sub-millisecond exact IOC lookup."""
        ...


class MockRetrievalBackend:
    """
    Default mock implementation returning empty results.

    Used during development and unit testing. Swap to a live
    implementation by setting RETRIEVAL_BACKEND=live.
    """

    async def hybrid_search(self, query: str, top_k: int = 50) -> list[RankedChunk]:
        return []

    async def entity_lookup(
        self, ioc: str, ioc_type: str | None = None
    ) -> list[ThreatChunk]:
        return []


# Module-level singleton — replaced at startup when RETRIEVAL_BACKEND=live
_backend: RetrievalBackend = MockRetrievalBackend()


def get_backend() -> RetrievalBackend:
    """Return the current retrieval backend instance."""
    return _backend


def set_backend(backend: RetrievalBackend) -> None:
    """Replace the retrieval backend (called during app lifespan startup)."""
    global _backend
    _backend = backend


# Convenience functions preserving backward compatibility with existing code
async def mock_hybrid_search(query: str, top_k: int = 50) -> list[RankedChunk]:
    """Delegate to the active backend's hybrid_search."""
    return await _backend.hybrid_search(query, top_k)


async def mock_entity_lookup(ioc: str, ioc_type: str | None = None) -> list[ThreatChunk]:
    """Delegate to the active backend's entity_lookup."""
    return await _backend.entity_lookup(ioc, ioc_type)
