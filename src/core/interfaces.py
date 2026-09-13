"""
Integration boundary interfaces for the Threat Retrieval & Matching Subsystem.

Defines the typed Protocol that teammates (Koushik, Suhani) implement,
plus a MockRetrievalBackend for development/testing ONLY.

Production code should consume upstream outputs through the adapter module
(src/adapters/upstream_adapter.py) rather than relying on mocks.
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
    DEFAULT MOCK — test-only. Not for production integration.

    Returns empty results. Use only inside tests/fixtures.
    Production path should use an adapter consuming real upstream data.
    """

    async def hybrid_search(self, query: str, top_k: int = 50) -> list[RankedChunk]:
        return []

    async def entity_lookup(
        self, ioc: str, ioc_type: str | None = None
    ) -> list[ThreatChunk]:
        return []


class MissingUpstreamDependency(Exception):
    pass


def create_retrieval_backend(
    mode: str = "mock",
    dependencies: dict | None = None,
) -> RetrievalBackend:
    """
    Factory for retrieval backend selection.
    - mock: MockRetrievalBackend (tests/default)
    - live: UpstreamRetrievalBackend with injected dependencies
    Raises clearly if LIVE requested but dependencies missing.
    """
    if mode == "mock":
        return MockRetrievalBackend()
    if mode == "live":
        if dependencies is None or not isinstance(dependencies, dict):
            raise MissingUpstreamDependency(
                "LIVE mode requires injectable dependencies dict: "
                "{hybrid_searcher, sqlite_connection, fetch_chunk_metadata, exact_lookup}"
            )
        from src.adapters.upstream_adapter import UpstreamRetrievalBackend
        return UpstreamRetrievalBackend(
            hybrid_searcher=dependencies.get("hybrid_searcher"),
            sqlite_connection=dependencies.get("sqlite_connection"),
            fetch_chunk_metadata=dependencies.get("fetch_chunk_metadata"),
            exact_lookup=dependencies.get("exact_lookup"),
        )
    raise ValueError(f"Unknown retrieval mode: {mode}. Use 'mock' or 'live'.")


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
# These delegate to the active backend (which may be mock or real adapter).
async def mock_hybrid_search(query: str, top_k: int = 50) -> list[RankedChunk]:
    """Delegate to the active backend's hybrid_search."""
    return await _backend.hybrid_search(query, top_k)


async def mock_entity_lookup(ioc: str, ioc_type: str | None = None) -> list[ThreatChunk]:
    """Delegate to the active backend's entity_lookup."""
    return await _backend.entity_lookup(ioc, ioc_type)
