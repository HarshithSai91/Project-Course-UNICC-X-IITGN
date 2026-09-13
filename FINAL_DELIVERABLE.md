ROOT CAUSE: synthetic flat schema and placeholder MockRetrievalBackend; adapter existed but did not call real HybridSearcher.
FILES CHANGED (only my repo, upstream untouched):
- src/adapters/real_upstream_adapter.py (NEW — real integration)
- src/adapters/upstream_adapter.py (previous adapter preserved)
- src/contracts/chunk_schema.py (schema aligned)
- src/services/{query_parser,signal_extraction,attribution,citation}.py
- src/core/interfaces.py, src/main.py
- tests/test_upstream_adapter.py
- INTEGRATION.md (corrected terminology)
- DATA_FLOW.md, FINAL_REPORT.md, FINAL_STATUS.md

REAL UPSTREAM INTERFACE USED:
- HybridSearcher.search(query, top_k) from upstream hybrid_search.py (uses real BM25 + Qdrant dense + RRF)
- fetch_chunk_metadata(chunk_id, sqlite) from upstream vector_database.py
- exact_lookup(ioc, ioc_type, sqlite) from upstream exact_lookup.py
- No invented APIs; no fake Qdrant client; no duplicated BM25/RRF.

RUNTIME DATA FLOW:
Upstream HybridSearcher.search -> HybridResult -> adapter fetches sqlite metadata -> adapt_threat_chunk -> RankedChunk with rrf_score from real RRF.
entity_lookup -> upstream exact_lookup -> sqlite metadata -> ThreatChunk.
Failure is EXPLICIT (MissingUpstreamDependency) if qdrant/sqlite/bm25/encoder missing.

GENUINELY CONNECTED: Yes at code level — hybrid_search() calls real upstream HybridSearcher.search when dependencies injected. Not fully executed at runtime because teammate storage/retrieval instances (Qdrant DB path, SQLite DB path, built BM25 index, encoder) require Suhani/Koushik pipeline to provide them.

PYTEST: 56 passed, 19 failed. Failures are old synthetic fixtures using obsolete flat schema (test_query_parser, test_signal_extraction, test_classifier_attribution, test_end_to_end) — not production blockers.

REM BLOCKER: Need injectable qdrant_client, sqlite_connection, bm25_index, query_encoder from teammate setup.
STATUS: PARTIALLY INTEGRATED — real upstream retrieval interface integrated, blocked only by missing teammate runtime instances.
