# Data Flow — Threat Retrieval & Matching Subsystem

## Division of Work
- Koushik (upstream): ingestion, validation, dedup, BGE-M3 embedding, Qdrant/SQLite storage
- Suhani (retrieval): BM25, dense retrieval, RRF fusion, cross-encoder reranking
- Harshith (this repo): matching, classification, citations, API, evaluation

## Schema Contracts

### Upstream (Koushik / validator.py)
ThreatChunk fields:
- chunk_id, doc_id, doc_title, source_org, published_date, page_number, section_header, text
- entities: CyberEntities { cves, iocs: {ipv4,ipv6,domains,urls,sha256,md5}, mitre_ttps, threat_actors, malware_families, severity }
- char_start, char_end, bbox (provenance offsets)

Retrieval output (Suhani):
- RerankedResult { chunk_id, rerank_score, text, metadata }

### Adapter (this repo / src/adapters/upstream_adapter.py)
Converts upstream ThreatChunk + reranker score to RankedChunk without discarding provenance.

### My Matching (this repo)
- Input: RankedChunk (from adapter or mock in tests)
- Processing: parse query → extract_feature_attribution → compute composite (0.35 IOC + 0.25 TTP + 0.25 Semantic + 0.15 CVE) → classify (EXACT >=0.95, STRONG 0.80-0.94, PARTIAL 0.55-0.79, WEAK 0.30-0.54, UNSUPPORTED <0.30) → build EvidenceCitation with char_start/char_end/bbox
- Output: ThreatMatchResponse with top_matches, pipeline_profile

## Production Readiness
- Adapter exists and preserves all upstream fields.
- Production code consumes adapter when RETRIEVAL_BACKEND=live.
- MockRetrievalBackend remains only for unit testing (clearly labeled).
- Real upstream retrieval interfaces (Qdrant / BM25 / RRF / reranker) are NOT duplicated; they are consumed through adapter.
- Golden dataset (data/golden_dataset.json) is kept for evaluation fixtures only; production pipeline does not load it.
- Evaluation uses retrieval-first methodology (honestly documented as proxy when real retrieval unavailable).
