"""
Adapter: upstream (Koushik / Suhani) -> Harshith matching layer.

UpstreamRetrievalBackend now calls REAL upstream HybridSearcher.search()
from upstream hybrid_search.py when injectable dependencies are provided.
Otherwise raises MissingUpstreamDependency — never silent [].
"""

from __future__ import annotations

import sqlite3
import json
from typing import Any, Callable

from src.contracts.chunk_schema import (
    CyberEntities,
    EvidenceCitation,
    FeatureAttribution,
    IOCEntities,
    RankedChunk,
    ThreatChunk,
)


def adapt_threat_chunk(raw: dict[str, Any] | ThreatChunk) -> ThreatChunk:
    if isinstance(raw, ThreatChunk):
        return raw
    entities_raw = raw.get("entities") or {}
    if isinstance(entities_raw, dict):
        iocs_raw = entities_raw.get("iocs") or {}
        entities = CyberEntities(
            cves=entities_raw.get("cves") or [],
            iocs=IOCEntities(
                ipv4=iocs_raw.get("ipv4") or [],
                ipv6=iocs_raw.get("ipv6") or [],
                domains=iocs_raw.get("domains") or [],
                urls=iocs_raw.get("urls") or [],
                sha256=iocs_raw.get("sha256") or [],
                md5=iocs_raw.get("md5") or [],
            ),
            mitre_ttps=entities_raw.get("mitre_ttps") or [],
            threat_actors=entities_raw.get("threat_actors") or [],
            malware_families=entities_raw.get("malware_families") or [],
            severity=entities_raw.get("severity") or "UNKNOWN",
        )
    else:
        entities = CyberEntities()
    return ThreatChunk(
        chunk_id=raw.get("chunk_id", ""),
        doc_id=raw.get("doc_id", ""),
        doc_title=raw.get("doc_title", ""),
        source_org=raw.get("source_org", ""),
        published_date=raw.get("published_date"),
        page_number=raw.get("page_number"),
        section_header=raw.get("section_header", ""),
        text=raw.get("text", ""),
        entities=entities,
        char_start=raw.get("char_start"),
        char_end=raw.get("char_end"),
        bbox=raw.get("bbox"),
    )


def adapt_reranked_result(
    chunk: ThreatChunk,
    rerank_score: float = 0.0,
    vector_score: float = 0.0,
    bm25_score: float = 0.0,
    rrf_score: float = 0.0,
    stix_relationships: list[str] | None = None,
    is_stitched: bool = False,
) -> RankedChunk:
    return RankedChunk(
        chunk=chunk,
        reranker_score=float(rerank_score),
        vector_score=float(vector_score),
        bm25_score=float(bm25_score),
        rrf_score=float(rrf_score),
        stix_relationships=list(stix_relationships or []),
        is_stitched=bool(is_stitched),
    )


class MissingUpstreamDependency(Exception):
    pass


def _parse_entities_json(raw: str | None) -> CyberEntities:
    if not raw:
        return CyberEntities()
    try:
        data = json.loads(raw)
    except Exception:
        data = {}
    if isinstance(data, dict):
        iocs_raw = data.get("iocs") or {}
        return CyberEntities(
            cves=data.get("cves") or [],
            iocs=IOCEntities(
                ipv4=iocs_raw.get("ipv4") or [],
                ipv6=iocs_raw.get("ipv6") or [],
                domains=iocs_raw.get("domains") or [],
                urls=iocs_raw.get("urls") or [],
                sha256=iocs_raw.get("sha256") or [],
                md5=iocs_raw.get("md5") or [],
            ),
            mitre_ttps=data.get("mitre_ttps") or [],
            threat_actors=data.get("threat_actors") or [],
            malware_families=data.get("malware_families") or [],
            severity=data.get("severity") or "UNKNOWN",
        )
    return CyberEntities()


class UpstreamRetrievalBackend:
    """REAL integration — injectable only. Requires HybridSearcher instance or callable."""

    def __init__(
        self,
        hybrid_searcher=None,
        sqlite_connection=None,
        fetch_chunk_metadata=None,
        exact_lookup=None,
    ) -> None:
        self.searcher = hybrid_searcher
        self.sqlite = sqlite_connection
        self.fetch_meta = fetch_chunk_metadata
        self.lookup = exact_lookup
        if hybrid_searcher is None:
            raise MissingUpstreamDependency(
                "UpstreamRetrievalBackend requires injectable hybrid_searcher (Suhani HybridSearcher). "
                "Pass real instance at startup; do not use hardcoded paths."
            )

    async def hybrid_search(self, query: str, top_k: int = 50) -> list[RankedChunk]:
        if self.searcher is None:
            raise MissingUpstreamDependency("hybrid_searcher not injected.")
        results = self.searcher.search(query, top_k=top_k)
        ranked: list[RankedChunk] = []
        for r in results:
            chunk = adapt_threat_chunk({
                "chunk_id": r.chunk_id,
                "text": "",
                "entities": None,
                "doc_id": "",
                "doc_title": "",
                "source_org": "",
            })
            if self.fetch_meta is not None and self.sqlite is not None:
                meta = self.fetch_meta(r.chunk_id, self.sqlite)
                if meta:
                    chunk = adapt_threat_chunk({
                        "chunk_id": meta.get("chunk_id", r.chunk_id),
                        "doc_id": meta.get("doc_id", ""),
                        "doc_title": meta.get("doc_title", ""),
                        "source_org": meta.get("source_org", ""),
                        "published_date": meta.get("published_date"),
                        "page_number": meta.get("page_number"),
                        "section_header": meta.get("section_header", ""),
                        "text": meta.get("text", ""),
                        "entities": meta.get("entities_json"),
                        "char_start": meta.get("char_start"),
                        "char_end": meta.get("char_end"),
                        "bbox": meta.get("bbox"),
                    })
            ranked.append(adapt_reranked_result(
                chunk=chunk,
                rerank_score=getattr(r, "rerank_score", 0.0),
                vector_score=getattr(r, "dense_score", 0.0) or 0.0,
                bm25_score=getattr(r, "bm25_score", getattr(r, "lexical_score", 0.0)) or 0.0,
                rrf_score=getattr(r, "rrf_score", 0.0),
            ))
        ranked.sort(key=lambda x: x.rrf_score, reverse=True)
        return ranked[:top_k]

    async def entity_lookup(self, ioc: str, ioc_type: str | None = None) -> list[ThreatChunk]:
        if self.lookup is None or self.sqlite is None:
            raise MissingUpstreamDependency("entity_lookup requires injectable exact_lookup and sqlite.")
        chunk_ids = self.lookup(ioc, ioc_type, sqlite=self.sqlite)
        chunks = []
        for cid in chunk_ids:
            meta = self.fetch_meta(cid, self.sqlite) if self.fetch_meta else None
            chunks.append(adapt_threat_chunk({
                "chunk_id": cid,
                "doc_id": meta.get("doc_id") if meta else "",
                "doc_title": meta.get("doc_title") if meta else "",
                "source_org": meta.get("source_org") if meta else "",
                "published_date": meta.get("published_date") if meta else None,
                "page_number": meta.get("page_number") if meta else None,
                "section_header": meta.get("section_header") if meta else "",
                "text": meta.get("text") if meta else "",
                "entities": meta.get("entities_json") if meta else None,
                "char_start": meta.get("char_start") if meta else None,
                "char_end": meta.get("char_end") if meta else None,
                "bbox": meta.get("bbox") if meta else None,
            }))
        return chunks

def build_evidence_citation_from_chunk(
    chunk: ThreatChunk,
    attribution: FeatureAttribution,
    text_snippet: str | None = None,
) -> EvidenceCitation:
    snippet = text_snippet or chunk.text[:500]
    return EvidenceCitation(
        doc_id=chunk.doc_id,
        doc_title=chunk.doc_title,
        source_org=chunk.source_org,
        published_date=chunk.published_date,
        page_number=chunk.page_number,
        section_header=chunk.section_header,
        text_snippet=snippet,
        char_start=chunk.char_start,
        char_end=chunk.char_end,
        bbox=chunk.bbox,
        matched_spans=[],
    )
