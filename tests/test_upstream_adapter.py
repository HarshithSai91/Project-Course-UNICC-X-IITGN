"""Tests for upstream adapter and schema integration (not synthetic mocks)."""

import pytest
from datetime import datetime

from src.contracts.chunk_schema import (
    CyberEntities, IOCEntities, ThreatChunk, RankedChunk, FeatureAttribution
)
from src.adapters.upstream_adapter import (
    adapt_threat_chunk, adapt_reranked_result, build_evidence_citation_from_chunk
)


def test_adapt_threat_chunk_from_dict():
    raw = {
        "chunk_id": "c1",
        "doc_id": "d1",
        "doc_title": "Test",
        "source_org": "NVD",
        "published_date": "2024-01-01T00:00:00",
        "text": "hello",
        "entities": {
            "cves": ["CVE-2024-1234"],
            "iocs": {"ipv4": ["10.0.0.1"], "sha256": ["a" * 64]},
            "mitre_ttps": ["T1059"],
            "malware_families": ["AgentTesla"],
            "severity": "HIGH",
        },
        "char_start": 10,
        "char_end": 20,
        "bbox": [0.1, 0.2, 0.3, 0.4],
    }
    chunk = adapt_threat_chunk(raw)
    assert chunk.chunk_id == "c1"
    assert chunk.entities.mitre_ttps == ["T1059"]
    assert chunk.entities.malware_families == ["AgentTesla"]
    assert chunk.char_start == 10
    assert chunk.bbox == [0.1, 0.2, 0.3, 0.4]
    assert chunk.entities.iocs.ipv4 == ["10.0.0.1"]


def test_adapt_reranked_result_preserves_score():
    chunk = ThreatChunk(chunk_id="c", doc_id="d", doc_title="t", source_org="s",
                        published_date=datetime.now(), text="txt", entities=CyberEntities())
    ranked = adapt_reranked_result(chunk, rerank_score=0.92)
    assert ranked.reranker_score == 0.92
    assert ranked.chunk.chunk_id == "c"


def test_build_evidence_citation_keeps_provenance():
    chunk = ThreatChunk(chunk_id="c", doc_id="d", doc_title="t", source_org="NVD",
                        published_date=datetime.now(), text="CVE-2024-1234", entities=CyberEntities())
    cit = build_evidence_citation_from_chunk(chunk, FeatureAttribution())
    assert cit.doc_id == "d"
    assert cit.char_start is None or cit.char_start == chunk.char_start
