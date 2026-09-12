from datetime import datetime

from pydantic import BaseModel


class EntitySchema(BaseModel):
    cves: list[str] = []
    malware: list[str] = []
    mitre_techniques: list[str] = []
    ips: list[str] = []
    hashes: list[str] = []


class ThreatChunk(BaseModel):
    chunk_id: str
    doc_id: str
    doc_title: str
    source_org: str
    published_date: datetime
    page_number: int | None
    section_header: str
    text: str
    entities: EntitySchema


class ScoredChunk(BaseModel):
    # Koushik (Index) -> Suhani (Retrieval)
    chunk: ThreatChunk
    vector_score: float
    bm25_score: float
    rrf_score: float


class RankedChunk(ScoredChunk):
    # Suhani (Rerank) -> Harshith (Matching)
    reranker_score: float
    stix_relationships: list[str]
    is_stitched: bool


class FeatureAttribution(BaseModel):
    matching_iocs: list[str] = []
    matching_cves: list[str] = []
    shared_malware: list[str] = []
    matching_mitre_techniques: list[str] = []


class CharSpan(BaseModel):
    """Character offset range for a matched entity within chunk text."""

    start: int
    end: int
    entity: str  # The matched entity string (e.g. "CVE-2024-1234")
    entity_type: str  # "cve" | "ioc" | "mitre" | "malware"


class EvidenceCitation(BaseModel):
    """Structured citation packaging provenance and match locations."""

    doc_id: str
    doc_title: str
    source_org: str
    published_date: datetime
    page_number: int | None
    section_header: str
    text_snippet: str
    matched_spans: list[CharSpan] = []


class MatchResult(BaseModel):
    chunk_id: str
    composite_score: float
    confidence_tier: str
    attribution: FeatureAttribution
    citations: list[EvidenceCitation]


class PipelineProfile(BaseModel):
    """Real per-stage timing for the threat matching pipeline."""

    parse_ms: float
    retrieval_ms: float
    scoring_ms: float
    citation_ms: float
    sort_ms: float
    total_ms: float


class ThreatMatchResponse(BaseModel):
    # Harshith (API) -> Team 3 (LLM) / Team 4 (UI)
    query_threat_id: str
    top_matches: list[MatchResult]
    pipeline_profile: PipelineProfile
