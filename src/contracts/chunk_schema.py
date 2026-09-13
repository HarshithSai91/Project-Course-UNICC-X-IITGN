from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Upstream data contract (Koushik / validator.py / hybrid_search)
# ---------------------------------------------------------------------------

class IOCEntities(BaseModel):
    ipv4: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    sha256: list[str] = Field(default_factory=list)
    md5: list[str] = Field(default_factory=list)


class CyberEntities(BaseModel):
    cves: list[str] = Field(default_factory=list)
    iocs: IOCEntities = Field(default_factory=IOCEntities)
    mitre_ttps: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    severity: str = Field(default="UNKNOWN")


# Backward-compatible alias for code that still refers to EntitySchema
EntitySchema = CyberEntities


class ThreatChunk(BaseModel):
    chunk_id: str = Field(..., description="Unique deterministic chunk ID")
    doc_id: str = Field(..., description="Parent document identifier")
    doc_title: str = Field(..., description="Advisory or CVE title")
    source_org: str = Field(..., description="NVD, CISA, EPSS, CVE_LIST_V5")
    published_date: datetime = Field(..., description="ISO-8601 published date")
    page_number: Optional[int] = None
    section_header: str = ""
    text: str = Field(..., description="Primary clean content")
    entities: CyberEntities = Field(default_factory=CyberEntities)
    char_start: Optional[int] = None
    char_end: Optional[int] = None
    bbox: Optional[list[float]] = None


# ---------------------------------------------------------------------------
# Retrieval / ranking interfaces (Suhani -> Harshith)
# ---------------------------------------------------------------------------

class ScoredChunk(BaseModel):
    # Koushik (Index) -> Suhani (Retrieval)
    chunk: ThreatChunk
    vector_score: float = 0.0
    bm25_score: float = 0.0
    rrf_score: float = 0.0


class RankedChunk(ScoredChunk):
    # Suhani (Rerank) -> Harshith (Matching)
    reranker_score: float = 0.0
    stix_relationships: list[str] = Field(default_factory=list)
    is_stitched: bool = False


# ---------------------------------------------------------------------------
# Matching outputs (Harshith)
# ---------------------------------------------------------------------------

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
    page_number: Optional[int] = None
    section_header: str
    text_snippet: str
    matched_spans: list[CharSpan] = []
    char_start: Optional[int] = None
    char_end: Optional[int] = None
    bbox: Optional[list[float]] = None


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
