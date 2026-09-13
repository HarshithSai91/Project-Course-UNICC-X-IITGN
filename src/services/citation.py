"""
H-2 Evidence Citation Builder.

Builds structured citations from chunk provenance and computes
character offsets for matched entities within chunk text.
Uses actual upstream provenance fields (char_start, char_end, bbox)
wherever available.
"""

import re

from src.contracts.chunk_schema import (
    CharSpan,
    CyberEntities,
    EvidenceCitation,
    FeatureAttribution,
    ThreatChunk,
)


def _entity_tags(attribution: FeatureAttribution) -> list[tuple[str, str]]:
    tagged: list[tuple[str, str]] = []
    for ioc in attribution.matching_iocs:
        tagged.append((ioc, "ioc"))
    for cve in attribution.matching_cves:
        tagged.append((cve, "cve"))
    for malware in attribution.shared_malware:
        tagged.append((malware, "malware"))
    for mitre in attribution.matching_mitre_techniques:
        tagged.append((mitre, "mitre"))
    return tagged


def find_entity_spans(text: str, attribution: FeatureAttribution) -> list[CharSpan]:
    spans: list[CharSpan] = []
    for entity, entity_type in _entity_tags(attribution):
        for match in re.finditer(re.escape(entity), text, re.IGNORECASE):
            spans.append(
                CharSpan(
                    start=match.start(),
                    end=match.end(),
                    entity=entity,
                    entity_type=entity_type,
                )
            )
    spans.sort(key=lambda s: s.start)
    return spans


def build_evidence_citation(
    chunk: ThreatChunk,
    attribution: FeatureAttribution,
    text_snippet: str | None = None,
) -> EvidenceCitation:
    snippet = text_snippet or chunk.text[:500]
    spans = find_entity_spans(chunk.text, attribution)
    return EvidenceCitation(
        doc_id=chunk.doc_id,
        doc_title=chunk.doc_title,
        source_org=chunk.source_org,
        published_date=chunk.published_date,
        page_number=chunk.page_number,
        section_header=chunk.section_header,
        text_snippet=snippet,
        matched_spans=spans,
        char_start=chunk.char_start,
        char_end=chunk.char_end,
        bbox=chunk.bbox,
    )
