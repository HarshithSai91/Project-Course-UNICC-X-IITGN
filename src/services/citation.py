"""
H-2 Evidence Citation Builder.

Builds structured citations from chunk provenance and computes
character offsets for matched entities within chunk text.
"""

import re

from src.contracts.chunk_schema import (
    CharSpan,
    EvidenceCitation,
    FeatureAttribution,
    ThreatChunk,
)


def find_entity_spans(text: str, attribution: FeatureAttribution) -> list[CharSpan]:
    """
    Find character offsets of all attributed entities within the chunk text.

    Searches case-insensitively for each matched entity. Returns spans
    sorted by start position.
    """
    spans: list[CharSpan] = []

    # Build (entity_value, entity_type) pairs from attribution
    tagged_entities: list[tuple[str, str]] = []
    for ioc in attribution.matching_iocs:
        tagged_entities.append((ioc, "ioc"))
    for cve in attribution.matching_cves:
        tagged_entities.append((cve, "cve"))
    for malware in attribution.shared_malware:
        tagged_entities.append((malware, "malware"))
    for mitre in attribution.matching_mitre_techniques:
        tagged_entities.append((mitre, "mitre"))

    for entity, entity_type in tagged_entities:
        # Use re.escape to safely match literal strings (IPs have dots, etc.)
        for match in re.finditer(re.escape(entity), text, re.IGNORECASE):
            spans.append(
                CharSpan(
                    start=match.start(),
                    end=match.end(),
                    entity=entity,
                    entity_type=entity_type,
                )
            )

    # Sort by start position for consistent ordering
    spans.sort(key=lambda s: s.start)
    return spans


def build_evidence_citation(
    chunk: ThreatChunk,
    attribution: FeatureAttribution,
) -> EvidenceCitation:
    """
    Package a chunk's provenance metadata and entity match offsets
    into a structured EvidenceCitation.
    """
    matched_spans = find_entity_spans(chunk.text, attribution)

    return EvidenceCitation(
        doc_id=chunk.doc_id,
        doc_title=chunk.doc_title,
        source_org=chunk.source_org,
        published_date=chunk.published_date,
        page_number=chunk.page_number,
        section_header=chunk.section_header,
        text_snippet=chunk.text,
        matched_spans=matched_spans,
    )
