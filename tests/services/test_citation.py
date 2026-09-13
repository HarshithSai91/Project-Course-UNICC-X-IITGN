from datetime import UTC, datetime

from src.contracts.chunk_schema import EntitySchema, FeatureAttribution, ThreatChunk
from src.services.citation import build_evidence_citation, find_entity_spans


def _make_chunk(text: str = "Sample text with CVE-2024-1234 and 10.0.0.1") -> ThreatChunk:
    return ThreatChunk(
        chunk_id="chunk_1",
        doc_id="doc_1",
        doc_title="APT29 Analysis",
        source_org="MITRE",
        published_date=datetime(2024, 6, 15, tzinfo=UTC),
        page_number=3,
        section_header="Indicators",
        text=text,
        entities=EntitySchema(
            cves=["CVE-2024-1234"],
            ips=["10.0.0.1"],
            mitre_techniques=["T1059"],
        ),
    )


# --- find_entity_spans ---


def test_find_spans_single_entity() -> None:
    text = "Exploited CVE-2024-1234 in the attack."
    attr = FeatureAttribution(matching_cves=["CVE-2024-1234"])
    spans = find_entity_spans(text, attr)
    assert len(spans) == 1
    assert spans[0].start == 10
    assert spans[0].end == 23
    assert spans[0].entity == "CVE-2024-1234"
    assert spans[0].entity_type == "cve"


def test_find_spans_multiple_entities() -> None:
    text = "Found CVE-2024-1234 and 10.0.0.1 communicating."
    attr = FeatureAttribution(
        matching_cves=["CVE-2024-1234"],
        matching_iocs=["10.0.0.1"],
    )
    spans = find_entity_spans(text, attr)
    assert len(spans) == 2
    # Should be sorted by start position — CVE appears first in text
    assert spans[0].start < spans[1].start
    # Verify both entities are found
    entities_found = {s.entity for s in spans}
    assert entities_found == {"CVE-2024-1234", "10.0.0.1"}


def test_find_spans_entity_not_in_text() -> None:
    text = "No indicators here."
    attr = FeatureAttribution(matching_cves=["CVE-2024-9999"])
    spans = find_entity_spans(text, attr)
    assert len(spans) == 0


def test_find_spans_case_insensitive() -> None:
    text = "Found cve-2024-1234 in logs."
    attr = FeatureAttribution(matching_cves=["CVE-2024-1234"])
    spans = find_entity_spans(text, attr)
    assert len(spans) == 1
    assert spans[0].entity == "CVE-2024-1234"


def test_find_spans_multiple_occurrences() -> None:
    text = "T1059 used first, then T1059 again."
    attr = FeatureAttribution(matching_mitre_techniques=["T1059"])
    spans = find_entity_spans(text, attr)
    assert len(spans) == 2
    assert spans[0].start == 0
    assert spans[1].start == 23


def test_find_spans_malware() -> None:
    text = "Cobalt Strike beacon detected in memory."
    attr = FeatureAttribution(shared_malware=["Cobalt Strike"])
    spans = find_entity_spans(text, attr)
    assert len(spans) == 1
    assert spans[0].entity_type == "malware"
    assert spans[0].entity == "Cobalt Strike"


def test_find_spans_empty_attribution() -> None:
    text = "Some text here."
    attr = FeatureAttribution()
    spans = find_entity_spans(text, attr)
    assert spans == []


# --- build_evidence_citation ---


def test_citation_provenance_propagation() -> None:
    chunk = _make_chunk("Attack used CVE-2024-1234 from 10.0.0.1")
    attr = FeatureAttribution(
        matching_cves=["CVE-2024-1234"],
        matching_iocs=["10.0.0.1"],
    )
    citation = build_evidence_citation(chunk, attr)

    assert citation.doc_id == "doc_1"
    assert citation.doc_title == "APT29 Analysis"
    assert citation.source_org == "MITRE"
    assert citation.published_date == datetime(2024, 6, 15, tzinfo=UTC)
    assert citation.page_number == 3
    assert citation.section_header == "Indicators"
    assert citation.text_snippet == "Attack used CVE-2024-1234 from 10.0.0.1"


def test_citation_matched_spans_populated() -> None:
    chunk = _make_chunk("Attack used CVE-2024-1234 from 10.0.0.1")
    attr = FeatureAttribution(
        matching_cves=["CVE-2024-1234"],
        matching_iocs=["10.0.0.1"],
    )
    citation = build_evidence_citation(chunk, attr)

    assert len(citation.matched_spans) == 2
    entities = {s.entity for s in citation.matched_spans}
    assert "CVE-2024-1234" in entities
    assert "10.0.0.1" in entities


def test_citation_no_matches_empty_spans() -> None:
    chunk = _make_chunk("No indicators in this text.")
    attr = FeatureAttribution()
    citation = build_evidence_citation(chunk, attr)

    assert citation.matched_spans == []
    # Provenance should still be populated
    assert citation.doc_id == "doc_1"
    assert citation.text_snippet == "No indicators in this text."
