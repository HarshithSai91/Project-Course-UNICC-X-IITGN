from datetime import UTC, datetime

from src.contracts.chunk_schema import CyberEntities, IOCEntities, EntitySchema, ThreatChunk
from src.services.attribution import extract_feature_attribution
from src.services.classifier import classify_threat_confidence


def test_classify_threat_confidence() -> None:
    assert classify_threat_confidence(0.96) == "EXACT"
    assert classify_threat_confidence(0.95) == "EXACT"
    assert classify_threat_confidence(0.94) == "STRONG"
    assert classify_threat_confidence(0.80) == "STRONG"
    assert classify_threat_confidence(0.79) == "PARTIAL"
    assert classify_threat_confidence(0.55) == "PARTIAL"
    assert classify_threat_confidence(0.54) == "WEAK"
    assert classify_threat_confidence(0.30) == "WEAK"
    assert classify_threat_confidence(0.29) == "UNSUPPORTED"
    assert classify_threat_confidence(0.0) == "UNSUPPORTED"

def test_extract_feature_attribution() -> None:
    chunk_entities = CyberEntities(
        cves=["CVE-2024-1234", "CVE-2023-0000"],
        malware_families=["Cobalt Strike", "Mimikatz"],
        mitre_ttps=["T1059", "T1003"],
        iocs=IOCEntities(ipv4=["10.0.0.1"]),
        hashes=["abc123"],
    )
    chunk = ThreatChunk(
        chunk_id="chunk_1",
        doc_id="doc_1",
        doc_title="Title",
        source_org="Org",
        published_date=datetime.now(UTC),
        page_number=1,
        section_header="Header",
        text="Sample text",
        entities=chunk_entities,
    )

    # Simulated parsed query entities
    query_entities = CyberEntities(
        cves=["CVE-2024-1234"],
        malware_families=["Cobalt Strike"],
        mitre_ttps=["T1059"],
        iocs=IOCEntities(ipv4=["10.0.0.1"], md5=[], sha256=[]),
    )

    attribution = extract_feature_attribution(query_entities, chunk)

    assert "CVE-2024-1234" in attribution.matching_cves
    assert "CVE-2023-0000" not in attribution.matching_cves

    assert "Cobalt Strike" in attribution.shared_malware
    assert "Mimikatz" not in attribution.shared_malware

    assert "T1059" in attribution.matching_mitre_techniques
    assert "T1003" not in attribution.matching_mitre_techniques

    assert "10.0.0.1" in attribution.matching_iocs


def test_extract_feature_attribution_no_overlap() -> None:
    chunk_entities = CyberEntities(
        cves=["CVE-2023-0000"],
        malware=["Mimikatz"],
        mitre_ttps=["T1003"],
    )
    chunk = ThreatChunk(
        chunk_id="chunk_2",
        doc_id="doc_2",
        doc_title="Title",
        source_org="Org",
        published_date=datetime.now(UTC),
        page_number=1,
        section_header="Header",
        text="Sample",
        entities=chunk_entities,
    )

    query_entities = CyberEntities(
        cves=["CVE-2024-9999"],
        malware=["NotAMalware"],
        mitre_ttps=["T9999"],
    )

    attribution = extract_feature_attribution(query_entities, chunk)

    assert attribution.matching_cves == []
    assert attribution.shared_malware == []
    assert attribution.matching_mitre_techniques == []
    assert attribution.matching_iocs == []