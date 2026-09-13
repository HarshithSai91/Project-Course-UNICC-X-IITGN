"""
H-2.3 Feature Attribution Extractor.

Identifies matching IOCs, CVEs, malware families, and MITRE techniques
between the query and a candidate threat chunk, using upstream schema.
"""

from src.contracts.chunk_schema import CyberEntities, FeatureAttribution, ThreatChunk


def _extract_ioc_strings(entities: CyberEntities) -> set[str]:
    s: set[str] = set()
    s.update(entities.iocs.ipv4)
    s.update(entities.iocs.ipv6)
    s.update(entities.iocs.domains)
    s.update(entities.iocs.urls)
    s.update(entities.iocs.sha256)
    s.update(entities.iocs.md5)
    return s


def extract_feature_attribution(
    query_entities: CyberEntities,
    chunk: ThreatChunk,
) -> FeatureAttribution:
    """
    Compare parsed query entities against a chunk's upstream entity metadata.
    """
    query_iocs = _extract_ioc_strings(query_entities)
    chunk_iocs = _extract_ioc_strings(chunk.entities)
    matching_iocs = sorted(query_iocs & chunk_iocs)

    query_cves = {c.upper() for c in query_entities.cves}
    chunk_cves = {c.upper() for c in chunk.entities.cves}
    matching_cves = sorted(query_cves & chunk_cves)

    # Malware families (upstream name)
    query_malware = {m.lower() for m in (getattr(query_entities, "malware_families", []) or [])}
    chunk_malware = {m.lower(): m for m in chunk.entities.malware_families}
    shared_malware = sorted(
        chunk_malware[m] for m in chunk_malware if m in query_malware
    )

    # MITRE TTPs
    query_mitre = set(query_entities.mitre_ttps)
    chunk_mitre = set(chunk.entities.mitre_ttps)
    matching_mitre = sorted(query_mitre & chunk_mitre)

    return FeatureAttribution(
        matching_iocs=matching_iocs,
        matching_cves=matching_cves,
        shared_malware=shared_malware,
        matching_mitre_techniques=matching_mitre,
    )
