"""
H-2.3 Feature Attribution Extractor.

Identifies matching IOCs, CVEs, malware families, and MITRE techniques
between the query and a candidate threat chunk.
"""

from src.contracts.chunk_schema import EntitySchema, FeatureAttribution, ThreatChunk


def extract_feature_attribution(
    query_entities: EntitySchema,
    chunk: ThreatChunk,
) -> FeatureAttribution:
    """
    Compare parsed query entities against a chunk's entity metadata
    and return the concrete matching indicators for each category.
    """
    # IOC matching: IPs + hashes (case-insensitive for hashes)
    query_iocs = set(query_entities.ips) | {h.lower() for h in query_entities.hashes}
    chunk_iocs = set(chunk.entities.ips) | {h.lower() for h in chunk.entities.hashes}
    matching_iocs = sorted(query_iocs & chunk_iocs)

    # CVE matching (case-insensitive)
    query_cves = {c.upper() for c in query_entities.cves}
    chunk_cves = {c.upper() for c in chunk.entities.cves}
    matching_cves = sorted(query_cves & chunk_cves)

    # Malware matching: substring match of chunk malware names in the query
    # malware list. Since query_parser can't regex-extract malware names
    # (they're natural language), we check if any chunk malware name
    # appears among query_entities.malware (if provided) or do case-insensitive
    # set intersection.
    query_malware = {m.lower() for m in query_entities.malware}
    chunk_malware_lower = {m.lower(): m for m in chunk.entities.malware}
    shared_malware = sorted(
        chunk_malware_lower[m] for m in chunk_malware_lower if m in query_malware
    )

    # MITRE technique matching (exact ID match)
    query_mitre = set(query_entities.mitre_techniques)
    chunk_mitre = set(chunk.entities.mitre_techniques)
    matching_mitre = sorted(query_mitre & chunk_mitre)

    return FeatureAttribution(
        matching_iocs=matching_iocs,
        matching_cves=matching_cves,
        shared_malware=shared_malware,
        matching_mitre_techniques=matching_mitre,
    )
