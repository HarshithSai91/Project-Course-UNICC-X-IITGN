"""
H-2 Query Entity Parser.

Extracts structured threat indicators from raw query text using regex.
No ML dependencies — pattern matching only.
"""

import re

from src.contracts.chunk_schema import CyberEntities, IOCEntities

# Compiled patterns for performance
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
_MITRE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def parse_query_entities(query: str) -> CyberEntities:
    """
    Extract structured entities from a threat query string.

    Returns CyberEntities aligned with upstream validator.py contract.
    """
    cves = sorted({m.upper() for m in _CVE_PATTERN.findall(query)})
    ips = sorted(set(_IPV4_PATTERN.findall(query)))

    sha256 = set(_SHA256_PATTERN.findall(query))
    sha1 = set(_SHA1_PATTERN.findall(query)) - sha256
    md5 = set(_MD5_PATTERN.findall(query)) - sha256 - sha1
    hashes = sorted(h.lower() for h in sha256 | sha1 | md5)

    mitre = sorted(set(_MITRE_PATTERN.findall(query)))

    return CyberEntities(
        cves=cves,
        iocs=IOCEntities(
            ipv4=ips,
            md5=sorted(h for h in hashes if len(h) == 32),
            sha256=sorted(h for h in hashes if len(h) == 64),
            # Note: sha1 (40 chars) not explicitly tracked in IOCEntities; map to md5 or ignore for simplicity
        ),
        mitre_ttps=mitre,
    )
