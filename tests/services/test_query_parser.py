from src.services.query_parser import parse_query_entities


def test_extract_cves() -> None:
    result = parse_query_entities("Exploited CVE-2024-1234 and CVE-2023-44228")
    assert result.cves == ["CVE-2023-44228", "CVE-2024-1234"]


def test_extract_cves_case_insensitive() -> None:
    result = parse_query_entities("found cve-2024-5678 in logs")
    assert result.cves == ["CVE-2024-5678"]


def test_extract_ipv4() -> None:
    result = parse_query_entities("C2 beacon to 10.0.0.1 and 192.168.1.100")
    assert result.ips == ["10.0.0.1", "192.168.1.100"]


def test_extract_md5_hash() -> None:
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    result = parse_query_entities(f"hash {md5}")
    assert md5 in result.hashes


def test_extract_sha256_hash() -> None:
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    result = parse_query_entities(f"sha256: {sha256}")
    assert sha256 in result.hashes
    # Should NOT also appear as a shorter hash
    assert len(result.hashes) == 1


def test_extract_mitre_techniques() -> None:
    result = parse_query_entities("Uses T1059 and T1059.001 for execution")
    assert "T1059" in result.mitre_techniques
    assert "T1059.001" in result.mitre_techniques


def test_empty_query() -> None:
    result = parse_query_entities("")
    assert result.cves == []
    assert result.ips == []
    assert result.hashes == []
    assert result.mitre_techniques == []
    assert result.malware == []


def test_no_matches() -> None:
    result = parse_query_entities("Suspicious login attempt from unknown source")
    assert result.cves == []
    assert result.ips == []
    assert result.hashes == []
    assert result.mitre_techniques == []


def test_mixed_query() -> None:
    query = (
        "APT29 used T1059 to exploit CVE-2024-1234 from 10.0.0.1 "
        "with hash d41d8cd98f00b204e9800998ecf8427e"
    )
    result = parse_query_entities(query)
    assert result.cves == ["CVE-2024-1234"]
    assert result.ips == ["10.0.0.1"]
    assert "d41d8cd98f00b204e9800998ecf8427e" in result.hashes
    assert "T1059" in result.mitre_techniques


def test_deduplication() -> None:
    result = parse_query_entities("CVE-2024-1234 repeated CVE-2024-1234")
    assert result.cves == ["CVE-2024-1234"]
