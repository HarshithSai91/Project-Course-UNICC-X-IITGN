import json

queries = [
    ("case_1_exact", "Attacker used CVE-2024-1234 and T1059 from 10.0.0.1", "EXACT", "chunk_exact"),
    ("case_2_strong", "Attacker used T1059 from 10.0.0.1", "STRONG", "chunk_strong"),
    ("case_3_partial", "Generic phishing campaign from 192.168.1.100", "PARTIAL", "chunk_partial"),
    ("case_4_weak", "Malware activity linked to CVE-2023-9999", "WEAK", "chunk_weak"),
    ("case_5_unsupported", "Routine system update logs", "UNSUPPORTED", "chunk_unsupported")
]

# We need distractors.
# We want distractors with high keyword overlap but low semantic overlap (hard to do without word embeddings, but maybe different word order or different entities).
# Actually, TF-IDF cosine similarity and Unigram Jaccard overlap are highly correlated.
# To make them produce different rankings, we can have a distractor that has a subset of exact words (high Jaccard) but different length, or repeated words (TF cosine similarity favors repeated words, while Jaccard ignores term frequency).
# Example: Query = "A B C". 
# Distractor 1 (Lexical bias): "A A A A B" -> Jaccard(set(A,B), set(A,B,C)) = 2/3 = 0.66. Cosine: [4, 1, 0] vs [1, 1, 1]. Dot=5, Mag=sqrt(17)*sqrt(3)=7.14 -> 5/7.14 = 0.70.
# Let's just create generic distractors to populate the corpus so it has 15-20 chunks.

base_chunks = {
    "chunk_exact": {
        "cves": ["CVE-2024-1234"], "mitre_techniques": ["T1059"], "ips": ["10.0.0.1"],
        "text": "Attacker used CVE-2024-1234 and T1059 from 10.0.0.1"
    },
    "chunk_strong": {
        "cves": [], "mitre_techniques": ["T1059"], "ips": ["10.0.0.1"],
        "text": "Attacker used T1059 from 10.0.0.1"
    },
    "chunk_partial": {
        "cves": [], "mitre_techniques": [], "ips": ["192.168.1.100"],
        "text": "Generic phishing campaign from 192.168.1.100"
    },
    "chunk_weak": {
        "cves": ["CVE-2023-9999"], "mitre_techniques": [], "ips": [],
        "text": "Malware activity linked to CVE-2023-9999"
    },
    "chunk_unsupported": {
        "cves": [], "mitre_techniques": [], "ips": [],
        "text": "Routine system update logs"
    }
}

distractors = {
    f"distractor_{i}": {
        "cves": [], "mitre_techniques": [], "ips": [],
        "text": text
    } for i, text in enumerate([
        "There is no malicious activity detected on the network today.",
        "The firewall blocked a connection from an unknown IP address.",
        "System administrator logged in to perform routine maintenance.",
        "An old vulnerability CVE-2021-0001 was discussed in the meeting.",
        "Suspicious PowerShell execution observed but blocked by AV.",
        "Generic malware activity linked to an unknown source.",
        "Phishing emails have been a problem for the generic user base.",
        "System update logs show successful patches applied.",
        "The attacker did not use any known techniques from the MITRE framework.",
        "We observed a connection from 10.0.0.2 which is a trusted internal IP.",
        "Malware campaign uses T1059 but not from the suspected IP.",
        "Update logs for the Linux servers are available in the central repository.",
        "Security update for CVE-2024-1234 was applied successfully.",
        "Attacker used T1059 from a different IP address 10.0.0.5."
    ])
}

# Distractor designed to trick keyword (Jaccard) but maybe vector (Cosine) handles it differently due to term frequency
distractors["distractor_kw_trap"] = {
    "cves": [], "mitre_techniques": [], "ips": [],
    "text": "Attacker attacker attacker used used used" # Jaccard: {attacker, used} overlaps with query. 
}

# Distractor designed to trick vector (Cosine) but not Jaccard
distractors["distractor_vec_trap"] = {
    "cves": [], "mitre_techniques": [], "ips": [],
    "text": "attacker used from"
}

all_chunks = {**base_chunks, **distractors}

dataset = []
for cid, query, tier, expected in queries:
    case = {
        "id": cid,
        "query": query,
        "expected_top_chunk": expected,
        "expected_tier": tier,
        "candidates": []
    }
    # Add ALL chunks to EVERY case so it's a true global corpus
    for chunk_id, data in all_chunks.items():
        case["candidates"].append({
            "chunk_id": chunk_id,
            "entities": {
                "cves": data["cves"],
                "mitre_techniques": data["mitre_techniques"],
                "ips": data["ips"],
                "hashes": [],
                "malware": []
            },
            "text": data["text"]
        })
    dataset.append(case)

with open("data/golden_dataset.json", "w", encoding="utf-8") as f:
    json.dump(dataset, f, indent=2)

