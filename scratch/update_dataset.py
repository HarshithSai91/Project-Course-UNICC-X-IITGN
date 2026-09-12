import json
from pathlib import Path

DATASET_PATH = Path("data/golden_dataset.json")
with open(DATASET_PATH, "r", encoding="utf-8") as f:
    dataset = json.load(f)

texts = {
    "chunk_exact": "Recent intelligence indicates an attacker used CVE-2024-1234 and mitre technique T1059 from the ip address 10.0.0.1 to compromise the system.",
    "chunk_noise": "There are no known indicators of compromise here. The system is operating normally without any unusual activity.",
    "chunk_strong": "Analysis of the attack pattern shows the attacker used T1059 from 10.0.0.1, indicating a potential targeted intrusion.",
    "chunk_partial": "We observed a generic phishing campaign originating from 192.168.1.100 targeting our employees.",
    "chunk_weak": "Malware activity linked to CVE-2023-9999 has been reported in various security bulletins recently.",
    "chunk_unsupported": "Routine system update logs indicate successful patching of several minor components."
}

for case in dataset:
    for c in case["candidates"]:
        c["text"] = texts.get(c["chunk_id"], "Sample text with no particular entities.")

with open(DATASET_PATH, "w", encoding="utf-8") as f:
    json.dump(dataset, f, indent=2)

