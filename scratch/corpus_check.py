import json
from pathlib import Path
import sys
sys.path.insert(0, ".")
from src.contracts.chunk_schema import EntitySchema, RankedChunk, ThreatChunk
from datetime import UTC, datetime

DATASET_PATH = Path("data/golden_dataset.json")
with open(DATASET_PATH, "r", encoding="utf-8") as f:
    dataset = json.load(f)

corpus = []
seen = set()
for case in dataset:
    for c in case["candidates"]:
        if c["chunk_id"] not in seen:
            seen.add(c["chunk_id"])
            corpus.append(c)
print(f"Total unique chunks: {len(corpus)}")
