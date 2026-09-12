import json
from pathlib import Path
import sys
sys.path.insert(0, ".")
from src.contracts.chunk_schema import EntitySchema, RankedChunk, ThreatChunk
from datetime import UTC, datetime

def get_words(text):
    return set(text.lower().split())

def get_3grams(text):
    text = text.lower()
    return set([text[i:i+3] for i in range(max(1, len(text)-2))])

DATASET_PATH = Path("data/golden_dataset.json")
with open(DATASET_PATH, "r", encoding="utf-8") as f:
    dataset = json.load(f)

# build global corpus
corpus = {}
for case in dataset:
    for c in case["candidates"]:
        if c["chunk_id"] not in corpus:
            corpus[c["chunk_id"]] = c

for case in dataset:
    query = case["query"]
    expected = case["expected_top_chunk"]
    
    qw = get_words(query)
    q3 = get_3grams(query)
    
    kw_scores = []
    vec_scores = []
    
    for cid, cand in corpus.items():
        text = cand.get("text", "")
        if not text:
            text = " ".join(cand["entities"].get("cves", [])) + " " + " ".join(cand["entities"].get("mitre_techniques", [])) + " " + " ".join(cand["entities"].get("ips", []))
            
        cw = get_words(text)
        c3 = get_3grams(text)
        
        kw_score = len(qw & cw) / (len(qw | cw) + 1e-6)
        vec_score = len(q3 & c3) / (len(q3 | c3) + 1e-6)
        
        kw_scores.append((cid, kw_score))
        vec_scores.append((cid, vec_score))
        
    kw_ranked = [c for c, s in sorted(kw_scores, key=lambda x: x[1], reverse=True)]
    vec_ranked = [c for c, s in sorted(vec_scores, key=lambda x: x[1], reverse=True)]
    hybrid_ranked = [c for c, s in sorted(
        [(cid, kw + vec) for (cid, kw), (_, vec) in zip(kw_scores, vec_scores)],
        key=lambda x: x[1], reverse=True
    )]
    
    print(f"Q: {query}")
    print(f"  Expected: {expected}")
    print(f"  KW: {kw_ranked.index(expected)} (Top: {kw_ranked[0]})")
    print(f"  Vec: {vec_ranked.index(expected)} (Top: {vec_ranked[0]})")
    print(f"  Hyb: {hybrid_ranked.index(expected)} (Top: {hybrid_ranked[0]})")
