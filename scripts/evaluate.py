#!/usr/bin/env python3
import asyncio
import json
import math
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.contracts.chunk_schema import EntitySchema, RankedChunk, ThreatChunk
from src.core.metrics import (
    confusion_matrix,
    hit_at_k,
    macro_f1,
    mrr_at_k,
    ndcg_at_k,
)
from src.services.pipeline import run_threat_match_pipeline

DATASET_PATH = Path(__file__).parent.parent / "data" / "golden_dataset.json"

TARGET_NDCG = 0.85
TARGET_MRR = 0.80
TARGET_LATENCY_MS = 200.0


def _build_threat_chunk(candidate_data: dict[str, Any]) -> ThreatChunk:
    entities_data = candidate_data.get("entities", {})
    entities = EntitySchema(
        cves=entities_data.get("cves", []),
        mitre_techniques=entities_data.get("mitre_techniques", []),
        ips=entities_data.get("ips", []),
        hashes=entities_data.get("hashes", []),
        malware=entities_data.get("malware", []),
    )
    return ThreatChunk(
        chunk_id=candidate_data["chunk_id"],
        doc_id=f"doc_{candidate_data['chunk_id']}",
        doc_title="Test Doc",
        source_org="Eval",
        published_date=datetime.now(UTC),
        page_number=1,
        section_header="Eval",
        text=candidate_data.get("text", "Eval text"),
        entities=entities,
    )


def _get_words(text: str) -> set[str]:
    return set(text.lower().split())


def _keyword_score(query: str, text: str) -> float:
    """Keyword-only lexical baseline using unigram Jaccard overlap."""
    qw = _get_words(query)
    cw = _get_words(text)
    if not qw and not cw:
        return 0.0
    return len(qw & cw) / (len(qw | cw) + 1e-6)


def _vector_cosine_score(query: str, text: str) -> float:
    """
    Deterministic semantic/vector proxy baseline.
    Uses character 3-gram TF vectors and computes cosine similarity.
    This independently calculates semantic similarity without relying on ground-truth labels.
    """
    q_lower = query.lower()
    t_lower = text.lower()
    
    q3 = [q_lower[i:i+3] for i in range(max(1, len(q_lower)-2))]
    c3 = [t_lower[i:i+3] for i in range(max(1, len(t_lower)-2))]
    
    vec_q = Counter(q3)
    vec_c = Counter(c3)
    
    intersection = set(vec_q.keys()) & set(vec_c.keys())
    dot_product = sum(vec_q[x] * vec_c[x] for x in intersection)
    
    mag_q = math.sqrt(sum(v**2 for v in vec_q.values()))
    mag_c = math.sqrt(sum(v**2 for v in vec_c.values()))
    
    if mag_q * mag_c == 0:
        return 0.0
    return dot_product / (mag_q * mag_c)


class MockRetrievalCorpus:
    def __init__(self, dataset: list[dict[str, Any]]):
        self.corpus: dict[str, ThreatChunk] = {}
        # Ensure we construct the global corpus completely agnostic of queries or expected labels
        for case in dataset:
            for cand in case["candidates"]:
                cid = cand["chunk_id"]
                if cid not in self.corpus:
                    self.corpus[cid] = _build_threat_chunk(cand)

    def retrieve(self, query: str, strategy: str, top_k: int = 50) -> list[RankedChunk]:
        scored_chunks = []
        
        # Independently score ALL chunks in the corpus for the given query
        for chunk in self.corpus.values():
            kw = _keyword_score(query, chunk.text)
            vec = _vector_cosine_score(query, chunk.text)
            
            if strategy == "keyword":
                bm25 = kw
                semantic = 0.0
                final_score = bm25
            elif strategy == "vector":
                bm25 = 0.0
                semantic = vec
                final_score = semantic
            else: # hybrid
                # Weighted hybrid retrieval (Not RRF)
                bm25 = kw
                semantic = vec
                final_score = bm25 * 0.5 + semantic * 0.5
                
            scored_chunks.append((final_score, bm25, semantic, chunk))
            
        scored_chunks.sort(key=lambda x: x[0], reverse=True)
        
        return [
            RankedChunk(
                chunk=chunk,
                vector_score=semantic,
                bm25_score=bm25,
                rrf_score=final,
                reranker_score=semantic, # Used downstream by the classifier pipeline
                stix_relationships=[],
                is_stitched=False
            )
            for final, bm25, semantic, chunk in scored_chunks[:top_k]
        ]


async def evaluate_pipeline(dataset: list[dict[str, Any]]) -> None:
    print("Starting Phase 5 Evaluation...")

    corpus_mock = MockRetrievalCorpus(dataset)
    print(f"Loaded global evaluation corpus with {len(corpus_mock.corpus)} unique chunks.")

    # 1. Evaluate Retrieval Baselines
    retrieval_results: dict[str, list[list[str]]] = {"keyword": [], "vector": [], "hybrid": []}
    actual_retrieval_targets = []
    
    for case in dataset:
        query = case["query"]
        expected_top_chunk = case["expected_top_chunk"]
        
        # Ground-truth labels are ONLY used here for evaluation comparison
        actual_retrieval_targets.append([expected_top_chunk])
        
        for strategy in ["keyword", "vector", "hybrid"]:
            # Retrieve enough candidates to calculate @10 metrics
            ranked = corpus_mock.retrieve(query, strategy, top_k=10)
            retrieval_results[strategy].append([r.chunk.chunk_id for r in ranked])

    print("\n" + "="*50)
    print("RETRIEVAL BASELINE COMPARISON")
    print("="*50)
    print(f"{'Strategy':<15} | {'Hit@3':<8} | {'MRR@10':<8} | {'NDCG@10':<8}")
    print("-" * 50)
    
    for strategy, display_name in [
        ("keyword", "Keyword-only"), 
        ("vector", "Vector-only"), 
        ("hybrid", "Hybrid")
    ]:
        preds = retrieval_results[strategy]
        
        # Calculate @3 and @10 using actual correct k parameters
        hit = sum(hit_at_k(act, p, 3) for act, p in zip(actual_retrieval_targets, preds)) / len(preds)
        mrr = sum(mrr_at_k(act, p, 10) for act, p in zip(actual_retrieval_targets, preds)) / len(preds)
        ndcg = sum(ndcg_at_k(act, p, 10) for act, p in zip(actual_retrieval_targets, preds)) / len(preds)
        
        print(f"{display_name:<15} | {hit:<8.4f} | {mrr:<8.4f} | {ndcg:<8.4f}")

    # 2. Evaluate Full Threat Matching Pipeline
    print("\n" + "="*50)
    print("PIPELINE CLASSIFICATION EVALUATION")
    print("="*50)

    actual_tiers = []
    predicted_tiers = []
    latencies = []

    for case in dataset:
        query = case["query"]
        expected_tier = case["expected_tier"]

        async def mock_hybrid(q: str, k: int) -> list[RankedChunk]:
            return corpus_mock.retrieve(q, "hybrid", top_k=k)

        result = await run_threat_match_pipeline(
            query=query, top_k=5, retrieval_fn=mock_hybrid
        )

        latencies.append(result.pipeline_profile.total_ms)

        predicted_tier = result.top_matches[0].confidence_tier if result.top_matches else "UNSUPPORTED"
        actual_tiers.append(expected_tier)
        predicted_tiers.append(predicted_tier)

    classes = ["EXACT", "STRONG", "PARTIAL", "WEAK", "UNSUPPORTED"]
    f1 = macro_f1(actual_tiers, predicted_tiers, classes)
    cm = confusion_matrix(actual_tiers, predicted_tiers, classes)

    print(f"\nMacro F1: {f1:.4f}")
    print("\nConfusion Matrix (Actual \\ Predicted):")
    print(" " * 14 + "".join([f"{c[:3]:>5}" for c in classes]))
    for cls in classes:
        print(f"{cls:<13} " + "".join([f"{cm[cls][p]:>5}" for p in classes]))

    p95_latency = sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0.0
    print("\nPerformance:")
    print(f"P95 Latency: {p95_latency:.2f} ms (Target: <={TARGET_LATENCY_MS} ms)")
    
    print("\n" + "="*50)

    # --- Assert Quality Gates ---
    # We use Hybrid as the system's active retrieval baseline
    hybrid_preds = retrieval_results["hybrid"]
    hybrid_ndcg = sum(ndcg_at_k(act, p, 10) for act, p in zip(actual_retrieval_targets, hybrid_preds)) / len(hybrid_preds)
    hybrid_mrr = sum(mrr_at_k(act, p, 10) for act, p in zip(actual_retrieval_targets, hybrid_preds)) / len(hybrid_preds)

    passed = True
    if hybrid_ndcg < TARGET_NDCG:
        print(f"❌ FAILED: Hybrid NDCG@10 {hybrid_ndcg:.4f} is below target {TARGET_NDCG}")
        passed = False
    if hybrid_mrr < TARGET_MRR:
        print(f"❌ FAILED: Hybrid MRR@10 {hybrid_mrr:.4f} is below target {TARGET_MRR}")
        passed = False
    if p95_latency > TARGET_LATENCY_MS:
        print(f"❌ FAILED: P95 Latency {p95_latency:.2f} ms exceeds limit {TARGET_LATENCY_MS} ms")
        passed = False

    if passed:
        print("✅ ALL QUALITY GATES PASSED")
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    if not DATASET_PATH.exists():
        print(f"Dataset not found: {DATASET_PATH}")
        sys.exit(1)

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        loaded_dataset = json.load(f)

    asyncio.run(evaluate_pipeline(loaded_dataset))
