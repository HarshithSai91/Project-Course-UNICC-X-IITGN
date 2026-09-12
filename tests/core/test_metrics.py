from src.core.metrics import (
    confusion_matrix,
    hit_at_k,
    macro_f1,
    mrr_at_k,
    ndcg_at_k,
    precision_recall,
)


def test_hit_at_k() -> None:
    assert hit_at_k(["A", "B"], ["C", "A", "D"], 2) == 1
    assert hit_at_k(["A", "B"], ["C", "D", "A"], 2) == 0
    assert hit_at_k([], ["A"], 5) == 0
    assert hit_at_k(["A"], [], 5) == 0


def test_mrr_at_k() -> None:
    # Match at rank 1 (index 0)
    assert mrr_at_k(["A"], ["A", "B", "C"], 3) == 1.0
    # Match at rank 2 (index 1)
    assert mrr_at_k(["A"], ["B", "A", "C"], 3) == 0.5
    # Match beyond k
    assert mrr_at_k(["A"], ["B", "C", "A"], 2) == 0.0
    # Empty cases
    assert mrr_at_k([], ["A"], 5) == 0.0


def test_ndcg_at_k() -> None:
    # Perfect ranking
    assert ndcg_at_k(["A", "B"], ["A", "B", "C"], 2) == 1.0
    
    # 0 NDCG
    assert ndcg_at_k(["Z"], ["A", "B", "C"], 3) == 0.0

    # Partial ranking: 'A' at index 0, 'B' missing
    # DCG = 1/log2(2) = 1.0
    # IDCG = 1/log2(2) + 1/log2(3) ≈ 1.0 + 0.6309 = 1.6309
    # NDCG ≈ 1.0 / 1.6309 ≈ 0.6131
    ndcg = ndcg_at_k(["A", "B"], ["A", "C", "D"], 3)
    assert abs(ndcg - 0.6131) < 0.001


def test_precision_recall() -> None:
    p, r = precision_recall(["A", "B"], ["A", "C"])
    assert p == 0.5  # 1 true positive / 2 predicted
    assert r == 0.5  # 1 true positive / 2 actual

    p, r = precision_recall(["A", "B"], ["A", "B", "C"])
    assert p == 2.0 / 3.0
    assert r == 1.0

    # Edge cases
    assert precision_recall([], []) == (1.0, 1.0)
    assert precision_recall(["A"], []) == (0.0, 0.0)


def test_macro_f1() -> None:
    actual = ["EXACT", "STRONG", "PARTIAL", "EXACT"]
    predicted = ["EXACT", "STRONG", "WEAK", "STRONG"]
    classes = ["EXACT", "STRONG", "PARTIAL", "WEAK"]

    # EXACT: tp=1, fp=0, fn=1 -> P=1.0, R=0.5 -> F1=0.666
    # STRONG: tp=1, fp=1, fn=0 -> P=0.5, R=1.0 -> F1=0.666
    # PARTIAL: tp=0, fp=0, fn=1 -> P=0.0, R=0.0 -> F1=0.0
    # WEAK: tp=0, fp=1, fn=0 -> P=0.0, R=0.0 -> F1=0.0
    # Macro F1 = (0.666 + 0.666 + 0 + 0) / 4 ≈ 0.333
    f1 = macro_f1(actual, predicted, classes)
    assert abs(f1 - 0.333) < 0.01

    assert macro_f1([], [], classes) == 0.0


def test_confusion_matrix() -> None:
    actual = ["EXACT", "STRONG", "STRONG"]
    predicted = ["EXACT", "EXACT", "STRONG"]
    classes = ["EXACT", "STRONG"]

    matrix = confusion_matrix(actual, predicted, classes)
    
    assert matrix["EXACT"]["EXACT"] == 1
    assert matrix["EXACT"]["STRONG"] == 0
    assert matrix["STRONG"]["EXACT"] == 1
    assert matrix["STRONG"]["STRONG"] == 1
