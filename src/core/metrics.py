import math
from collections import defaultdict


def hit_at_k(actual: list[str], predicted: list[str], k: int) -> int:
    """Returns 1 if any of the actual items are in the top K predicted items, else 0."""
    if not actual or not predicted:
        return 0
    top_k = set(predicted[:k])
    for item in actual:
        if item in top_k:
            return 1
    return 0


def mrr_at_k(actual: list[str], predicted: list[str], k: int) -> float:
    """Calculates Mean Reciprocal Rank at K."""
    if not actual or not predicted:
        return 0.0
    actual_set = set(actual)
    for i, item in enumerate(predicted[:k]):
        if item in actual_set:
            return 1.0 / (i + 1.0)
    return 0.0


def ndcg_at_k(actual: list[str], predicted: list[str], k: int) -> float:
    """
    Calculates Normalized Discounted Cumulative Gain at K.
    Assumes binary relevance: 1 if item in actual, 0 otherwise.
    """
    if not actual or not predicted:
        return 0.0

    actual_set = set(actual)
    dcg = 0.0
    for i, item in enumerate(predicted[:k]):
        if item in actual_set:
            dcg += 1.0 / math.log2(i + 2.0)  # log2(i + 2) because i is 0-indexed

    idcg = 0.0
    # Ideal DCG is when all actual items are at the top
    num_ideal = min(len(actual_set), k)
    for i in range(num_ideal):
        idcg += 1.0 / math.log2(i + 2.0)

    if idcg == 0.0:
        return 0.0
    return dcg / idcg


def precision_recall(actual: list[str], predicted: list[str]) -> tuple[float, float]:
    """Calculates generic set-based Precision and Recall."""
    if not actual and not predicted:
        return 1.0, 1.0
    if not actual or not predicted:
        return 0.0, 0.0

    actual_set = set(actual)
    predicted_set = set(predicted)

    true_positives = len(actual_set & predicted_set)

    precision = true_positives / len(predicted_set)
    recall = true_positives / len(actual_set)

    return precision, recall


def macro_f1(actual_labels: list[str], predicted_labels: list[str], classes: list[str]) -> float:
    """
    Calculates Macro F1 score across all provided classes.
    """
    if not actual_labels or not predicted_labels or len(actual_labels) != len(predicted_labels):
        return 0.0

    f1_scores = []
    for cls in classes:
        tp = sum(1 for a, p in zip(actual_labels, predicted_labels) if a == cls and p == cls)
        fp = sum(1 for a, p in zip(actual_labels, predicted_labels) if a != cls and p == cls)
        fn = sum(1 for a, p in zip(actual_labels, predicted_labels) if a == cls and p != cls)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        if precision + recall > 0:
            f1_scores.append(2 * precision * recall / (precision + recall))
        else:
            f1_scores.append(0.0)

    if not f1_scores:
        return 0.0
    return sum(f1_scores) / len(f1_scores)


def confusion_matrix(
    actual_labels: list[str], predicted_labels: list[str], classes: list[str]
) -> dict[str, dict[str, int]]:
    """
    Generates a confusion matrix: dict[actual_class][predicted_class] = count.
    """
    matrix: dict[str, dict[str, int]] = {cls: defaultdict(int) for cls in classes}

    # Initialize all pairs to 0 so the matrix is always complete
    for cls1 in classes:
        for cls2 in classes:
            matrix[cls1][cls2] = 0

    for a, p in zip(actual_labels, predicted_labels):
        if a in matrix and p in matrix[a]:
            matrix[a][p] += 1

    return dict(matrix)
