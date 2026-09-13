def classify_threat_confidence(composite_score: float) -> str:
    """
    H-2.2: 5-Tier Confidence Classifier.
    Threshold gating based on the composite score.
    EXACT (>= 0.95)
    STRONG (0.80-0.94)
    PARTIAL (0.55-0.79)
    WEAK (0.30-0.54)  # Assumed boundary based on remaining scale
    UNSUPPORTED (< 0.30) # Assumed boundary based on remaining scale
    """
    if composite_score >= 0.95:
        return "EXACT"
    elif composite_score >= 0.80:
        return "STRONG"
    elif composite_score >= 0.55:
        return "PARTIAL"
    elif composite_score >= 0.30:
        return "WEAK"
    else:
        return "UNSUPPORTED"
