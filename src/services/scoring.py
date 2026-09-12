def calculate_composite_score(
    ioc_score: float,
    ttp_score: float,
    semantic_score: float,
    cve_score: float
) -> float:
    """
    H-2.1: Composite Scoring Engine prototype.
    Formulation of weighted similarity: 0.35*IOC + 0.25*TTP + 0.25*Semantic + 0.15*CVE
    """
    weight_ioc = 0.35
    weight_ttp = 0.25
    weight_semantic = 0.25
    weight_cve = 0.15
    
    # Ensure weights sum to 1.0
    # 0.35 + 0.25 + 0.25 + 0.15 = 1.00
    
    composite = (
        (ioc_score * weight_ioc) +
        (ttp_score * weight_ttp) +
        (semantic_score * weight_semantic) +
        (cve_score * weight_cve)
    )
    
    return round(composite, 4)
