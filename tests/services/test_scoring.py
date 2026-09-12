from src.services.scoring import calculate_composite_score


def test_calculate_composite_score() -> None:
    # Test with perfect scores
    score = calculate_composite_score(1.0, 1.0, 1.0, 1.0)
    assert score == 1.0
    
    # Test with partial scores
    score = calculate_composite_score(0.8, 0.5, 0.9, 0.0)
    # Expected: 0.8*0.35(0.28) + 0.5*0.25(0.125) + 0.9*0.25(0.225) + 0.0(0) = 0.63
    assert score == 0.63
    
    # Test zero scores
    score = calculate_composite_score(0.0, 0.0, 0.0, 0.0)
    assert score == 0.0
