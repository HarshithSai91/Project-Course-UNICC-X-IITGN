import sys
from pathlib import Path
sys.path.insert(0, ".")
from src.services.scoring import calculate_composite_score
from src.services.classifier import classify_threat_confidence

cases = [
    ("exact", 1.0, 1.0, 1.0, 1.0, "EXACT"),
    ("strong", 1.0, 1.0, 1.0, 0.0, "STRONG"),
    ("partial", 1.0, 0.0, 1.0, 0.0, "PARTIAL"),
    ("weak", 0.0, 0.0, 1.0, 1.0, "WEAK"),
    ("unsupported", 0.0, 0.0, 1.0, 0.0, "UNSUPPORTED")
]

for name, ioc, ttp, semantic, cve, expected in cases:
    score = calculate_composite_score(ioc, ttp, semantic, cve)
    tier = classify_threat_confidence(score)
    print(f"{name}: score={score}, tier={tier} (expected {expected})")
