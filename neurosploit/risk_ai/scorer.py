"""Apply weighted scoring formula."""
from __future__ import annotations

from typing import Dict

WEIGHTS = {
    "idor_feats": 0.4,
    "auth_feats": 0.3,
    "framework_risk": 0.1,
    "endpoint_complexity": 0.2,
}


def score_features(features: Dict[str, float]) -> float:
    return sum(features.get(name, 0.0) * weight for name, weight in WEIGHTS.items())
