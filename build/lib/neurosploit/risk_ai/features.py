"""Feature engineering for AI-based risk scoring."""
from __future__ import annotations

from typing import Dict


def build_features(
    endpoint: str,
    method: str,
    classification: str,
    framework: str | None,
) -> Dict[str, float]:
    lower = endpoint.lower()
    features = {
        "idor_feats": 1.0 if any(char.isdigit() for char in lower) else 0.0,
        "auth_feats": 1.0 if "auth" in lower or "token" in lower else 0.0,
        "framework_risk": 0.5 if framework in {"Laravel", "Express"} else 0.2,
        "endpoint_complexity": min(len(endpoint) / 50.0, 1.0),
    }
    if classification == "Admin Privilege Function":
        features["auth_feats"] = 1.0
    if "upload" in lower:
        features["endpoint_complexity"] = 1.0
    return features
