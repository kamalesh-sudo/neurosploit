"""Heuristic sensitivity scoring for parameters."""
from __future__ import annotations

from typing import Dict, Iterable, List

SENSITIVE_KEYWORDS = [
    "id",
    "uid",
    "pid",
    "role",
    "type",
    "permission",
    "file",
    "owner",
    "org",
    "group",
    "isadmin",
    "amount",
    "price",
]


def score_parameters(params: Iterable[Dict[str, str]]) -> List[Dict[str, object]]:
    scored: List[Dict[str, object]] = []
    counts = {}
    for param in params:
        name = param["name"].lower()
        counts[name] = counts.get(name, 0) + 1

    for param in params:
        name = param["name"].lower()
        score = 10
        if any(keyword in name for keyword in SENSITIVE_KEYWORDS):
            score += 40
        if any(char.isdigit() for char in param.get("value", "")):
            score += 20
        if counts[name] > 1:
            score += 20
        if "true" in param.get("value", "").lower() or "false" in param.get("value", "").lower():
            score += 10
        scored.append({"param": param["name"], "value": param.get("value"), "score": min(score, 100)})
    scored.sort(key=lambda item: item["score"], reverse=True)
    return scored
