"""Filter and prioritize extracted endpoints."""
from __future__ import annotations

from typing import Iterable, List, Set
from urllib.parse import urlparse

PRIORITY_KEYWORDS = [
    "id",
    "user",
    "admin",
    "profile",
    "cart",
    "invoice",
]

TRACKING_KEYWORDS = [
    "google-analytics",
    "segment",
    "optimizely",
    "datadog",
]

STATIC_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css")


def normalize_endpoint(endpoint: str) -> str:
    parsed = urlparse(endpoint)
    if parsed.scheme:
        return parsed.path or "/"
    return endpoint


def filter_endpoints(endpoints: Iterable[str]) -> List[str]:
    unique: Set[str] = set()
    prioritized: List[str] = []

    for endpoint in endpoints:
        lower = endpoint.lower()
        if any(token in lower for token in TRACKING_KEYWORDS):
            continue
        if lower.endswith(STATIC_EXTENSIONS):
            continue
        normalized = normalize_endpoint(endpoint)
        if normalized in unique:
            continue
        unique.add(normalized)
        prioritized.append(normalized)

    prioritized.sort(key=lambda ep: _priority_score(ep), reverse=True)
    return prioritized


def _priority_score(endpoint: str) -> int:
    score = 0
    for keyword in PRIORITY_KEYWORDS:
        if keyword in endpoint.lower():
            score += 10
    if any(char.isdigit() for char in endpoint):
        score += 5
    if "upload" in endpoint.lower() or "delete" in endpoint.lower():
        score += 5
    return score
