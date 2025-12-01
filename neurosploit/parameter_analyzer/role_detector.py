"""Detect privilege-sensitive contexts."""
from __future__ import annotations

from typing import Iterable, List

ROLE_KEYWORDS = [
    "admin",
    "moderator",
    "staff",
    "role",
    "permission",
    "group",
    "owner",
]


def detect_roles(endpoints: Iterable[str]) -> List[str]:
    matches: List[str] = []
    for endpoint in endpoints:
        lower = endpoint.lower()
        if any(keyword in lower for keyword in ROLE_KEYWORDS):
            matches.append(endpoint)
    return matches
