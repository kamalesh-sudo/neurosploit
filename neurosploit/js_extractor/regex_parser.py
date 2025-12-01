"""Regex helpers for extracting endpoints from JavaScript."""
from __future__ import annotations

import re
from typing import Iterable, List, Set

ENDPOINT_REGEXES = [
    re.compile(r"/api/[A-Za-z0-9_\-/]+"),
    re.compile(r"https?://[A-Za-z0-9._:-]+/[A-Za-z0-9_\-/]+"),
]

METHOD_HINT_REGEX = re.compile(r"(GET|POST|PUT|DELETE|PATCH)\s*['\"](.*?)['\"]", re.IGNORECASE)


def extract_endpoints_from_js(content: str) -> Set[str]:
    matches: Set[str] = set()
    for regex in ENDPOINT_REGEXES:
        matches.update(regex.findall(content))
    return matches


def guess_methods(content: str) -> List[str]:
    return [match[0].upper() for match in METHOD_HINT_REGEX.findall(content)]
