"""Identify frameworks using favicon mmh3 hashes."""
from __future__ import annotations

from typing import Dict, Optional, Tuple

import mmh3

# Sample mapping of known favicon hashes to frameworks.
FAVICON_HASHES: Dict[int, Tuple[str, float]] = {
    -247388890: ("Laravel", 0.65),
    -1583478053: ("Express", 0.6),
    782980657: ("Django", 0.6),
    -1372627186: ("Next.js", 0.55),
}


def identify_from_favicon(content: bytes) -> Optional[Dict[str, str | float]]:
    """Return a match dict if favicon hash is known."""
    if not content:
        return None
    hash_value = mmh3.hash(content)
    match = FAVICON_HASHES.get(hash_value)
    if not match:
        return None
    label, confidence = match
    return {
        "source": "favicon_hash",
        "value": str(hash_value),
        "label": label,
        "confidence": confidence,
    }
