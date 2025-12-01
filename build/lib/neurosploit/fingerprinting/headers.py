"""Utilities for fingerprinting backend frameworks via HTTP headers."""
from __future__ import annotations

from typing import Dict, List

HeaderHit = Dict[str, str]

# (header_name, lowercase signature, label)
HEADER_SIGNATURES = [
    ("x-powered-by", "laravel", "Laravel"),
    ("x-powered-by", "express", "Express"),
    ("x-powered-by", "next.js", "Next.js"),
    ("x-powered-by", "php", "PHP"),
    ("server", "gunicorn", "Django"),
    ("server", "werkzeug", "Flask"),
    ("server", "apache", "PHP / Apache"),
    ("server", "iis", "IIS / .NET"),
    ("x-runtime", "", "Rails"),
    ("x-drupal-cache", "", "Drupal"),
    ("x-laravel-session", "", "Laravel"),
]


def fingerprint_headers(headers: Dict[str, str]) -> List[HeaderHit]:
    """Return header-based fingerprint hits."""
    if not headers:
        return []
    normalized = {k.lower(): v for k, v in headers.items()}

    hits: List[HeaderHit] = []
    for header_name, needle, label in HEADER_SIGNATURES:
        value = normalized.get(header_name)
        if not value:
            continue
        if needle:
            if needle in value.lower():
                hits.append({
                    "source": f"header.{header_name}",
                    "value": value,
                    "label": label,
                })
        else:
            hits.append({
                "source": f"header.{header_name}",
                "value": value,
                "label": label,
            })
    return hits
