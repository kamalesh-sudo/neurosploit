"""Target parsing and validation utilities."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

DOMAIN_PATTERN = re.compile(r"^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)
SUBDOMAIN_LABEL_PATTERN = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)


def normalize_domain(value: str) -> str:
    candidate = (value or "").strip().lower()
    if not candidate:
        return ""

    if "://" in candidate:
        parsed = urlsplit(candidate)
        candidate = parsed.netloc or parsed.path

    candidate = candidate.split("/", 1)[0]
    candidate = candidate.split("?", 1)[0]
    candidate = candidate.split("#", 1)[0]

    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[-1]

    candidate = candidate.lstrip("*.").rstrip(".")
    if ":" in candidate:
        host, _, port = candidate.rpartition(":")
        if host and port.isdigit():
            candidate = host

    return candidate


def is_valid_domain(value: str) -> bool:
    return bool(value) and len(value) <= 253 and DOMAIN_PATTERN.fullmatch(value) is not None
