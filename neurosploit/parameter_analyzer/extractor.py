"""Parameter extraction helpers."""
from __future__ import annotations

import json
import re
from typing import Dict, Iterable, List
from urllib.parse import parse_qs, urlparse

PARAM_PATTERN = re.compile(r"([A-Za-z0-9_]+)=([A-Za-z0-9_-]+)")


def extract_parameters(sources: Iterable[str]) -> List[Dict[str, str]]:
    """Extract key/value pairs from URLs or query strings."""
    params: List[Dict[str, str]] = []
    for item in sources:
        if not item:
            continue
        parsed = urlparse(item)
        if parsed.query:
            for key, values in parse_qs(parsed.query).items():
                params.append({"name": key, "value": values[0]})
        for key, value in PARAM_PATTERN.findall(item):
            params.append({"name": key, "value": value})
    return params


def extract_from_json_blobs(blobs: Iterable[str]) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    for blob in blobs:
        try:
            data = json.loads(blob)
        except (json.JSONDecodeError, TypeError):
            continue
        _walk_json(data, results)
    return results


def _walk_json(obj, results: List[Dict[str, str]], prefix: str = ""):
    if isinstance(obj, dict):
        for key, value in obj.items():
            _walk_json(value, results, f"{prefix}{key}.")
    elif isinstance(obj, list):
        for item in obj:
            _walk_json(item, results, prefix)
    else:
        if prefix:
            results.append({"name": prefix.rstrip("."), "value": str(obj)})
