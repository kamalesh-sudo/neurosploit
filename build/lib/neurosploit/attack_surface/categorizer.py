"""Aggregate classification results."""
from __future__ import annotations

from collections import Counter
from typing import Dict


def summarize_classifications(classifications: Dict[str, str]) -> Dict[str, object]:
    counter = Counter(classifications.values())
    top_categories = counter.most_common()
    return {
        "counts": dict(counter),
        "top": top_categories,
        "high_risk": [endpoint for endpoint, category in classifications.items() if category != "General API"],
    }
