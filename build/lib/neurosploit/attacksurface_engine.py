"""High level Attack Surface Engine orchestrating the five modules."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urljoin

import requests

from .fingerprinting import (
    fingerprint_cookies,
    fingerprint_headers,
    identify_from_favicon,
)
from .js_extractor import fetch_js_assets, extract_endpoints_from_js, filter_endpoints
from .parameter_analyzer import extract_parameters, score_parameters, detect_roles
from .attack_surface import classify_bulk, summarize_classifications
from .risk_ai import build_features, score_features


@dataclass
class AttackSurfaceResult:
    backend_fingerprint: Dict[str, object]
    endpoint_extraction: Dict[str, object]
    parameter_discovery: Dict[str, object]
    attack_surface: Dict[str, object]
    risk_scores: List[Dict[str, object]]


class AttackSurfaceEngine:
    def __init__(self, target_url: str, session: Optional[requests.Session] = None):
        if not target_url.startswith("http"):
            target_url = f"https://{target_url}"
        self.target_url = target_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.update(
            {
                "User-Agent": "NeuroSploit/2.0 (+https://github.com/iharishragav/neurosploit)",
            }
        )

    def fingerprint_backend(self) -> Dict[str, object]:
        response = self.session.get(self.target_url, timeout=20)
        header_hits = fingerprint_headers(response.headers)
        cookie_hits = fingerprint_cookies(response.headers.get("set-cookie"))
        favicon_match = None
        try:
            favicon_resp = self.session.get(urljoin(self.target_url, "/favicon.ico"), timeout=10)
            if favicon_resp.ok:
                favicon_match = identify_from_favicon(favicon_resp.content)
        except requests.RequestException:
            favicon_match = None

        detections = header_hits + cookie_hits
        if favicon_match:
            detections.append(favicon_match)

        backend_label = None
        confidence = 0.0
        if detections:
            backend_label = detections[0]["label"]
            confidence = 0.5 + (0.1 * (len(detections) - 1))
            confidence = min(confidence, 0.95)

        return {
            "backend": backend_label,
            "confidence": round(confidence, 2),
            "detected_from": [hit["source"] for hit in detections],
            "raw": detections,
        }

    def extract_js_endpoints(self) -> Dict[str, object]:
        assets = fetch_js_assets(self.target_url, session=self.session)
        raw_endpoints: List[str] = []
        method_hints: List[str] = []
        for asset in assets:
            raw_endpoints.extend(extract_endpoints_from_js(asset.content))
        filtered = filter_endpoints(raw_endpoints)
        return {
            "endpoints": filtered,
            "metadata": {
                "total_js_files": len(assets),
                "extracted": len(raw_endpoints),
                "filtered": len(filtered),
            },
        }

    def discover_parameters(self, endpoints: List[str]) -> Dict[str, object]:
        params = extract_parameters(endpoints)
        scored = score_parameters(params)
        roles = detect_roles(endpoints)
        return {
            "sensitive_params": scored[:20],
            "role_indicators": roles,
        }

    def classify_attack_surface(self, endpoints: List[str]) -> Dict[str, object]:
        endpoint_map = {endpoint: {"method": "GET"} for endpoint in endpoints}
        classifications = classify_bulk(endpoint_map)
        summary = summarize_classifications(classifications)
        return {
            "classification": classifications,
            "summary": summary,
        }

    def score_risks(
        self,
        endpoints: List[str],
        classifications: Dict[str, str],
        backend_label: Optional[str],
    ) -> List[Dict[str, object]]:
        results = []
        for endpoint in endpoints:
            classification = classifications.get(endpoint, "General API")
            features = build_features(endpoint, "GET", classification, backend_label)
            risk_score = score_features(features)
            results.append(
                {
                    "endpoint": endpoint,
                    "risk_score": round(risk_score, 2),
                    "high_risk_reason": [key for key, value in features.items() if value >= 0.9],
                    "classification": classification,
                }
            )
        results.sort(key=lambda item: item["risk_score"], reverse=True)
        return results

    def run_full_analysis(self) -> AttackSurfaceResult:
        backend = self.fingerprint_backend()
        endpoints_data = self.extract_js_endpoints()
        endpoints = endpoints_data["endpoints"]
        params = self.discover_parameters(endpoints)
        attack_surface = self.classify_attack_surface(endpoints)
        risk_scores = self.score_risks(
            endpoints,
            attack_surface["classification"],
            backend.get("backend"),
        )
        return AttackSurfaceResult(
            backend_fingerprint=backend,
            endpoint_extraction=endpoints_data,
            parameter_discovery=params,
            attack_surface=attack_surface,
            risk_scores=risk_scores,
        )
