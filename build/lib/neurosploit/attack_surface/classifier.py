"""Endpoint attack surface classification."""
from __future__ import annotations

from typing import Dict, Optional

CATEGORY_KEYWORDS = {
    "Admin Privilege Function": ["/admin", "admin"],
    "File Upload Attack Surface": ["upload", "import"],
    "Payment Flow": ["payment", "invoice", "checkout"],
    "User Profile / PII": ["profile", "user", "account"],
    "GraphQL Endpoint": ["/graphql"],
}


def classify_endpoint(
    endpoint: str,
    method: str = "GET",
    auth_required: Optional[bool] = None,
) -> str:
    lower = endpoint.lower()
    if method.upper() in {"POST", "PUT", "DELETE"} and any(char.isdigit() for char in lower):
        return "BAC / IDOR"
    if "/graphql" in lower:
        return "GraphQL Endpoint"
    if "upload" in lower or "multipart" in lower:
        return "File Upload Attack Surface"
    if "admin" in lower:
        return "Admin Privilege Function"
    if any(keyword in lower for keyword in ["payment", "invoice", "checkout"]):
        return "Payment Flow"
    if any(keyword in lower for keyword in ["profile", "account", "user/"]):
        return "User Profile / PII"
    if auth_required is False:
        return "Public Unauthenticated Endpoint"
    if method.upper() not in {"GET", "POST"}:
        return "Unsafe HTTP Method"
    return "General API"


def classify_bulk(items: Dict[str, Dict[str, object]]) -> Dict[str, str]:
    return {
        endpoint: classify_endpoint(
            endpoint,
            method=data.get("method", "GET"),
            auth_required=data.get("auth_required"),
        )
        for endpoint, data in items.items()
    }
