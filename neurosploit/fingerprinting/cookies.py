"""Cookie-based backend fingerprinting helpers."""
from __future__ import annotations

from http.cookies import SimpleCookie
from typing import Dict, List

CookieHit = Dict[str, str]

COOKIE_SIGNATURES = {
    "laravel_session": "Laravel",
    "ci_session": "CodeIgniter",
    "jsessionid": "Java",
    "sessionid": "Django",
    "csrftoken": "Django",
    "wordpress_logged_in": "WordPress",
}


def fingerprint_cookies(cookie_header: str | Dict[str, str] | None) -> List[CookieHit]:
    """Return cookie-based framework matches."""
    if not cookie_header:
        return []

    jar = SimpleCookie()
    if isinstance(cookie_header, str):
        jar.load(cookie_header)
    else:
        for key, value in cookie_header.items():
            jar[key] = value

    hits: List[CookieHit] = []
    for morsel in jar.values():
        name = morsel.key.lower()
        label = COOKIE_SIGNATURES.get(name)
        if label:
            hits.append({
                "source": f"cookie.{name}",
                "value": morsel.value,
                "label": label,
            })
    return hits
