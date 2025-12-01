"""Fetch HTML + JavaScript assets for endpoint discovery."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

DEFAULT_HEADERS = {
    "User-Agent": "NeuroSploit/2.0 (+https://github.com/iharishragav/neurosploit)",
}


@dataclass
class JavaScriptAsset:
    url: str
    content: str
    status: int


def fetch_js_assets(
    base_url: str,
    session: Optional[requests.Session] = None,
    max_assets: int = 25,
) -> List[JavaScriptAsset]:
    """Fetch script tags from the landing page and return their contents."""
    sess = session or requests.Session()
    sess.headers.update(DEFAULT_HEADERS)

    response = sess.get(base_url, timeout=15, verify=False)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")
    js_urls: List[str] = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if not src:
            continue
        js_urls.append(urljoin(base_url, src))
        if len(js_urls) >= max_assets:
            break

    assets: List[JavaScriptAsset] = []
    for js_url in js_urls:
        try:
            js_resp = sess.get(js_url, timeout=20, verify=False)
            assets.append(
                JavaScriptAsset(url=js_url, content=js_resp.text, status=js_resp.status_code)
            )
        except requests.RequestException:
            continue
    return assets
