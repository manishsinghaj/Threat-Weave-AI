# modules/redirect_resolver.py
# -------------------------------------------------------------------
# Redirect resolver derived from resolve_httpx.py (lightweight version)
# -------------------------------------------------------------------

from __future__ import annotations
import re
import time
from typing import Optional, List
from urllib.parse import urljoin, urlsplit, parse_qs, unquote

import httpx
from bs4 import BeautifulSoup

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
)

HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Referer": "https://www.google.com/",
}

TIMEOUT = 20.0
MAX_RETRIES = 2
RETRY_BACKOFF = 1.5

# Add your priority domains here if needed
PREFERRED_DOMAINS: List[str] = []


# -----------------------------------------------------
# Helper: extract ?url= / ?u= wrapper parameters
# -----------------------------------------------------
def _decode_wrapper(url: str) -> str:
    try:
        p = urlsplit(url)
        qs = parse_qs(p.query)
        for k in ("a", "url", "u", "target", "r"):
            if k in qs and qs[k]:
                return unquote(qs[k][0])
    except Exception:
        pass
    return url


# -----------------------------------------------------
# Helper: extract candidate URLs from HTML
# -----------------------------------------------------
def _find_candidates(html: str, base_url: Optional[str] = None) -> List[str]:
    soup = BeautifulSoup(html or "", "html.parser")
    cands: List[str] = []

    # anchor tags
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if base_url and not href.lower().startswith("http"):
            href = urljoin(base_url, href)
        cands.append(href)

    # meta refresh
    for meta in soup.find_all("meta"):
        if meta.get("http-equiv", "").lower() == "refresh":
            content = meta.get("content", "")
            m = re.search(r"url=(.+)", content, re.I)
            if m:
                url = m.group(1).strip().strip("'").strip('"')
                if base_url and not url.lower().startswith("http"):
                    url = urljoin(base_url, url)
                cands.append(url)

    # JS patterns
    js = html
    for pattern in (
        r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
        r'location\.href\s*=\s*["\']([^"\']+)["\']',
        r'window\.open\(["\']([^"\']+)["\']',
    ):
        for m in re.finditer(pattern, js, re.I):
            url = m.group(1)
            if base_url and not url.lower().startswith("http"):
                url = urljoin(base_url, url)
            cands.append(url)

    # plain URLs
    for m in re.finditer(r"(https?://[^\s\"'<>]+)", soup.get_text(" ")):
        cands.append(m.group(1))

    # dedupe
    out, seen = [], set()
    for c in cands:
        if c and c not in seen:
            seen.add(c)
            out.append(c)

    return out


# -----------------------------------------------------
# Helper: HEAD then GET probe
# -----------------------------------------------------
def _head_then_get(client: httpx.Client, url: str) -> Optional[str]:
    try:
        r = client.head(url, timeout=TIMEOUT, follow_redirects=True)
        if r.history or r.status_code == 200:
            return str(r.url)
    except Exception:
        pass

    try:
        r = client.get(url, timeout=TIMEOUT, follow_redirects=True)
        if r.history or r.status_code == 200:
            return str(r.url)
    except Exception:
        pass

    return None


# -----------------------------------------------------
# Main public API: resolve_url()
# -----------------------------------------------------
def resolve_url(initial_url: str, proxy: Optional[str] = None,
                preferred_domains: Optional[List[str]] = None) -> Optional[str]:

    url = (initial_url or "").strip()
    if not url:
        return None

    url = _decode_wrapper(url)

    client_args = {"headers": HEADERS, "http2": True, "trust_env": False}
    if proxy:
        client_args["proxies"] = {"http://": proxy, "https://": proxy}

    preferred_domains = preferred_domains or PREFERRED_DOMAINS

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with httpx.Client(**client_args) as client:

                r = client.get(url, timeout=TIMEOUT, follow_redirects=True)
                final = str(r.url)

                # If this looks like a real landing, return it immediately
                if final and not any(x in final for x in (
                    "wheregoes.com", "inky.com", "shared.outlook",
                    "linkprotect.cudasvc.com", "help.medium.com"
                )):
                    return final

                html = r.text or ""
                candidates = _find_candidates(html, base_url=final)

                # Prefer candidates with preferred domains
                ordered = []
                if preferred_domains:
                    pref = [c for c in candidates if any(d in c for d in preferred_domains)]
                    ordered = pref + [c for c in candidates if c not in pref]
                else:
                    ordered = candidates

                tried = set()
                for c in ordered:
                    if c in tried:
                        continue
                    tried.add(c)
                    hop = _head_then_get(client, c)
                    if hop and not any(x in hop for x in (
                        "wheregoes.com", "inky.com", "shared.outlook",
                        "linkprotect.cudasvc.com", "help.medium.com"
                    )):
                        return hop

                return None

        except httpx.TransportError:
            wait = RETRY_BACKOFF * attempt
            time.sleep(wait)
            continue
        except Exception:
            break

    return None
