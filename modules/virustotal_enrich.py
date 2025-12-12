# modules/virustotal_enrich.py
import base64
import asyncio
from typing import Dict, Any, Iterable
import httpx
import time

from config import VT_CFG

def _safe_get(obj: Any, *keys, default=None):
    cur = obj
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur

DEFAULT_HEADERS = {"User-Agent": "ThreatWeaveAI/1.0"}

def _vt_url_id_from_url(url: str) -> str:
    """VirusTotal v3 expects URL IDs as base64 URL-safe encoding of the raw URL, without trailing '='."""
    b = url.encode("utf-8")
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

async def vt_url_lookup(url: str) -> Dict[str, Any]:
    """Async lookup for a URL on VirusTotal v3 with simplified output."""
    cfg = VT_CFG or {}
    if not cfg.get("enabled", False):
        return {"vt_verified": False, "error": "disabled"}

    api_key = cfg.get("api_key")
    if not api_key:
        return {"vt_verified": False, "error": "missing_api_key"}

    base_url = (cfg.get("api_url") or "https://www.virustotal.com/api/v3").rstrip("/")
    submit_url = cfg.get("submit_url") or f"{base_url}/urls"
    report_url = f"{base_url}/urls/{_vt_url_id_from_url(url)}"

    timeout = cfg.get("timeout_seconds", 15)
    headers = {"x-apikey": api_key, **DEFAULT_HEADERS}

    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        try:
            # Try optional submission; ignore errors (many users prefer to avoid submit failures breaking the flow)
            try:
                await client.post(submit_url, data={"url": url})
            except Exception:
                pass

            r = await client.get(report_url)
            r.raise_for_status()
            j = r.json()

            attrs = _safe_get(j, "data", "attributes", default={}) or {}
            stats = attrs.get("last_analysis_stats", {}) or {}
            results = attrs.get("last_analysis_results", {}) or {}

            # Build map of vendors that flagged the URL with a suspicious category
            flagged_vendors: Dict[str, Any] = {}
            if isinstance(results, dict):
                for vendor, rpt in results.items():
                    try:
                        cat = rpt.get("category")
                        # treat these categories as noteworthy
                        if cat in ("malicious", "phishing", "spam", "suspicious"):
                            flagged_vendors[vendor] = {
                                "category": cat,
                                "result": rpt.get("result"),
                                "method": rpt.get("engine_name") or rpt.get("engine") or None
                            }
                    except Exception:
                        # skip vendor if shape unexpected
                        continue

            # Decide simple verdict
            if flagged_vendors:
                simplified = {
                    "vt_verified": True,
                    "verdict": "malicious",
                    "flagged_vendors": flagged_vendors,
                    "summary_counts": stats,
                    "fetched_at": int(time.time()),
                }
            else:
                simplified = {
                    "vt_verified": True,
                    "verdict": "clean",
                    "summary_counts": stats,
                    "fetched_at": int(time.time()),
                }

            return simplified

        except httpx.HTTPStatusError as he:
            status_code = getattr(he.response, "status_code", None)
            return {"vt_verified": False, "error": f"http_error: {str(he)}", "status_code": status_code}
        except Exception as e:
            return {"vt_verified": False, "error": str(e)}

def vt_url_lookup_sync(url: str) -> Dict[str, Any]:
    """Run the async vt_url_lookup in a new loop or using asyncio.run."""
    try:
        return asyncio.run(vt_url_lookup(url))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(vt_url_lookup(url))
        finally:
            loop.close()

async def fetch_vt_for_urls(urls: Iterable[str]):
    """Bulk async fetch helper (returns results in same order as urls list)."""
    tasks = [vt_url_lookup(u) for u in urls]
    return await asyncio.gather(*tasks)
