# modules/mx_blacklist.py
"""
MX blacklist helper — API-only variant for environments where MXToolbox API is available.

Public:
- mx_blacklists_sync(domain_or_ip: str) -> dict

Return shape:
{
  "blacklisted": bool,
  "blacklisted_count": int,
  "listed_providers": [...],
  "providers": [ { "provider": str, "listed": bool, "reason": str|None, "status": str|None }, ... ],
  "raw": {...},            # raw API payload
  "fetched_at": 1234567890,
  "error": "..."           # present only on failures
}
Notes:
- No DNSBL lookups or web-scraping performed.
- Requires CONFIG["mxtoolbox"] configured with enabled=True, use_api=True, api_key set.
"""

from __future__ import annotations

import time
from typing import Dict, Any, List, Optional

# try to import project CONFIG; fallback to minimal but API will be considered disabled
try:
    from config import CONFIG  # type: ignore
except Exception:
    CONFIG = {"mxtoolbox": {"enabled": False, "use_api": True, "api_key": "", "timeout_seconds": 15}}


def _normalize_failed_passed(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalize MXToolbox shape with Failed/Warnings/Passed/Information sections."""
    if not isinstance(data, dict) or not any(k in data for k in ("Failed", "Warnings", "Passed", "Information")):
        return None

    providers: List[Dict[str, Any]] = []

    def _add_entries(lst: List[Dict[str, Any]], label: str) -> None:
        for p in (lst or []):
            name = p.get("Name") or p.get("name") or p.get("check") or ""
            info = p.get("Info") or p.get("info") or p.get("Result") or ""
            listed = (label == "Failed")
            providers.append({"provider": name, "status": label, "reason": info, "listed": bool(listed)})

    _add_entries(data.get("Failed", []), "Failed")
    _add_entries(data.get("Warnings", []), "Warning")
    _add_entries(data.get("Passed", []), "Passed")
    for p in data.get("Information", []):
        providers.append({"provider": p.get("Name", str(p)), "status": "Info", "reason": str(p), "listed": False})

    listed_providers = [p["provider"] for p in providers if p.get("listed")]
    return {
        "blacklisted": bool(listed_providers),
        "blacklisted_count": len(listed_providers),
        "listed_providers": listed_providers,

    }


def _normalize_blacklists_array(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalize MXToolbox payloads that contain a 'Blacklists' array."""
    if not isinstance(data, dict):
        return None
    bl = data.get("Blacklists")
    if not isinstance(bl, list):
        return None

    providers: List[Dict[str, Any]] = []
    for item in bl:
        if not isinstance(item, dict):
            continue
        name = item.get("Name") or item.get("name") or ""
        status = item.get("Status") or item.get("status") or ""
        details = item.get("Details") or item.get("Details", "") or ""
        listed = bool(item.get("Listed", False)) or ("listed" in (status or "").lower())
        providers.append({"provider": name, "status": status, "reason": details, "listed": listed})

    listed_providers = [p["provider"] for p in providers if p.get("listed")]
    return {
        "blacklisted": bool(listed_providers)
    }


def _mxtoolbox_api_check(domain_or_ip: str) -> Dict[str, Any]:
    """
    Call MXToolbox API and normalize response.
    Returns normalized dict with compact summary keys, or error info on failure.
    """
    import requests  # local import

    mcfg = CONFIG.get("mxtoolbox", {}) if isinstance(CONFIG, dict) else {}
    if not mcfg.get("enabled", False) or not mcfg.get("use_api", True) or not mcfg.get("api_key"):
        return {
            "blacklisted": False,
            "providers": [],
            "blacklisted_count": 0,
            "listed_providers": [],
            "raw": {"error": "mxtoolbox_api_not_configured"},
            "fetched_at": int(time.time()),
            "error": "mxtoolbox_api_not_configured",
        }

    api_key = mcfg.get("api_key")
    endpoint = f"https://mxtoolbox.com/api/v1/Lookup/Blacklist/{domain_or_ip}"
    headers = {"Authorization": api_key}
    timeout = mcfg.get("timeout_seconds", 15)

    try:
        resp = requests.get(endpoint, headers=headers, timeout=timeout)
    except requests.exceptions.RequestException as e:
        return {
            "blacklisted": False,
            "providers": [],
            "blacklisted_count": 0,
            "listed_providers": [],
            "raw": {"error": "network_exception", "detail": str(e)},
            "fetched_at": int(time.time()),
            "error": f"network_error: {str(e)}",
        }

    try:
        data = resp.json()
    except Exception:
        return {
            "blacklisted": False,
            "providers": [],
            "blacklisted_count": 0,
            "listed_providers": [],
            "raw_status": resp.status_code,
            "raw": resp.text,
            "fetched_at": int(time.time()),
            "error": "non_json_response",
        }

    # Try recognized normalizations
    normalized = _normalize_failed_passed(data)
    if normalized:
        return normalized

    normalized = _normalize_blacklists_array(data)
    if normalized:
        return normalized

    # Last attempt: coerce provider-like entries from top-level lists/dicts
    providers: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict) and ("Name" in item or "name" in item):
                        name = item.get("Name") or item.get("name") or str(item)
                        listed = bool(item.get("Listed", False)) or ("listed" in (item.get("Status") or "").lower())
                        reason = item.get("Details") or item.get("Info") or item.get("Result") or ""
                        providers.append({"provider": name, "listed": listed, "reason": reason})
    listed_providers = [p["provider"] for p in providers if p.get("listed")]
    if providers:
        return {
            "blacklisted": bool(listed_providers),
            
        }

    # No normalization possible — return raw payload with safe summary
    return {
        "blacklisted": False,
        "providers": [],
        "blacklisted_count": 0,
        "listed_providers": [],
        "raw": data,
        "fetched_at": int(time.time()),
    }


def mx_blacklists_sync(domain_or_ip: str) -> Dict[str, Any]:
    """
    Public sync entrypoint — API only.
    If API is misconfigured or fails, returns an explicit 'error' field instead of falling back.
    """
    if not domain_or_ip:
        return {
            "blacklisted": False,
            "providers": [],
            "blacklisted_count": 0,
            "listed_providers": [],
            "raw": {},
            "fetched_at": int(time.time()),
            "error": "invalid_input",
        }

    # Always use API path (per your environment)
    return _mxtoolbox_api_check(domain_or_ip)
