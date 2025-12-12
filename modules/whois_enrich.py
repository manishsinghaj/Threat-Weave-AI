# modules/whois_enrich.py
"""
whois_enrich.py — wrapper around python-whois with graceful fallback
"""

from __future__ import annotations
import socket
import time
from typing import Dict, Any

def whois_lookup(host: str) -> Dict[str, Any]:
    """
    Perform a whois lookup for a domain (blocking).
    If the 'whois' package is not installed, return a helpful error dict.
    """
    # Defensive: strip port if present
    host = (host or "").split(":", 1)[0]

    try:
        # lazy import so static analysis / installs that lack whois won't fail at import-time
        import whois as pywhois  # type: ignore
    except Exception as e:
        return {
            "query": host,
            "error": "python-whois_not_installed",
            "detail": str(e),
            "note": "Install with: python -m pip install python-whois"
        }

    try:
        w = pywhois.whois(host)
        # Normalize some common fields into JSON-friendly strings
        def _first_or_str(v):
            if v is None:
                return None
            if isinstance(v, (list, tuple, set)):
                for item in v:
                    if item:
                        return str(item)
                return str(next(iter(v), "")) if v else None
            return str(v)

        def _norm_date(d):
            if d is None:
                return None
            if isinstance(d, (list, tuple)):
                return [str(x) for x in d]
            return str(d)

        result = {
            "query": host,
            "domain_name": _first_or_str(getattr(w, "domain_name", None)),
            "registrar": _first_or_str(getattr(w, "registrar", None)),
            "creation_date": _norm_date(getattr(w, "creation_date", None)),
            "expiration_date": _norm_date(getattr(w, "expiration_date", None)),
            "status": _first_or_str(getattr(w, "status", None)),
            "raw": {
                "name_servers": getattr(w, "name_servers", None),
                "emails": getattr(w, "emails", None),
            }
        }
        return result
    except Exception as e:
        return {"query": host, "error": "whois_failed", "detail": str(e)}
