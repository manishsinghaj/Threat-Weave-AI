# config.py
"""
Centralized configuration loader.

Exports:
- settings: lightweight object with common attributes (SAGE_API_URL, SAGE_API_KEY, DEBUG_MODE)
- CONFIG: full nested dict used by modules/external_checks and others (whois, virustotal, mxtoolbox, wheregoes, general)
- VT_CFG: legacy top-level alias used by modules/virustotal_enrich.py
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root if present
env_path = Path(".") / ".env"
if env_path.exists():
    load_dotenv(env_path)
else:
    # still call load_dotenv (reads default environment) in case env is provided elsewhere
    load_dotenv()

def _boolenv(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return str(v).lower() in ("1", "true", "yes", "y", "on")

def _intenv(key: str, default: int = 0) -> int:
    v = os.getenv(key)
    try:
        return int(v) if v is not None and v != "" else default
    except Exception:
        return default

class Settings:
    """Simple convenience object for commonly used settings."""
    SAGE_API_URL: str = os.getenv("SAGE_API_URL", "https://api.sage.cudasvc.com/openai/chat/completions")
    SAGE_API_KEY: str = os.getenv("SAGE_API_KEY", "")
    DEBUG_MODE: bool = _boolenv("DEBUG_MODE", False)
    # optional generic timeouts
    DEFAULT_TIMEOUT_SECONDS: int = _intenv("DEFAULT_TIMEOUT_SECONDS", 15)

settings = Settings()

# Full nested CONFIG used by async external checks and other modules.
CONFIG = {
    "general": {
        "timeout_seconds": _intenv("GENERAL_TIMEOUT", settings.DEFAULT_TIMEOUT_SECONDS),
        "max_concurrency": _intenv("GENERAL_MAX_CONCURRENCY", 8),
    },
    "sage": {
        "api_url": settings.SAGE_API_URL,
        "api_key": settings.SAGE_API_KEY,
        "timeout_seconds": _intenv("SAGE_TIMEOUT", 120),
    },
    "virustotal": {
        # enable via VT_ENABLED=true in .env
        "enabled": _boolenv("VT_ENABLED", False),
        "api_key": os.getenv("VT_API_KEY", os.getenv("VIRUSTOTAL_API_KEY", "")),
        "api_url": os.getenv("VT_API_URL", "https://www.virustotal.com/api/v3").rstrip("/"),
        # optional explicit submit endpoint (useful for proxied deployments)
        "submit_url": os.getenv("VT_SUBMIT_URL", "") or None,
        "timeout_seconds": _intenv("VT_TIMEOUT", 30),
        # file upload limits in bytes (default 32 MB)
        "simple_upload_limit": _intenv("VT_SIMPLE_UPLOAD_LIMIT", 32 * 1024 * 1024),
    },
    "whois": {
        "enabled": _boolenv("WHOIS_ENABLED", True),
        "timeout_seconds": _intenv("WHOIS_TIMEOUT", 8),
    },
    "wheregoes": {
        "enabled": _boolenv("WHEREGOES_ENABLED", True),
        "timeout_seconds": _intenv("WHEREGOES_TIMEOUT", 8),
    },
    "mxtoolbox": {
        # to enable set MXTOOLBOX_ENABLED=true and set MXTOOLBOX_API_KEY in .env
        "enabled": _boolenv("MXTOOLBOX_ENABLED", True),
        "use_api": _boolenv("MXTOOLBOX_USE_API", True),
        "api_key": os.getenv("MXTOOLBOX_API_KEY", ""),
        "timeout_seconds": _intenv("MXTOOLBOX_TIMEOUT", 15),
    },
    # compatibility / legacy flags
    "compat": {
        "synchronous_vt_wrapper": True,
    }
}

# Backwards-compatible alias used by multiple modules (VT_CFG)
VT_CFG = CONFIG["virustotal"]

# Convenience: top-level exports for older modules that import directly
SAGE_API_URL = settings.SAGE_API_URL
SAGE_API_KEY = settings.SAGE_API_KEY

# Optional helper: print minimal diagnostics when DEBUG_MODE is true
if settings.DEBUG_MODE:
    try:
        import json as _json
        print("[config] DEBUG_MODE enabled; effective CONFIG:")
        print(_json.dumps(CONFIG, indent=2))
    except Exception:
        pass
