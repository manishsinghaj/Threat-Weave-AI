#!/usr/bin/env python3
"""
attachments_scanner.py (updated)

Privacy-first attachments scanner.

- Images: try QR extraction (OpenCV). If QR -> URL -> run vt_url_lookup_sync (returns simplified vt verdict).
          If no QR -> do NOT upload image to VT; return image_no_qr_skipped.
- Non-images: check by SHA256; if report exists or after upload, return a simplified VT verdict:
      {"vt_verified": True/False, "verdict": "malicious"/"clean", "flagged_vendors": {...}, "summary_counts": {...}, "fetched_at": ...}
- Keeps public signature:
      scan_attachment_bytes(name, data_bytes, api_key=None, debug=False) -> Dict[str, Any]
"""
from __future__ import annotations

import os
import time
import hashlib
from typing import Dict, Any, Optional
from pathlib import Path

# Try to import CONFIG from project config (recommended)
try:
    from config import CONFIG  # type: ignore
except Exception:
    CONFIG = {}

# Optional QR dependencies
_HAS_OPENCV = True
try:
    import cv2
    import numpy as _np
except Exception:
    _HAS_OPENCV = False

# Prefer the simplified VT helpers if available
try:
    # vt_url_lookup_sync returns simplified vt verdict for URLs
    from modules.virustotal_enrich import vt_url_lookup_sync  # type: ignore
except Exception:
    vt_url_lookup_sync = None

# Fallback HTTP libs for file upload/report check
import requests

VT_FILE_REPORT_URL = "https://www.virustotal.com/api/v3/files/{}"
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{}"

VT_SIMPLE_UPLOAD_LIMIT = 32 * 1024 * 1024  # 32MB
POLL_INTERVAL = 6
MAX_POLLS = 40


def _compute_sha256(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def _resolve_api_key(passed_key: Optional[str]) -> Optional[str]:
    """Resolve API key: explicit param -> env var -> CONFIG."""
    if passed_key:
        return passed_key
    env = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
    if env:
        return env
    try:
        vt_conf = CONFIG.get("virustotal", {}) if isinstance(CONFIG, dict) else {}
        key = vt_conf.get("api_key")
        if key:
            return key
    except Exception:
        pass
    return None


def _is_image_filename(name: str) -> bool:
    if not name:
        return False
    name = name.lower()
    return any(name.endswith(ext) for ext in ('.png', '.jpg', '.jpeg', '.webp', '.gif', '.bmp'))


def _extract_qr_from_bytes(data_bytes: bytes) -> Optional[str]:
    """Try to decode QR code from image bytes using OpenCV. Returns decoded string or None."""
    if not _HAS_OPENCV:
        return None
    try:
        arr = _np.frombuffer(data_bytes, dtype=_np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return None
        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(img)
        if data:
            return data.strip()
        if points is not None:
            try:
                pts = points[0] if isinstance(points, (list, tuple)) and len(points) and isinstance(points[0], (list, tuple)) else points
                pts = _np.array(pts, dtype=_np.int32).reshape(-1, 2)
                x, y, w, h = cv2.boundingRect(pts)
                roi = img[y:y+h, x:x+w]
                data2, _, _ = detector.detectAndDecode(roi)
                if data2:
                    return data2.strip()
            except Exception:
                pass
        return None
    except Exception:
        return None


def _headers(api_key: Optional[str]) -> Dict[str, str]:
    return {"x-apikey": api_key} if api_key else {}


def _simplify_vt_file_json(j: Dict[str, Any]) -> Dict[str, Any]:
    """
    Given a full VirusTotal file-report JSON, produce the simplified verdict object:
    { vt_verified: True, verdict: "malicious"/"clean", flagged_vendors: {...}, summary_counts: {...}, fetched_at: ... }
    """
    try:
        data = j.get("data", {}) if isinstance(j, dict) else {}
        attrs = data.get("attributes", {}) if isinstance(data, dict) else {}
        stats = attrs.get("last_analysis_stats", {}) or {}
        results = attrs.get("last_analysis_results", {}) or {}

        flagged_vendors: Dict[str, Any] = {}
        if isinstance(results, dict):
            for vendor, rpt in results.items():
                try:
                    cat = rpt.get("category")
                    if cat in ("malicious", "phishing", "spam", "suspicious"):
                        flagged_vendors[vendor] = {
                            "category": cat,
                            "result": rpt.get("result"),
                            # cleanup: prefer readable engine name where present
                            "method": rpt.get("engine_name") or rpt.get("engine") or None
                        }
                except Exception:
                    continue

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
    except Exception as e:
        return {"vt_verified": False, "error": "simplify_failed", "detail": str(e)}


def scan_attachment_bytes(name: str, data_bytes: bytes, api_key: Optional[str] = None, debug: bool = False) -> Dict[str, Any]:
    """
    Scan attachment bytes and return either:
      - simplified VT verdict dict (for non-image or image-with-QR -> URL lookup),
      - privacy-preserving errors for images with no QR,
      - or error dicts for network / config issues.

    Note: for image-with-QR we will still include the decoded QR as 'qr_data' alongside the VT verdict.
    """
    resolved_key = _resolve_api_key(api_key)
    sha256 = _compute_sha256(data_bytes)

    # Image path: QR-first, privacy-preserving
    if _is_image_filename(name):
        if not _HAS_OPENCV:
            return {"sha256": sha256, "vt_verified": False, "error": "opencv_or_numpy_missing", "detail": "Install opencv-python and numpy to enable QR extraction."}

        qr = _extract_qr_from_bytes(data_bytes)
        if qr:
            qr_str = qr.strip()
            if qr_str.startswith("http://") or qr_str.startswith("https://") or ("." in qr_str and " " not in qr_str):
                if vt_url_lookup_sync:
                    try:
                        vt_res = vt_url_lookup_sync(qr_str)
                        # vt_res is already simplified (vt_url_lookup returns simplified)
                        # include sha256 and qr_data wrapper for attachments flow
                        out = {"sha256": sha256, "qr_data": qr_str, "virustotal": vt_res}
                        return out
                    except Exception as e:
                        return {"sha256": sha256, "vt_verified": False, "error": "vt_lookup_failed", "detail": str(e), "qr_data": qr_str}
                else:
                    return {"sha256": sha256, "vt_verified": False, "note": "vt_url_lookup_unavailable", "qr_data": qr_str}
            else:
                return {"sha256": sha256, "vt_verified": False, "error": "qr_not_a_url", "qr_data": qr_str}
        else:
            return {"sha256": sha256, "vt_verified": False, "error": "image_no_qr_skipped", "note": "privacy_preserved"}

    # Non-image path: must have API key for file reports
    if not resolved_key:
        return {"sha256": sha256, "vt_verified": False, "error": "missing_api_key"}

    # Lightweight helpers using requests (kept for compatibility)
    def _get_file_report(sha: str, api_k: str, timeout: int = 30) -> requests.Response:
        url = VT_FILE_REPORT_URL.format(sha)
        return requests.get(url, headers=_headers(api_k), timeout=timeout)

    def _upload_file_bytes(name_local: str, b: bytes, api_k: str, timeout: int = 120) -> Dict[str, Any]:
        files = {"file": (name_local, b)}
        resp = requests.post(VT_UPLOAD_URL, headers=_headers(api_k), files=files, timeout=timeout)
        resp.raise_for_status()
        return resp.json()

    def _get_analysis(analysis_id: str, api_k: str, timeout: int = 30) -> Dict[str, Any]:
        resp = requests.get(VT_ANALYSIS_URL.format(analysis_id), headers=_headers(api_k), timeout=timeout)
        resp.raise_for_status()
        return resp.json()

    # 1) check existing report by hash
    try:
        r = _get_file_report(sha256, resolved_key)
    except requests.RequestException as e:
        return {"sha256": sha256, "vt_verified": False, "error": "vt_network_error", "detail": str(e)}

    if r.status_code == 200:
        try:
            j = r.json()
            simplified = _simplify_vt_file_json(j)
            # return simplified directly (consistent with vt_url_lookup simplified output)
            return simplified
        except Exception:
            return {"sha256": sha256, "vt_verified": False, "error": "invalid_json_in_report"}

    if r.status_code != 404:
        return {"sha256": sha256, "vt_verified": False, "error": f"unexpected_status_{r.status_code}", "raw": getattr(r, "text", None)}

    # 2) If not found, attempt upload if within size limits
    size = len(data_bytes)
    if size > VT_SIMPLE_UPLOAD_LIMIT:
        return {"sha256": sha256, "vt_verified": False, "error": "file_too_large_for_simple_upload", "size": size}

    try:
        upload_resp = _upload_file_bytes(name, data_bytes, resolved_key)
    except requests.HTTPError as e:
        resp = getattr(e, "response", None)
        raw = resp.text if resp is not None else None
        return {"sha256": sha256, "vt_verified": False, "error": "upload_failed", "detail": str(e), "raw": raw}
    except requests.RequestException as e:
        return {"sha256": sha256, "vt_verified": False, "error": "upload_network_error", "detail": str(e)}

    # 3) Poll analyses endpoint if analysis id returned
    analysis_id = None
    if isinstance(upload_resp, dict):
        analysis_id = upload_resp.get("data", {}).get("id") or upload_resp.get("meta", {}).get("id")

    if analysis_id:
        for attempt in range(1, MAX_POLLS + 1):
            try:
                anal = _get_analysis(analysis_id, resolved_key)
            except requests.RequestException:
                time.sleep(POLL_INTERVAL)
                continue
            status = anal.get("data", {}).get("attributes", {}).get("status")
            if debug:
                print(f"VT poll {attempt}/{MAX_POLLS} - status: {status}")
            if status == "completed":
                break
            time.sleep(POLL_INTERVAL)

    # 4) Fetch canonical file report by sha256 and simplify
    try:
        resp2 = _get_file_report(sha256, resolved_key)
    except requests.RequestException as e:
        return {"sha256": sha256, "vt_verified": False, "error": "vt_network_error_after_upload", "detail": str(e)}

    if resp2.status_code == 200:
        try:
            j2 = resp2.json()
            simplified = _simplify_vt_file_json(j2)
            return simplified
        except Exception:
            return {"sha256": sha256, "vt_verified": False, "error": "invalid_json_in_report_after_upload"}
    else:
        return {"sha256": sha256, "vt_verified": False, "error": f"report_unavailable_status_{resp2.status_code}", "raw": getattr(resp2, "text", None)}
