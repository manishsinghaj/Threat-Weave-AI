# app_streamlit.py
from __future__ import annotations
import streamlit as st
import tempfile
import time
import html
import json
import traceback
import os
from urllib.parse import unquote
from typing import Dict, Any, List, Optional

# Local modules (expected to exist in your project)
from modules.eml_parser import parse_eml
from modules.url_analyzer import normalize_urls, detect_evasion_techniques
from modules.whois_enrich import whois_lookup
from modules.tls_enrich import get_cert_info
from modules.oauth_analyzer import analyze_oauth_url
from modules.llm_analyzer import analyze_with_sage
from modules.virustotal_enrich import vt_url_lookup_sync
from modules.redirect_resolver import resolve_url
from urllib.parse import urlparse
# Optional helpers
try:
    from modules.attachments_scanner import scan_attachment_bytes
except Exception:
    scan_attachment_bytes = None

try:
    from modules.mx_blacklist import mx_blacklists_sync
except Exception:
    try:
        from modules.mx_blacklist import mx_blacklists_sync
    except Exception:
        def mx_blacklists_sync(domain_or_ip: str) -> Dict[str, Any]:
            return {"blacklisted": False, "providers": [], "error": "mx_check_not_available"}

# Page config
st.set_page_config(page_title="ThreatWeaveAI", layout="wide")
st.title("ThreatWeaveAI")
uploaded = st.file_uploader(
    "Upload a `.eml` file to analyze phishing, OAuth abuse, URL evasion, and see WHOIS/TLS/VirusTotal enrichment.",
    type=["eml"],
)

# ---------- Helpers ----------
def _host_from_url(u: str) -> str:
    try:
        return u.split("://")[-1].split("/")[0].split("?")[0]
    except Exception:
        return u or ""


def _extract_regex_indicators_from_llm(llm_resp: Any) -> List[Dict[str, Any]]:
    """
    Robustly extract a list of indicator dicts from the LLM response.
    Supports direct dict, chat choices, string JSON, and JSON substring extraction.
    """
    def try_parse_json(s: str) -> Optional[Dict[str, Any]]:
        if not isinstance(s, str):
            return None
        candidates = [s]
        try:
            candidates.append(s.encode("utf-8").decode("unicode_escape"))
        except Exception:
            pass
        try:
            candidates.append(s.replace("\\\\n", "\\n").replace("\\\\t", "\\t"))
        except Exception:
            pass

        for cand in candidates:
            try:
                parsed = json.loads(cand)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                try:
                    start = cand.find("{")
                    end = cand.rfind("}")
                    if start != -1 and end != -1 and end > start:
                        maybe = cand[start : end + 1]
                        parsed2 = json.loads(maybe)
                        if isinstance(parsed2, dict):
                            return parsed2
                except Exception:
                    pass
        return None

    # 1) direct dict containing regex_indicator
    try:
        if isinstance(llm_resp, dict) and "regex_indicator" in llm_resp:
            val = llm_resp.get("regex_indicator") or []
            if isinstance(val, list):
                return val
    except Exception:
        pass

    # 2) Chat-style response: choices -> [ { "message": { "content": "..." } } ]
    try:
        if isinstance(llm_resp, dict) and "choices" in llm_resp:
            choices = llm_resp.get("choices") or []
            if isinstance(choices, (list, tuple)) and len(choices) > 0:
                for candidate in choices:
                    if not isinstance(candidate, dict):
                        continue
                    content = None
                    msg = candidate.get("message") or {}
                    if isinstance(msg, dict):
                        content = msg.get("content") or msg.get("text")
                    if not content:
                        content = candidate.get("text") or candidate.get("message") or None
                    if content:
                        parsed = try_parse_json(content)
                        if (
                            parsed
                            and "regex_indicator" in parsed
                            and isinstance(parsed.get("regex_indicator"), list)
                        ):
                            return parsed.get("regex_indicator") or []
    except Exception:
        pass

    # 3) if llm_resp is string, try parse it
    try:
        if isinstance(llm_resp, str):
            parsed = try_parse_json(llm_resp)
            if parsed and "regex_indicator" in parsed and isinstance(parsed.get("regex_indicator"), list):
                return parsed.get("regex_indicator") or []
    except Exception:
        pass

    # 4) fallback: search for "regex_indicator" in any stringified form
    try:
        s = json.dumps(llm_resp) if not isinstance(llm_resp, str) else llm_resp
        idx = s.find('"regex_indicator"')
        if idx != -1:
            pre = s.rfind("{", 0, idx)
            post = s.find("}", idx)
            if pre != -1 and post != -1 and post > pre:
                maybe = s[pre : post + 1]
                parsed = try_parse_json(maybe)
                if parsed and "regex_indicator" in parsed and isinstance(parsed.get("regex_indicator"), list):
                    return parsed.get("regex_indicator") or []
    except Exception:
        pass

    return []


def _format_indicator_as_block(indicator: Dict[str, Any]) -> str:
    """
    Produce a YAML-like triple-quoted block where each indicator is rendered as a
    list item (leading '- strings:'). Escapes backslashes/double quotes safely.
    """
    def _escape_for_block(s: str) -> str:
        if s is None:
            return ""
        s = str(s)
        s = s.replace('"""', '\\"""')
        s = s.replace('"', '\\"')
        s = s.replace("\\", "\\\\")
        return s

    lines: List[str] = []
    lines.append('"""')

    strings = indicator.get("strings") or indicator.get("string") or []
    if isinstance(strings, str):
        strings = [strings]

    lines.append("  - strings:")
    if strings:
        for s in strings:
            safe = _escape_for_block(s)
            lines.append(f'     - "{safe}"')
    else:
        lines.append('      - ""')

    scalar_order = [
        "or",
        "regex",
        "type",
        "normalized",
        "headless",
        "determination",
        "description",
    ]
    for key in scalar_order:
        if key in indicator:
            val = indicator.get(key)
            if isinstance(val, bool):
                vs = "true" if val else "false"
                lines.append(f"    {key}: {vs}")
            else:
                if val is None:
                    lines.append(f"    {key}: null")
                else:
                    sval = _escape_for_block(str(val).replace("\n", " "))
                    lines.append(f'    {key}: "{sval}"')

    highlights = indicator.get("highlights") or []
    lines.append("    highlights:")
    if isinstance(highlights, (list, tuple)) and highlights:
        for h in highlights:
            hid = str(h).replace("\\", "\\\\")
            lines.append(f"      - {hid}")
    else:
        lines.append("      - NONE")

    lines.append('"""')
    return "\n".join(lines)


# ---------- Session defaults ----------
if "local_findings" not in st.session_state:
    st.session_state["local_findings"] = {}

if "llm_analysis" not in st.session_state:
    st.session_state["llm_analysis"] = {}

# Helper to build a filtered enrichment dict based on user choice
def _build_filtered_enrichment(enrichment: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a full, deep-copied enrichment dictionary.
    This version removes the 'fields' argument completely
    and always exports ALL enrichment fields safely.
    """
    if not enrichment:
        return {}

    # Try deep copy
    try:
        return json.loads(json.dumps(enrichment))
    except Exception:
        # Fallback shallow copy
        return dict(enrichment)

# ---------------------- New: professional report builder ----------------------
def _safe_list_names(vendors_obj) -> str:
    """
    Extract a comma-separated list of vendor names (handles many possible shapes).
    """
    if not vendors_obj:
        return ""
    # If a dict mapping vendor -> details
    if isinstance(vendors_obj, dict):
        return ", ".join(sorted([str(k) for k in vendors_obj.keys()]))
    # If it's a list of dicts with 'vendor' or 'name'
    if isinstance(vendors_obj, (list, tuple)):
        names = []
        for item in vendors_obj:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict):
                for k in ("vendor", "name"):
                    if k in item:
                        names.append(item.get(k))
                        break
                else:
                    # fallback: use first key if item is dict of vendor->info
                    if item:
                        names.append(next(iter(item.keys())))
        return ", ".join([n for n in names if n])
    # Final fallback: convert to string
    return str(vendors_obj)


def _normalize_attachments(attachments_raw) -> Dict[str, Dict[str, Any]]:
    """
    Normalize attachments into a dict keyed by a filename-like key.
    Accepts dict, list, tuple, or single value. Returns dict[name] -> dict(info).
    """
    if not attachments_raw:
        return {}
    if isinstance(attachments_raw, dict):
        return {
            str(k): (v if isinstance(v, dict) else {"value": v})
            for k, v in attachments_raw.items()
        }
    if isinstance(attachments_raw, (list, tuple)):
        out = {}
        for i, item in enumerate(attachments_raw, start=1):
            if isinstance(item, dict):
                name = (
                    item.get("filename")
                    or item.get("name")
                    or item.get("fname")
                    or f"attachment_{i}"
                )
                out[str(name)] = item
            else:
                out[f"attachment_{i}"] = {"value": item}
        return out
    # fallback for single scalar
    return {"attachment_1": {"value": attachments_raw}}


def build_professional_report_from_export(out: Dict[str, Any]) -> str:
    """
    Build textual report (Markdown/plain text) from export JSON matching user's template.
    Always emits an Attachments section if attachments exist; also emits QR/Decoded blocks
    for image attachments that contain QR data.
    """
    import time
    from typing import Any, Dict, List

    def _flagged_vendor_names_from_vt(vt_obj: Any) -> List[str]:
        names = set()
        try:
            if isinstance(vt_obj, dict):
                candidates = [
                    vt_obj.get("flagged_vendors"),
                    (vt_obj.get("virustotal") or {}).get("flagged_vendors"),
                    vt_obj.get("flagged_engines"),
                    vt_obj.get("vendors"),
                ]
                for c in candidates:
                    if isinstance(c, dict):
                        for k in c.keys():
                            names.add(str(k))
                    elif isinstance(c, (list, tuple)):
                        for item in c:
                            names.add(str(item))
        except Exception:
            pass
        return sorted(names)

    def _vt_summary_counts(vt_obj: Any) -> Dict[str, int]:
        defaults = {
            "malicious": 0,
            "suspicious": 0,
            "undetected": 0,
            "harmless": 0,
        }
        try:
            if isinstance(vt_obj, dict):
                sc = vt_obj.get("summary_counts")
                if not sc:
                    sc = (vt_obj.get("virustotal") or {}).get("summary_counts")
                if isinstance(sc, dict):
                    return {
                        "malicious": int(sc.get("malicious", 0)),
                        "suspicious": int(sc.get("suspicious", 0)),
                        "undetected": int(sc.get("undetected", 0)),
                        "harmless": int(sc.get("harmless", 0)),
                    }
        except Exception:
            pass
        return defaults

    def _is_attachment_image(name: str, ainfo: Dict[str, Any]) -> bool:
        """
        Heuristic to decide whether attachment is an image:
          - content_type starting with 'image/'
          - filename extension in common image extensions
          - explicit 'is_image' flag if present
        """
        try:
            if not isinstance(ainfo, dict):
                return False
            ct = (ainfo.get("content_type") or ainfo.get("mime_type") or "").lower()
            if isinstance(ct, str) and ct.startswith("image/"):
                return True
            if ainfo.get("is_image") in (True, "true", "True"):
                return True
            if name and isinstance(name, str):
                lname = name.lower()
                for ext in (
                    ".png",
                    ".jpg",
                    ".jpeg",
                    ".gif",
                    ".bmp",
                    ".webp",
                    ".tif",
                    ".tiff",
                    ".ico",
                ):
                    if lname.endswith(ext):
                        return True
        except Exception:
            pass
        return False

    def _format_date_field(v: Any) -> str:
        if v is None:
            return "N/A"
        try:
            return str(v)
        except Exception:
            return "N/A"

    # --- main ---
    em = out.get("email_metadata", {}) or {}
    llm_top = out.get("llm_analysis", {}) or {}
    llm_raw = llm_top.get("raw") if isinstance(llm_top, dict) and llm_top.get("raw") else (llm_top or {})
    enrichment = out.get("enrichment", {}) or {}
    oauths = out.get("oauths", {}) or {}
    attachments_raw = out.get("attachments", {}) or {}
    attachments = _normalize_attachments(attachments_raw)
    src_check = out.get("source_ip_check", {}) or {}

    lines: List[str] = []
    lines.append("# Analysis\n")
    attack_type = (
        llm_raw.get("Type_of_Attack")
        or llm_raw.get("phishing_type")
        or llm_raw.get("type")
        or "Unknown"
    )
    lines.append(f"**This is a {attack_type} email**\n")
    lines.append(f"**Subject**: {em.get('subject') or 'N/A'}\n")
    lines.append(f"**From**: {em.get('from') or 'N/A'}\n")
    lines.append(f"**To**: {em.get('to') or em.get('To') or 'N/A'}\n")
    lines.append(f"**Source Ip**: {em.get('source_ip') or 'N/A'}\n")
    lines.append("\n")

    # Type/Description/Techniques
    lines.append(
        f"**Type of Phishing**: {llm_raw.get('phishing_type') or llm_raw.get('Type_of_Attack','N/A')}\n"
    )
    lines.append(
        f"**Description**: {llm_raw.get('Brief_summary') or llm_raw.get('description', '')}\n"
    )
    techniques = (
        llm_raw.get("techniques")
        or llm_raw.get("URL_Evasion Techniques")
        or llm_raw.get("techniques_used")
        or []
    )
    if isinstance(techniques, (list, tuple)):
        tech_txt = ", ".join(map(str, techniques)) if techniques else "N/A"
    else:
        tech_txt = str(techniques or "N/A")
    lines.append(f"**Techniques Used**: {tech_txt}\n")
    lines.append("\n---\n")

    # VirusTotal / Enrichment per URL
    lines.append("## VirusTotal & Enrichment (per URL)\n")
    if not enrichment:
        lines.append("_No URL enrichment available_\n")
    else:
        for url, info in enrichment.items():
            lines.append(f"**Link**: {url}\n")
            vt_candidate = info.get("virustotal") or info or {}
            verdict = (
                vt_candidate.get("verdict")
                or vt_candidate.get("result")
                or vt_candidate.get("vt_verdict")
                or "unknown"
            )
            sc = _vt_summary_counts(vt_candidate)
            lines.append(f"- **Verdict**: {verdict}")
            lines.append(f"- **Malicious**: {sc.get('malicious', 0)}")
            lines.append(f"- **Suspicious**: {sc.get('suspicious', 0)}")
            lines.append(f"- **Undetected**: {sc.get('undetected', 0)}")
            lines.append(f"- **Harmless**: {sc.get('harmless', 0)}")
            flagged_names = _flagged_vendor_names_from_vt(vt_candidate)
            lines.append(
                f"- **Flagged Vendors**: {', '.join(flagged_names) if flagged_names else 'None'}"
            )
            w = info.get("whois") or {}
            if isinstance(w, dict) and (w.get("domain_name") or w.get("query")):
                domain = w.get("domain_name") or w.get("query")
                lines.append(f"- **Whois Domain**: {domain}")
                lines.append(
                    f"  - Creation Date: {_format_date_field(w.get('creation_date'))}"
                )
                lines.append(
                    f"  - Expiration Date: {_format_date_field(w.get('expiration_date') or w.get('expiry_date'))}"
                )
            lines.append("\n")

    # --- Attachments: ALWAYS display attachments section if attachments exist ---
    if attachments:
        lines.append("## Attachments\n")
        for name, ainfo in attachments.items():
            try:
                if not isinstance(ainfo, dict):
                    ainfo = {} if ainfo is None else {"value": ainfo}
                fname = name or (ainfo.get("filename") or ainfo.get("name") or "unknown")
                fsize = (
                    ainfo.get("size")
                    or ainfo.get("bytes")
                    or ainfo.get("length")
                    or "N/A"
                )
                fsha = ainfo.get("sha256") or ainfo.get("hash") or "N/A"

                vt_obj = ainfo.get("virustotal") or ainfo
                sc = (
                    _vt_summary_counts(vt_obj)
                    if isinstance(vt_obj, dict)
                    else {
                        "malicious": "N/A",
                        "suspicious": "N/A",
                        "undetected": "N/A",
                        "harmless": "N/A",
                    }
                )
                flagged = (
                    _flagged_vendor_names_from_vt(vt_obj)
                    if isinstance(vt_obj, dict)
                    else []
                )

                lines.append(f"**Attachment**: {fname}")
                lines.append(f"- Size: {fsize}")
                lines.append(f"- sha256: {fsha}")
                lines.append(
                    f"- VT Malicious: {sc.get('malicious', 'N/A')}\n Suspicious: {sc.get('suspicious', 'N/A')}\n Undetected: {sc.get('undetected','N/A')}\n Harmless: {sc.get('harmless','N/A')}\n"
                )
                lines.append(
                    f"- Flagged Vendors: {', '.join(flagged) if flagged else 'None'}"
                )
                if ainfo.get("content_type"):
                    lines.append(f"- Content-Type: {ainfo.get('content_type')}")
                if ainfo.get("description"):
                    lines.append(f"- Description: {ainfo.get('description')}")
                lines.append("")  # spacer
            except Exception:
                lines.append(
                    f"**Attachment**: {name or 'unknown'} (metadata read error)\n"
                )

    # --- Also build image QR subsection (if any image attachments with QR exist) ---
    image_qr_entries: List[Dict[str, Any]] = []
    for name, ainfo in attachments.items():
        try:
            if not isinstance(ainfo, dict):
                ainfo = {} if ainfo is None else {"value": ainfo}

            ct = (
                (ainfo.get("content_type") or ainfo.get("mime_type") or "").lower()
                if isinstance(ainfo, dict)
                else ""
            )
            is_image = False
            if isinstance(ct, str) and ct.startswith("image/"):
                is_image = True
            if ainfo.get("is_image") in (True, "true", "True"):
                is_image = True
            if not is_image:
                lname = (name or "").lower()
                for ext in (
                    ".png",
                    ".jpg",
                    ".jpeg",
                    ".gif",
                    ".bmp",
                    ".webp",
                    ".tif",
                    ".tiff",
                    ".ico",
                ):
                    if lname.endswith(ext):
                        is_image = True
                        break

            if is_image:
                qr = (
                    ainfo.get("qr_data")
                    or ainfo.get("qr")
                    or (ainfo.get("virustotal") or {}).get("qr_data")
                    or (ainfo.get("virustotal") or {}).get("qr")
                    or (ainfo.get("virustotal") or {})
                    .get("data", {})
                    .get("qr")
                )
                if qr:
                    vt_obj = ainfo.get("virustotal") or ainfo
                    sc = _vt_summary_counts(vt_obj)
                    fvs = _flagged_vendor_names_from_vt(vt_obj)
                    image_qr_entries.append(
                        {
                            "name": name,
                            "qr": qr,
                            "counts": sc,
                            "flagged": fvs,
                        }
                    )
        except Exception:
            continue

    if image_qr_entries:
        lines.append("## QR/Decoded Payloads (image attachments)\n")
        for entry in image_qr_entries:
            lines.append(f"**Attachment**: {entry['name']}\n")
            lines.append(f"Link : {entry['qr']}\n")
            lines.append(f"- Malicious : {entry['counts'].get('malicious', 'N/A')}\n")
            lines.append(f"- Suspicious: {entry['counts'].get('suspicious', 'N/A')}\n")
            lines.append(f"- Undetected: {entry['counts'].get('undetected', 'N/A')}\n")
            lines.append(f"- Harmless: {entry['counts'].get('harmless', 'N/A')}\n")
            lines.append(
                f"- Flagged Vendors : {', '.join(entry['flagged']) if entry['flagged'] else 'None'}"
            )
            lines.append("\n")

    # OAuth Analysis
    lines.append("## OAuth Analysis\n")
    if not oauths:
        lines.append("_No OAuth patterns detected_\n")
    else:
        for u, oa in oauths.items():
            lines.append(f" URL: {u}\n")
            params = oa.get("oauth_params") or oa.get("params") or {}
            redirect_uri = (
                params.get("redirect_uri")
                or oa.get("redirect_uri")
                or params.get("redirect")
                or ""
            )
            client_id = (
                params.get("client_id")
                or params.get("clientid")
                or oa.get("client_id")
                or "N/A"
            )
            if redirect_uri:
                lines.append(f"- Redirected Url : {redirect_uri}")
            elif oa.get("redirect_host"):
                lines.append(f"- Redirect Host : {oa.get('redirect_host')}")
            lines.append(f"- Client Id : {client_id}")
            lines.append("\n")
            

    # WHOIS summary (collect domains if present across enrichment)
    lines.append("## WhoIs Data (summary)\n")
    collected = []
    for url, info in enrichment.items():
        try:
            w = info.get("whois")
            if w and isinstance(w, dict):
                domain = (
                    w.get("domain_name") or w.get("query") or w.get("domain")
                )
                if domain and domain not in collected:
                    collected.append(domain)
                    lines.append(f"- Domain : {domain}")
                    lines.append(
                        f"  - Creation Date: {_format_date_field(w.get('creation_date'))}"
                    )
                    lines.append(
                        f"  - Expiration Date: {_format_date_field(w.get('expiration_date'))}"
                    )
        except Exception:
            pass
    if not collected:
        lines.append("_No whois entries in enrichment_\n")

    # TLS summary
    lines.append("\n## TLS Data (summary)\n")
    tls_collected = False
    for url, info in enrichment.items():
        try:
            t = info.get("tls")
            if t and isinstance(t, dict) and not t.get("note"):
                tls_collected = True
                lines.append(f"- Link: {url}")
                lines.append(
                    f"  - Issuer: {t.get('issuer') or t.get('certificate_issuer') or 'N/A'}"
                )
                lines.append(f"  - Subject: {t.get('subject') or 'N/A'}")
                lines.append(
                    f"  - Licence From : {_format_date_field(t.get('not_before'))}"
                )
                lines.append(
                    f"  - Licence To : {_format_date_field(t.get('not_after'))}"
                )
        except Exception:
            pass
    if not tls_collected:
        lines.append("_No TLS data available_\n")

    # MX Toolbox Blacklisting
    lines.append("\n## MXToolbox Blacklisting\n")
    blacklisted_val = src_check.get("blacklisted_count", src_check.get("blacklisted", False))
    lines.append(f"- Black Listed : {blacklisted_val}")
    providers = src_check.get("listed_providers") or src_check.get("providers") or []
    if providers:
        if isinstance(providers, (list, tuple)):
            ptxt = ", ".join(map(str, providers))
        else:
            ptxt = str(providers)
        lines.append(f"- Providers : {ptxt}")
    else:
        lines.append("- Providers : None")

    # Recommended actions
    recommended = (
        llm_raw.get("recommended_actions")
        or llm_raw.get("recommended_action")
        or llm_raw.get("recommended", [])
        or []
    )
    if recommended:
        lines.append("\n---\n")
        lines.append("## Recommended Actions\n")
        if isinstance(recommended, (list, tuple)):
            for r in recommended:
                lines.append(f"- {r}")
        else:
            lines.append(str(recommended))

    # Timestamp
    lines.append(
        f"\n_Report generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC_\n"
    )

    return "\n".join(lines)


# ---------------------- End: professional report builder ----------------------

# (Optional) fallback JSON info – kept just as an info, no extra buttons
fallback_path = "/mnt/data/phish_enrichment_1763550026.json"
if os.path.exists(fallback_path):
    st.caption(
        f"Fallback JSON detected on server (will be used internally if needed): {os.path.basename(fallback_path)}"
    )

# ---------- UI & Flow ----------
if uploaded is not None:
    # Save uploaded file to temp path for parsing
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
        tmp.write(uploaded.read())
        tmp_path = tmp.name

    st.info("Parsing email...")
    try:
        email_data = parse_eml(tmp_path)
    except Exception as e:
        st.error(f"Failed to parse EML: {e}")
        st.error(traceback.format_exc())
        email_data = {}

    # Email metadata
    st.subheader("Email Metadata")
    st.json(
        {
            "subject": email_data.get("subject"),
            "from": email_data.get("from"),
            "to": email_data.get("to"),
            "date": email_data.get("date"),
            "source_ip": email_data.get("source_ip")
            or email_data.get("headers", {}).get("X-BESS-Apparent-Source-IP"),
        }
    )

    # Extracted URLs
    urls = normalize_urls(email_data.get("urls", []) or [])
    st.subheader("Extracted URLs")
    if not urls:
        st.write("*No URLs detected*")
    else:
        for u in urls:
            st.write(u)

    # Attachments listing
    eml_attachments = email_data.get("attachments", []) or []
    if eml_attachments:
        st.subheader("Attachments (parsed)")
        for a in eml_attachments:
            st.write(
                f"{a.get('filename')} — {a.get('content_type')} — {a.get('size', 0)} bytes — sha256: {a.get('sha256')}"
            )

    # ---------------- ONE BUTTON: local + LLM + report (REWRITTEN with redirect resolution) ----------------
    if st.button("Analyze & Generate Report"):
        from modules.redirect_resolver import resolve_url
        from urllib.parse import urlparse

        findings: Dict[str, Any] = {}
        enrich: Dict[str, Any] = {}
        oauths: Dict[str, Any] = {}
        attachments_info: Dict[str, Any] = {}
        source_ip_check: Dict[str, Any] = {}

        if (
            not urls
            and not eml_attachments
            and not (
                email_data.get("source_ip")
                or email_data.get("headers", {}).get("X-BESS-Apparent-Source-IP")
            )
        ):
            st.warning("No URLs, attachments or source IP to analyze.")
        else:
            progress = st.progress(0)
            total_items = max(1, len(urls))
            idx = 0
            st.info(
                "Running local checks (URL evasion, OAuth, redirect resolution, WHOIS, TLS, VirusTotal, MX blacklist, attachments)..."
            )

            # Per-URL analysis (with redirect resolution + final-domain enrichment)
            for u in urls:
                idx += 1
                enrich.setdefault(u, {})
                oauths.setdefault(u, {})

                # Local evasion heuristics (run on original URL)
                try:
                    findings[u] = detect_evasion_techniques(u)
                except Exception as e:
                    findings[u] = {"error": f"detect_evasion_techniques_error: {str(e)}"}

                # OAuth analysis on original URL (preserve original evidence)
                try:
                    oa = analyze_oauth_url(u)
                    oauths[u] = oa
                except Exception as e:
                    oauths[u] = {"error": str(e)}
                    oa = {}

                # Redirect resolution: attempt to resolve to final landing URL
                try:
                    final = resolve_url(u)
                    enrich[u]["resolved_final"] = final
                except Exception as e:
                    enrich[u]["resolved_final_error"] = str(e)
                    final = None

                # If we resolved a final landing URL, run VirusTotal on the final URL
                # and run WHOIS/TLS enrichment on the final domain only (privacy-preserving).
                if final:
                    try:
                        vt_res = vt_url_lookup_sync(final)
                        enrich[u]["virustotal"] = vt_res
                    except Exception as e:
                        enrich[u]["virustotal"] = {"vt_verified": False, "error": str(e)}

                    try:
                        final_host = urlparse(final).netloc
                    except Exception:
                        final_host = None

                    if final_host:
                        try:
                            enrich[u]["whois"] = whois_lookup(final_host)
                        except Exception as e:
                            enrich[u]["whois"] = {"error": str(e)}

                        try:
                            enrich[u]["tls"] = get_cert_info(final_host)
                        except Exception as e:
                            enrich[u]["tls"] = {"error": str(e)}
                    else:
                        enrich[u]["whois"] = {"note": "final_host_unparsable"}
                        enrich[u]["tls"] = {"note": "final_host_unparsable"}
                else:
                    # Resolution failed: mark enrichment as skipped for privacy/clarity
                    enrich[u]["virustotal"] = {"note": "resolution_failed"}
                    enrich[u]["whois"] = {"note": "resolution_failed"}
                    enrich[u]["tls"] = {"note": "resolution_failed"}

                # Update progress (avoid blocking sleeps — keep UI responsive)
                progress.progress(int((idx / total_items) * 100))

            # Attachments scanning via VirusTotal (unchanged)
            if eml_attachments:
                st.info("Scanning attachments with VirusTotal (may take a while)...")
                for i, att in enumerate(eml_attachments, start=1):
                    fname = att.get("filename") or "unknown"
                    size = att.get("size", 0)
                    sha = att.get("sha256")
                    attachments_info[fname] = {"size": size, "sha256": sha}
                    if scan_attachment_bytes is None:
                        attachments_info[fname]["virustotal"] = {
                            "error": "attachment_scanner_missing"
                        }
                        st.write(
                            f"[{i}/{len(eml_attachments)}] {fname}: scanner missing, skipped"
                        )
                        continue
                    try:
                        data_bytes = att.get("data") or b""
                        if data_bytes:
                            vt_file_res = scan_attachment_bytes(fname, data_bytes)
                            attachments_info[fname]["virustotal"] = vt_file_res
                        else:
                            attachments_info[fname]["virustotal"] = {
                                "error": "no_bytes_extracted"
                            }
                    except Exception as e:
                        attachments_info[fname]["virustotal"] = {"error": str(e)}
                    st.write(f"[{i}/{len(eml_attachments)}] {fname}: scanned")

            # Source IP MXToolbox blacklist check (unchanged)
            src_ip = email_data.get("source_ip") or email_data.get("headers", {}).get(
                "X-BESS-Apparent-Source-IP"
            )
            if src_ip:
                st.info(f"Checking source IP ({src_ip}) against MXToolbox blacklists...")
                try:
                    source_ip_check = mx_blacklists_sync(src_ip)
                except Exception as e:
                    source_ip_check = {"error": str(e)}
            else:
                source_ip_check = {"note": "no_source_ip_found"}

            # Store local results in session_state
                        # Store local results in session_state
            local_findings = {
                "findings": findings,
                "enrichment": enrich,
                "oauths": oauths,
                "attachments": attachments_info,
                "source_ip_check": source_ip_check,
                "urls": urls,
                "email_metadata": {
                    "subject": email_data.get("subject"),
                    "from": email_data.get("from"),
                    "to": email_data.get("to"),
                    "date": email_data.get("date"),
                    "source_ip": src_ip,
                },
                "run_at": int(time.time()),
            }

            malicious_found = False
            malicious_final_links = []

            for url, info in local_findings.get("enrichment", {}).items():
                vt_obj = info.get("virustotal") or {}
                verdict = (
                    vt_obj.get("verdict")
                    or vt_obj.get("result")
                    or vt_obj.get("vt_verdict")
                    or "unknown"
                )

                if verdict == "malicious":
                    malicious_found = True
                    final_url = info.get("resolved_final") or url
                    malicious_final_links.append(final_url)

            # ---------------------------------------------
            # SET is_phishing VARIABLE BASED ON MALICIOUS LINKS
            # ---------------------------------------------
            if malicious_found:
                prompt_obj_extra = {
                    "is_phishing": "malicious_link_with_wrapper_is_shared",
                    "malicious_final_links": malicious_final_links,
                }
            else:
                prompt_obj_extra = {}

            st.session_state["local_findings"] = local_findings

            # Display local outputs
            st.subheader("Local Findings (URL evasion & heuristics)")
            st.json(findings)

            st.subheader("WHOIS, TLS & VirusTotal Enrichment (per-URL)")
            st.json(enrich)

            st.subheader("OAuth Analysis (per-URL)")
            for u, oa in oauths.items():
                with st.expander(u):
                    st.json(oa)
                    try:
                        redirect_host = (
                            oa.get("redirect_host") if isinstance(oa, dict) else None
                        )
                        oauth_params = (
                            oa.get("oauth_params", {}) if isinstance(oa, dict) else {}
                        )
                        redirect_uri = oauth_params.get("redirect_uri") or ""
                    except Exception:
                        redirect_host = None
                        redirect_uri = ""
                    safe_display = html.escape(u)
                    decoded = ""
                    try:
                        decoded = unquote(redirect_uri)
                    except Exception:
                        decoded = redirect_uri or ""
                    highlighted = safe_display
                    if decoded and html.escape(decoded) in safe_display:
                        highlighted = safe_display.replace(
                            html.escape(decoded),
                            f"<span style='color:red;font-weight:bold'>{html.escape(decoded)}</span>",
                        )
                    elif redirect_host and html.escape(redirect_host) in safe_display:
                        highlighted = safe_display.replace(
                            html.escape(redirect_host),
                            f"<span style='color:red;font-weight:bold'>{html.escape(redirect_host)}</span>",
                        )
                    st.markdown(highlighted, unsafe_allow_html=True)

            if attachments_info:
                st.subheader("Attachment Scan Results (VirusTotal)")
                safe_attach_disp = {}
                for fname, info in attachments_info.items():
                    entry = {
                        "size": info.get("size"),
                        "sha256": info.get("sha256"),
                        "virustotal": info.get("virustotal"),
                    }
                    safe_attach_disp[fname] = entry
                st.json(safe_attach_disp)

            st.subheader("Source IP MXToolbox Blacklist Check")
            st.json(source_ip_check)

            # -------------- LLM: Sage reasoning --------------
            st.subheader("LLM Reasoning")

            # Build context for LLM: note the fix here — unpack prompt_obj_extra
            ctx = {
                "subject": local_findings.get("email_metadata", {}).get("subject"),
                "from": local_findings.get("email_metadata", {}).get("from"),
                "body": email_data.get("body_text")
                or email_data.get("body_html")
                or "",
                "urls": local_findings.get("urls", []),
                "local_findings": local_findings.get("findings", {}),
                "enrichment": local_findings.get("enrichment", {}),
                "oauths": local_findings.get("oauths", {}),
                "attachments": local_findings.get("attachments", {}),
                "source_ip_check": local_findings.get("source_ip_check", {}),
                **prompt_obj_extra,   # <- CORRECT: unpack the extra fields here
            }

            with st.spinner("Contacting Sage LLM..."):
                try:
                    llm = analyze_with_sage(ctx)
                    indicators = _extract_regex_indicators_from_llm(llm)
                    st.session_state["llm_analysis"] = {
                        "raw": llm,
                        "indicators": indicators,
                        "run_at": int(time.time()),
                    }

                    st.subheader("Raw LLM Response")
                    if isinstance(llm, dict):
                        st.json(llm)
                    else:
                        st.code(str(llm))

                    if not indicators:
                        st.warning("No `regex_indicator` entries found in LLM response.")
                    else:
                        st.subheader("Regex Indicators (copy-ready blocks)")
                        edited_blocks: List[str] = []
                        for idx_ind, ind in enumerate(indicators, start=1):
                            title = f"Indicator {idx_ind}"
                            try:
                                first_h = (ind.get("highlights") or [None])[0]
                                if first_h:
                                    title += f" — {first_h}"
                            except Exception:
                                pass
                            with st.expander(title, expanded=False):
                                try:
                                    block = _format_indicator_as_block(ind)
                                    st.markdown("**Preview (read-only)**")
                                    st.code(block, language=None)
                                    ta_key = f"indicator_edit_{idx_ind}"
                                    initial = st.session_state.get(ta_key, block)
                                    # If you later want editable blocks, add a text_area here.
                                except Exception as e:
                                    st.error(f"Failed to render indicator {idx_ind}: {e}")
                                    st.write(ind)
                        if edited_blocks:
                            st.session_state["llm_analysis"]["edited_blocks"] = edited_blocks

                except Exception as e:
                    st.error(f"LLM analysis failed: {e}")
                    st.error(traceback.format_exc())
                    st.warning(
                        "Skipping LLM-based reasoning due to the error above; "
                        "the report will be generated from local enrichment only."
                    )
                    # Ensure llm_analysis exists so report builder doesn't explode
                    st.session_state["llm_analysis"] = {}


            # -------------- Build and show professional report (same click) --------------
            try:
                out = {
                    "email_metadata": local_findings.get("email_metadata", {}),
                    "enrichment": local_findings.get("enrichment", {}),
                    "oauths": local_findings.get("oauths", {}),
                    "source_ip_check": local_findings.get("source_ip_check", {}),
                    "attachments": local_findings.get("attachments", {}),
                    "llm_analysis": st.session_state.get("llm_analysis", {}),
                    "exported_at": int(time.time()),
                }

                report_md = build_professional_report_from_export(out)

                st.subheader("Professional Report Preview")
                st.markdown(report_md, unsafe_allow_html=True)

                stamp = int(time.time())
                md_name = f"phish_report_{stamp}.md"
                txt_name = f"phish_report_{stamp}.txt"

                st.download_button(
                    "Download report (Markdown)",
                    data=report_md,
                    file_name=md_name,
                    mime="text/markdown",
                )
                st.download_button(
                    "Download report (Plain text)",
                    data=report_md,
                    file_name=txt_name,
                    mime="text/plain",
                )
                st.success("Report generated successfully (local + LLM) in one click.")
            except Exception as e:
                st.error(f"Failed to prepare final report: {e}")
                st.error(traceback.format_exc())

# End of file