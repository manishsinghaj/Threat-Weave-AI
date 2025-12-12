# --------------------------
# FILE: report_generator.py
# --------------------------
"""Report generation helpers migrated from app_streamlit.py.

Public API:
- build_professional_report_from_export(out: Dict[str, Any]) -> str
- save_report_files(report_md: str, dest_dir: Optional[str]=None, stamp: Optional[int]=None) -> Dict[str, str]
- generate_report(email_data, analysis_bundle, out_path)  # legacy compatibility

Additionally, a few helper functions are exported for reuse in the app.
"""

import json
import os
import time
from typing import Any, Dict, List, Optional

# ---- Helpers that were previously embedded in app_streamlit.py ----

def extract_regex_indicators_from_llm(llm_resp: Any) -> List[Dict[str, Any]]:
    """Thin wrapper that reuses the extraction logic. Kept small and robust."""
    # Re-implement minimal logic originally used in the app.
    try:
        if isinstance(llm_resp, dict) and "regex_indicator" in llm_resp:
            val = llm_resp.get("regex_indicator") or []
            if isinstance(val, list):
                return val
    except Exception:
        pass
    # Fallback: attempt to parse JSON if possible
    try:
        if isinstance(llm_resp, str):
            parsed = json.loads(llm_resp)
            if isinstance(parsed, dict) and "regex_indicator" in parsed:
                return parsed.get("regex_indicator") or []
    except Exception:
        pass
    return []


def _escape_for_block(s: str) -> str:
    if s is None:
        return ""
    s = str(s)
    s = s.replace('"""', '\\"""')
    s = s.replace('"', '\\"')
    s = s.replace('\\', '\\\\')
    return s


def format_indicator_as_block(indicator: Dict[str, Any]) -> str:
    """Produce a YAML-like triple-quoted block for an indicator (used in the UI)."""
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

    scalar_order = ["or", "regex", "type", "normalized", "headless", "determination", "description"]
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
            hid = str(h).replace('\\', '\\\\')
            lines.append(f"      - {hid}")
    else:
        lines.append("      - NONE")

    lines.append('"""')
    return "\n".join(lines)

# Export small helpers so app_streamlit can call them
extract_regex_indicators_from_llm = extract_regex_indicators_from_llm
format_indicator_as_block = format_indicator_as_block

# ----- The big report builder (migrated) -----

def _safe_list_names(vendors_obj) -> str:
    if not vendors_obj:
        return ""
    if isinstance(vendors_obj, dict):
        return ", ".join(sorted([str(k) for k in vendors_obj.keys()]))
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
                    if item:
                        names.append(next(iter(item.keys())))
        return ", ".join([n for n in names if n])
    return str(vendors_obj)


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
    defaults = {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0}
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
    try:
        ct = (ainfo.get("content_type") or ainfo.get("mime_type") or "").lower()
        if isinstance(ct, str) and ct.startswith("image/"):
            return True
        if ainfo.get("is_image") in (True, "true", "True"):
            return True
        if name and isinstance(name, str):
            lname = name.lower()
            for ext in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".ico"):
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


def build_professional_report_from_export(out: Dict[str, Any]) -> str:
    """Build textual report (Markdown/plain text) from export JSON matching user's template."""
    em = out.get("email_metadata", {}) or {}
    llm_top = out.get("llm_analysis", {}) or {}
    llm_raw = llm_top.get("raw") if isinstance(llm_top, dict) and llm_top.get("raw") else (llm_top or {})
    enrichment = out.get("enrichment", {}) or {}
    oauths = out.get("oauths", {}) or {}
    attachments = out.get("attachments", {}) or {}
    src_check = out.get("source_ip_check", {}) or {}

    lines: List[str] = []
    lines.append("# Analysis\n")
    attack_type = llm_raw.get("Type_of_Attack") or llm_raw.get("phishing_type") or llm_raw.get("type") or "Unknown"
    lines.append(f"**This is a {attack_type} email**\n")
    lines.append(f"**Subject**: {em.get('subject') or 'N/A'}\n")
    lines.append(f"**From**: {em.get('from') or 'N/A'}\n")
    lines.append(f"**To**: {em.get('to') or 'N/A'}\n")
    lines.append(f"**Source Ip**: {em.get('source_ip') or 'N/A'}\n")
    lines.append("\n")

    lines.append(f"**Type of Phishing**: {llm_raw.get('phishing_type') or llm_raw.get('Type_of_Attack','N/A')}\n")
    lines.append(f"**Description**: {llm_raw.get('Brief_summary') or llm_raw.get('description', '')}\n")
    techniques = llm_raw.get('techniques') or llm_raw.get('URL_Evasion Techniques') or llm_raw.get('techniques_used') or []
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
            verdict = vt_candidate.get("verdict") or vt_candidate.get("result") or vt_candidate.get("vt_verdict") or "unknown"
            sc = _vt_summary_counts(vt_candidate)
            lines.append(f"- **Verdict**: {verdict}")
            lines.append(f"- **Malicious**: {sc.get('malicious', 0)}")
            lines.append(f"- **Suspicious**: {sc.get('suspicious', 0)}")
            lines.append(f"- **Undetected**: {sc.get('undetected', 0)}")
            lines.append(f"- **Harmless**: {sc.get('harmless', 0)}")
            flagged_names = _flagged_vendor_names_from_vt(vt_candidate)
            lines.append(f"- **Flagged Vendors**: {', '.join(flagged_names) if flagged_names else 'None'}")
            w = info.get("whois") or {}
            if isinstance(w, dict) and (w.get("domain_name") or w.get("query")):
                domain = w.get("domain_name") or w.get("query")
                lines.append(f"- **Whois Domain**: {domain}")
                lines.append(f"  - Creation Date: {_format_date_field(w.get('creation_date'))}")
                lines.append(f"  - Expiration Date: {_format_date_field(w.get('expiration_date') or w.get('expiry_date'))}")
            lines.append("\n")

    # Attachments: ONLY display QR/Decoded blocks for image attachments
    image_qr_entries: List[Dict[str, Any]] = []
    for name, ainfo in attachments.items():
        try:
            if not isinstance(ainfo, dict):
                ainfo = {} if ainfo is None else ainfo
            if _is_attachment_image(name, ainfo):
                qr = (
                    ainfo.get("qr_data")
                    or ainfo.get("qr")
                    or (ainfo.get("virustotal") or {}).get("qr_data")
                    or (ainfo.get("virustotal") or {}).get("qr")
                    or (ainfo.get("virustotal") or {}).get("data", {}).get("qr")
                )
                if qr:
                    vt_obj = ainfo.get("virustotal") or ainfo
                    sc = _vt_summary_counts(vt_obj)
                    fvs = _flagged_vendor_names_from_vt(vt_obj)
                    image_qr_entries.append({
                        "name": name,
                        "qr": qr,
                        "counts": sc,
                        "flagged": fvs,
                    })
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
            lines.append(f"- Flagged Vendors : {', '.join(entry['flagged']) if entry['flagged'] else 'None'}")
            lines.append("\n")
    else:
        any_images = any(_is_attachment_image(n, a) for n, a in attachments.items())
        if any_images:
            lines.append("## QR/Decoded Payloads (image attachments)\n")
            lines.append("_Image attachments present but no QR/decoded payloads detected._\n")

    # OAuth Analysis
    lines.append("## OAuth Analysis\n")
    if not oauths:
        lines.append("_No OAuth patterns detected_\n")
    else:
        for u, oa in oauths.items():
            lines.append(f" URL: {u}\n")
            params = oa.get("oauth_params") or oa.get("params") or {}
            redirect_uri = params.get("redirect_uri") or oa.get("redirect_uri") or params.get("redirect") or ""
            client_id = params.get("client_id") or params.get("clientid") or oa.get("client_id") or "N/A"
            if redirect_uri:
                lines.append(f"- Redirected Url : {redirect_uri}")
            elif oa.get("redirect_host"):
                lines.append(f"- Redirect Host : {oa.get('redirect_host')}")
            lines.append(f"- Client Id : {client_id}")
            lines.append("\n")

    # WHOIS summary
    lines.append("## WhoIs Data (summary)\n")
    collected = []
    for url, info in enrichment.items():
        try:
            w = info.get("whois")
            if w and isinstance(w, dict):
                domain = w.get("domain_name") or w.get("query") or w.get("domain")
                if domain and domain not in collected:
                    collected.append(domain)
                    lines.append(f"- Domain : {domain}")
                    lines.append(f"  - Creation Date: {_format_date_field(w.get('creation_date'))}")
                    lines.append(f"  - Expiration Date: {_format_date_field(w.get('expiration_date'))}")
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
                lines.append(f"  - Issuer: {t.get('issuer') or t.get('certificate_issuer') or 'N/A'}")
                lines.append(f"  - Subject: {t.get('subject') or 'N/A'}")
                lines.append(f"  - Licence From : {_format_date_field(t.get('not_before'))}")
                lines.append(f"  - Licence To : {_format_date_field(t.get('not_after'))}")
        except Exception:
            pass
    if not tls_collected:
        lines.append("_No TLS data available_\n")

    # MX Toolbox Blacklisting
    lines.append("\n## MXToolbox Blacklisting\n")
    blacklisted_val = src_check.get('blacklisted_count', src_check.get('blacklisted', False))
    lines.append(f"- Black Listed : {blacklisted_val}")
    providers = src_check.get('listed_providers') or src_check.get('providers') or []
    if providers:
        if isinstance(providers, (list, tuple)):
            ptxt = ", ".join(map(str, providers))
        else:
            ptxt = str(providers)
        lines.append(f"- Providers : {ptxt}")
    else:
        lines.append("- Providers : None")

    # Recommended actions
    recommended = llm_raw.get("recommended_actions") or llm_raw.get("recommended_action") or llm_raw.get("recommended", []) or []
    if recommended:
        lines.append("\n---\n")
        lines.append("## Recommended Actions\n")
        if isinstance(recommended, (list, tuple)):
            for r in recommended:
                lines.append(f"- {r}")
        else:
            lines.append(str(recommended))

    # Timestamp
    lines.append(f"\n_Report generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC_\n")

    return "\n".join(lines)


def save_report_files(report_md: str, dest_dir: Optional[str] = None, stamp: Optional[int] = None) -> Dict[str, str]:
    """Save the markdown and plain text versions to disk. Returns dict with file paths."""
    if dest_dir is None:
        dest_dir = os.getcwd()
    os.makedirs(dest_dir, exist_ok=True)
    if stamp is None:
        stamp = int(time.time())
    md_name = f"phish_report_{stamp}.md"
    txt_name = f"phish_report_{stamp}.txt"
    md_path = os.path.join(dest_dir, md_name)
    txt_path = os.path.join(dest_dir, txt_name)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(report_md)
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write(report_md)
    return {"md": md_path, "txt": txt_path}


def generate_report(email_data, analysis_bundle, out_path):
    """Legacy compatibility function. Creates a JSON bundle like previous tool and writes it."""
    report = {
        'subject': email_data.get('subject'),
        'from': email_data.get('from'),
        'to': email_data.get('to'),
        'urls': email_data.get('urls'),
        'analysis': analysis_bundle
    }
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    return out_path