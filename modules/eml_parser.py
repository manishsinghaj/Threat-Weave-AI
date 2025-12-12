#!/usr/bin/env python3
"""
modules/eml_parser.py — Improved EML parser for full URL extraction and attachment extraction.
"""
from __future__ import annotations

import re
import html
import base64
import quopri
import hashlib
from typing import List, Dict, Any, Optional
from email import policy
from email.parser import BytesParser
from email.header import decode_header, make_header
from email.utils import getaddresses
from bs4 import BeautifulSoup

# Regex robust enough to catch complex tracking URLs
URL_RE = re.compile(
    r'((?:https?://|http://|www\.)[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+)',
    re.IGNORECASE
)

def _is_cid_url(u: str) -> bool:
    """
    Return True if the URL-like string is an inline/cid reference that should not be
    treated as an external URL (e.g., "cid:1234", "content-id:...").
    Also skips data: and mailto: URIs.
    """
    if not u:
        return False
    u = str(u).strip().lower()
    if u.startswith("cid:") or u.startswith("content-id:"):
        return True
    if u.startswith("data:"):
        return True
    if u.startswith("mailto:"):
        return True
    return False

def _decode_text(payload: Optional[str]) -> str:
    """Decode text from quoted-printable or base64 safely."""
    if not payload:
        return ""
    text = payload

    # Quoted-printable signatures
    if "=3D" in text or "=\r\n" in text or "=\n" in text:
        try:
            text = quopri.decodestring(text).decode("utf-8", errors="ignore")
        except Exception:
            pass

    # Try base64 block decode if it looks like base64
    try:
        s = text.strip()
        if s and re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", s) and len(s) % 4 == 0:
            decoded = base64.b64decode(s)
            dec_str = decoded.decode("utf-8", errors="ignore")
            printable_ratio = sum(1 for c in dec_str if c.isprintable()) / max(1, len(dec_str))
            if printable_ratio > 0.8:
                text = dec_str
    except Exception:
        pass

    return text

def _decode_mime_header(value: Optional[str]) -> str:
    """Decode MIME-encoded header like Subject, From, To."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value

def extract_urls_from_html(html_data: str) -> List[str]:
    """Extract URLs from HTML content (tags + fallback regex). Skip inline/cid/data URIs."""
    if not html_data:
        return []

    decoded_html = _decode_text(html_data)
    decoded_html = decoded_html.replace("=\r\n", "").replace("=\n", "")
    decoded_html = html.unescape(decoded_html)

    soup = BeautifulSoup(decoded_html, "html.parser")
    urls = set()

    # tags with href/src/action - but skip cid/data/content-id entries
    for tag in soup.find_all(["a", "link"], href=True):
        href = tag.get("href")
        if href and not _is_cid_url(href):
            urls.add(href)
    for tag in soup.find_all(["img", "script", "iframe"], src=True):
        src = tag.get("src")
        if src and not _is_cid_url(src):
            urls.add(src)
    for tag in soup.find_all("form", action=True):
        action = tag.get("action")
        if action and not _is_cid_url(action):
            urls.add(action)

    # fallback regex scan
    for m in re.findall(URL_RE, decoded_html):
        if m and not _is_cid_url(m):
            urls.add(m)

    # normalize
    clean_urls = []
    for u in urls:
        if not u:
            continue
        u = html.unescape(str(u)).strip().replace("\r", "").replace("\n", "")
        u = u.replace("=3D", "=")
        if u.startswith("www."):
            u = "http://" + u
        clean_urls.append(u)
    return list(dict.fromkeys(clean_urls))

def extract_urls_from_text(text: str) -> List[str]:
    """Extract URLs from plain text body. Skip inline/cid/data URIs."""
    if not text:
        return []

    decoded_text = _decode_text(text)
    decoded_text = decoded_text.replace("=\r\n", "").replace("=\n", "")
    decoded_text = html.unescape(decoded_text)

    found = re.findall(URL_RE, decoded_text)
    clean = []
    for u in found:
        if not u:
            continue
        u = html.unescape(u.strip().replace("\r", "").replace("\n", ""))
        u = u.replace("=3D", "=")
        # skip cid/data/content-id/mailto URIs
        if _is_cid_url(u):
            continue
        if u.startswith("www."):
            u = "http://" + u
        clean.append(u)
    return list(dict.fromkeys(clean))

def _sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def parse_eml(file_path: str) -> Dict[str, Any]:
    """
    Parse EML and return a structured dict with:
    - headers, from, to, subject, date, source_ip
    - body_text (preview), body_html (preview)
    - urls (list)
    - attachments: list of {filename, content_type, size, sha256, data}
    """
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # Raw headers
    headers = dict(msg.items())

    # Decode standard headers
    from_header_raw = msg.get("From", "") or ""
    subject_raw = msg.get("Subject", "") or ""
    date_raw = msg.get("Date", "") or ""

    from_header = _decode_mime_header(from_header_raw)
    subject = _decode_mime_header(subject_raw)
    date = _decode_mime_header(date_raw)

    # ---- NEW: To header extraction ----
    to_headers_raw = msg.get_all("To", []) or []
    # getaddresses handles multiple "To" lines and "Name <addr>" format
    to_parsed = getaddresses(to_headers_raw)
    # just email addresses
    to_emails = [addr for name, addr in to_parsed if addr]
    # string form for your UI
    to_str = ", ".join(to_emails)

    # X-BESS-Apparent-Source-IP compatibility
    source_ip = (
        headers.get("X-BESS-Apparent-Source-IP", "")
        or headers.get("X-BESS-Apparent-SourceIP", "")
        or ""
    )

    body_text = ""
    body_html = ""
    attachments: List[Dict[str, Any]] = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = (part.get_content_disposition() or "") or ""
            filename = part.get_filename()
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None

            # gather inline text/html
            if ctype in ("text/plain", "text/html") and "attachment" not in disp:
                if payload:
                    try:
                        decoded = payload.decode("utf-8", errors="ignore")
                    except Exception:
                        decoded = str(payload)
                    if ctype == "text/html":
                        body_html += decoded
                    else:
                        body_text += decoded

            # attachments (including embedded images)
            if filename or disp == "attachment" or (payload and ctype not in ("text/plain", "text/html")):
                try:
                    b = payload or b""
                    fname = filename or (part.get("Content-Location") or "unknown")
                    sha = _sha256_bytes(b) if b else None
                    attachments.append({
                        "filename": fname,
                        "content_type": ctype,
                        "size": len(b),
                        "sha256": sha,
                        "data": b
                    })
                except Exception:
                    continue
    else:
        # singlepart
        ctype = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
        except Exception:
            payload = None
        if payload:
            try:
                decoded = payload.decode("utf-8", errors="ignore")
            except Exception:
                decoded = str(payload)
            if ctype == "text/html":
                body_html = decoded
            else:
                body_text = decoded

    # Extract URLs
    urls = set()
    urls.update(extract_urls_from_text(body_text or ""))
    urls.update(extract_urls_from_html(body_html or ""))

    return {
        "from": from_header,
        "to": to_str,              # <-- what Streamlit uses
        "to_emails": to_emails,    # <-- extra, if you need pure list
        "subject": subject,
        "date": date,
        "source_ip": source_ip,
        "urls": list(urls),
        "body_text": (body_text or "")[:2000],
        "body_html": (body_html or "")[:2000],
        "headers": headers,
        "attachments": attachments,
    }

if __name__ == "__main__":
    import sys, json
    if len(sys.argv) > 1:
        out = parse_eml(sys.argv[1])
        print(json.dumps(out, indent=2, default=str))
