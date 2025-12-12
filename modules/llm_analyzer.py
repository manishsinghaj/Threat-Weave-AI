# modules/llm_analyzer.py
"""
LLM wrapper for ThreatWeaveAI — updated to accept precomputed VT signals from the caller
and *force* phishing classification when a VT malicious verdict is present.

Key behavior changes:
- If the incoming `context` already contains:
    - context["is_phishing"] == "malicious_link_with_wrapper_is_shared"
    OR
    - context["VT_MALICIOUS_FOUND"] == True
  then the prompt will instruct the model to force Type_of_Attack = "Phishing" and
  to emit regex indicators for the provided malicious_final_links (if any).
- If those precomputed signals are not present, the LLM will still check enrichment
  inside the provided context and enforce the same rule if it finds VT malicious verdicts.
"""

import os
import json
import re
import requests
import time
from typing import Any, Dict, List, Optional
from config import settings
from modules.oauth_analyzer import analyze_oauth_url

SAGE_URL = settings.SAGE_API_URL
API_KEY = settings.SAGE_API_KEY

# small helper to extract a JSON object from a string (first {...} block)
def _extract_json_block(s: str) -> Optional[Dict[str, Any]]:
    if not isinstance(s, str):
        return None
    start = s.find('{')
    if start == -1:
        return None
    for end in range(len(s), start, -1):
        if s[end - 1] != '}':
            continue
        candidate = s[start:end]
        try:
            return json.loads(candidate)
        except Exception:
            continue
    return None


def _precompute_vt_signals(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Examine ctx['local_findings']['enrichment'] (or ctx['enrichment']) and compute:
      - VT_MALICIOUS_FOUND (bool)
      - malicious_final_links (list of canonical final URLs)
    Also respect any incoming override flags in ctx (e.g., ctx['is_phishing'] string).
    """
    out = {"VT_MALICIOUS_FOUND": False, "malicious_final_links": []}

    # Respect explicit override if present
    if ctx.get("is_phishing") == "malicious_link_with_wrapper_is_shared":
        out["VT_MALICIOUS_FOUND"] = True
        # If malicious_final_links provided use them
        mfl = ctx.get("malicious_final_links") or ctx.get("malicious_urls") or []
        out["malicious_final_links"] = list(dict.fromkeys(mfl)) if mfl else []

    # If not overridden, scan enrichment fields
    enrichment = {}
    # support both shapes
    if isinstance(ctx.get("local_findings"), dict):
        enrichment = ctx["local_findings"].get("enrichment") or {}
    enrichment = enrichment or ctx.get("enrichment") or {}

    for u, info in (enrichment or {}).items():
        try:
            vt_obj = info.get("virustotal") or {}
            verdict = (
                vt_obj.get("verdict")
                or vt_obj.get("result")
                or vt_obj.get("vt_verdict")
                or "unknown"
            )
            # summary_counts.malicious or non-empty flagged_vendors are also treated as malicious
            sc_mal = 0
            try:
                sc = vt_obj.get("summary_counts") or {}
                sc_mal = int(sc.get("malicious", 0)) if isinstance(sc, dict) else 0
            except Exception:
                sc_mal = 0
            fv = vt_obj.get("flagged_vendors") or (vt_obj.get("virustotal") or {}).get("flagged_vendors") or {}
            fv_nonempty = bool(isinstance(fv, dict) and len(fv.keys()) > 0)

            if verdict == "malicious" or sc_mal > 0 or fv_nonempty:
                out["VT_MALICIOUS_FOUND"] = True
                final = info.get("resolved_final") or u
                out["malicious_final_links"].append(final)
        except Exception:
            continue

    # dedupe
    out["malicious_final_links"] = list(dict.fromkeys(out["malicious_final_links"]))
    return out


def analyze_with_sage(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry: context is expected to contain keys from the app (subject, body, urls,
    local_findings/enrichment, attachments, etc.). This function:
      - computes VT signals (unless provided)
      - builds a strict prompt that forces the model to honor the VT-driven phishing rule
      - calls the Sage endpoint and returns the parsed JSON (or helpful error)
    """
    if not API_KEY:
        return {"error": "SAGE_API_KEY not set. Please set it in .env or config/settings.py"}

    body = context.get("body", "") or ""
    subject = context.get("subject", "") or ""
    urls = context.get("urls", []) or []
    local_findings = context.get("local_findings") or {}

    # compute VT-driven signals (or respect overrides in context)
    vt_signals = _precompute_vt_signals(context)
    VT_MALICIOUS_FOUND = vt_signals.get("VT_MALICIOUS_FOUND", False)
    MALICIOUS_URLS = vt_signals.get("malicious_final_links", [])

    # Prepare OAuth analyses for the urls provided (informational, included in prompt)
    oauth_analyses = []
    for u in urls:
        try:
            oauth_analyses.append(analyze_oauth_url(u))
        except Exception as e:
            oauth_analyses.append({"url": u, "error": str(e)})

    # Construct the prompt object that will be embedded in the prompt. Include computed flags
    prompt_obj = {
        "task": "Threat Analysis of Potential Malicious/Suspicious Email",
        "subject": subject,
        "body_snippet": body[:2000],
        "urls": urls,
        "local_findings": local_findings,
        "oauth_analysis": oauth_analyses,
        "VT_MALICIOUS_FOUND": VT_MALICIOUS_FOUND,
        "malicious_final_links": MALICIOUS_URLS,
        # include any explicit override string the caller might have provided
        "is_phishing_override": context.get("is_phishing"),
    }

    prompt = f"""
        You are a cybersecurity analyst LLM. Analyze the input and return ONLY a JSON object with fields:
        Type of Attack (Taxonomy_list: Account Takeover, Conversation Hijacking, Business Email Compromise (BEC), Phishing, Spam, Extortion), 
        is_phishing (bool), phishing_type (string), confidence_score (0-100),
        Brief_summary (Generate 1–2 concise technical paragraphs explaining the EML sample, describing how the attacker attempts to harvest data, and summarizing key details from the email body and local_findings.) 
        techniques (list), ioc_domains (list),
        recommended_actions (2–3 strings), URL_Evasion Techniques (list), 
        regex_indicator (list of objects), Phaas_kit (string),
        prompt_tokens (integer), completion_tokens (integer), total_tokens (integer).

        Output STRICTLY one JSON object — no prose, no explanations, no code fences, no extra fields.

        Use the provided inputs (body, subject, urls, local_findings, etc.) to populate the fields.

        SPECIAL RULE: If `prompt_obj_extra` is provided, the message is 100% phishing — set Type_of_Attack="Phishing" and is_phishing=true automatically.

        CRITICAL RULE: Only generate `regex_indicator` entries when `Type_of_Attack` is exactly "Phishing". 
        For all other types (Ham, BEC, etc.), `regex_indicator` must be an empty array or omitted.

        Regex / Indicator Construction Rules:
        1) Evidence-first: Derive indicators ONLY from data present in local_findings 
           (suspicious_urls, redirect_traces, attachment names/hashes, header anomalies). 
           Do NOT invent indicators.

        2) Regex formatting:
           - Anchor URLs with ^ and escape slashes (use \\/).
           - For OAuth `redirect_uri` or encoded params, retain percent-encoded form (redirect_uri=https%3A%2F%2F).
           - Avoid greedy `.*`; use bounded classes like [^#\\s]* or [^&]*.
           - Example pattern:
             ^https:\\/\\/login\\.microsoftonline\\.com\\/organizations\\/oauth2\\/v2\\.0\\/authorize\\?[^#\\s]*redirect_uri=https%3A%2F%2F(?:[\\w.-]+\\.)?tetainternational\\.com(?:%2F[^\\s]*)?

        3) Normalization:
           - If matching encoded/obfuscated fragments, set "normalized": false.
           - If matching canonical paths/hosts, set "normalized": true.

        4) Headless vs full:
           - headless=false for patterns requiring full URL inspection.
           - headless=true only for header-only checks.
           - determination must be SUSPICIOUS or MALICIOUS (all caps).

        5) Highlight Tags:
           - Use short uppercase identifiers.
           - OAuth indicators should use H- style tags, e.g., H-MS-OAUTH-TETAINTERNATIONAL-REDIRECT.

        6) Benign Host Rule:
           - If top-level host is a known benign provider (microsoftonline.com, google.com, link wrappers), 
             DO NOT create domain indicators for it.
           - Instead analyze embedded domains, redirect_uri parameters, encoded payloads.

        7) regex_indicator object fields (when present):
           - strings (array of regex/literal strings, escaped, anchored)
           - or (boolean)
           - regex (boolean)
           - type ("URL", "HTML", "ATTACHMENT")
           - normalized (boolean)
           - headless (boolean)
           - determination ("SUSPICIOUS" or "MALICIOUS")
           - description (short 1-sentence explanation)
           - highlights (array of uppercase highlight IDs)

        8) Additional constraints:
           - recommended_actions must include exactly 2–3 meaningful actions.
           - URL_Evasion Techniques must reflect actual observed evasion patterns.
           - Do NOT produce regex_indicator entries for benign/clean content.
           - Use "or" correctly for alternative regex forms.

        Return only the JSON object following all rules above.
        Input: {json.dumps(prompt_obj)}
        """

    # JSON schema used for structured-response validation (left as-is to guide model)
    response_schema = {
        "type": "object",
        "properties": {
            "Type_of_Attack": {"type": "string"},
            "is_phishing": {"type": "boolean"},
            "phishing_type": {"type": "string"},
            "confidence_score": {"type": "number"},
            "Brief_summary": {"type": "string"},
            "techniques": {"type": "array", "items": {"type": "string"}},
            "ioc_domains": {"type": "array", "items": {"type": "string"}},
            "recommended_actions": {"type": "array", "items": {"type": "string"}},
            "Phaas_kit": {"type": ["string", "null"]},
            "regex_indicator": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "strings": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                        "or": {"type": "boolean"},
                        "regex": {"type": "boolean"},
                        "type": {"type": "string", "enum": ["URL", "HTML", "ATTACHMENT"]},
                        "normalized": {"type": "boolean"},
                        "headless": {"type": "boolean"},
                        "determination": {"type": "string", "enum": ["SUSPICIOUS", "MALICIOUS", "CLEAN"]},
                        "description": {"type": "string"},
                        "highlights": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["strings", "regex", "type", "normalized", "headless", "determination"],
                },
            },
            "completion_tokens": {"type": "integer"},
            "prompt_tokens": {"type": "integer"},
            "total_tokens": {"type": "integer"},
        },
        "required": [
            "Type_of_Attack",
            "is_phishing",
            "phishing_type",
            "confidence_score",
            "completion_tokens",
            "prompt_tokens",
            "total_tokens",
        ],
    }

    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    data = {
        "model": "gpt-5",
        "messages": [
            {"role": "system", "content": "You are a cybersecurity analyst."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "phish_analysis", "schema": response_schema},
        },
    }

    try:
        r = requests.post(SAGE_URL, headers=headers, json=data, timeout=120)
    except Exception as e:
        return {"error": f"HTTP request failed: {e}"}

    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}", "raw": r.text}

    try:
        resp = r.json()
    except Exception:
        return {"error": "Response not JSON", "raw": r.text}

    # 1) If the API returned a top-level JSON object (ideal)
    if isinstance(resp, dict):
        # Some systems may place the object directly
        if "Type_of_Attack" in resp or "is_phishing" in resp:
            return resp

    # 2) Check for OpenAI-like "choices" structure where content is a string
    try:
        choices = resp.get("choices") or resp.get("results") or None
        if isinstance(choices, list) and len(choices) > 0:
            content = None
            first = choices[0]
            if isinstance(first, dict):
                msg = first.get("message") or first.get("text") or first.get("output_text") or first
                if isinstance(msg, dict):
                    content = msg.get("content") or msg.get("text") or None
                elif isinstance(msg, str):
                    content = msg
                else:
                    content = first.get("text") or first.get("message")
            if content is None and isinstance(first, str):
                content = first

            if isinstance(content, str):
                # direct JSON parse
                try:
                    parsed = json.loads(content)
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    pass

                # try to extract {...} block
                parsed = _extract_json_block(content)
                if parsed:
                    return parsed

                # attempt to unescape nested "content" fields
                try:
                    m = re.search(r'"content"\s*:\s*"(\\\{.*?\\\})"', content, flags=re.DOTALL)
                    if m:
                        candidate = m.group(1).encode("utf-8").decode("unicode_escape")
                        parsed = json.loads(candidate)
                        if isinstance(parsed, dict):
                            return parsed
                except Exception:
                    pass

    except Exception:
        pass

    # Final fallback return raw response for debugging
    return {"error": "Could not parse model output as JSON object", "raw_response": resp}
