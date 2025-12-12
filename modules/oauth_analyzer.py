
import urllib.parse as urlparse
from urllib.parse import parse_qs, unquote
import tldextract, re
from modules.whois_enrich import whois_lookup
from modules.tls_enrich import get_cert_info

KNOWN_OAUTH_PROVIDERS = {
    "login.microsoftonline.com",
    "accounts.google.com",
    "login.microsoft.com",
    "login.salesforce.com",
    "login.live.com",
    "identity.microsoftonline.com",
}

REDIRECT_ALLOWLIST = {
    "yourcompany.com",
    "microsoft.com",
    "docusign.com",
    "office.com",
    "sharepoint.com"
}

REDIRECT_PARAM_NAMES = {"redirect_uri","redirect","return","next","url","continue","callback","reply_to"}

def extract_oauth_params(url):
    parsed = urlparse.urlparse(url)
    params = parse_qs(parsed.query)
    findings = {}
    for name in REDIRECT_PARAM_NAMES.union({"client_id","response_type","state"}):
        if name in params:
            findings[name] = params[name][0]
    return findings

def normalize_and_decode_uri(uri):
    if not uri:
        return uri
    done = uri
    for _ in range(3):
        prev = done
        try:
            done = unquote(prev)
        except Exception:
            done = prev
        if done == prev:
            break
    return done

def get_etld1(host):
    ext = tldextract.extract(host)
    return ext.registered_domain or host

def analyze_oauth_url(url):
    res = {"url": url, "oauth_params": {}, "redirect_host": None, "redirect_etld1": None,
           "initial_host": None, "risk_flags": [], "enrichment": {}}

    parsed = urlparse.urlparse(url)
    res["initial_host"] = parsed.netloc.lower()
    params = extract_oauth_params(url)
    res["oauth_params"] = params

    redirect_val = None
    for k in REDIRECT_PARAM_NAMES:
        if k in params:
            redirect_val = params[k]
            break

    if redirect_val:
        norm = normalize_and_decode_uri(redirect_val)
        try:
            r_parsed = urlparse.urlparse(norm if '://' in norm else 'http://' + norm)
            redirect_host = r_parsed.netloc.lower()
        except Exception:
            redirect_host = norm
        res["redirect_host"] = redirect_host
        res["redirect_etld1"] = get_etld1(redirect_host)

        if res["initial_host"] in KNOWN_OAUTH_PROVIDERS:
            if res["redirect_etld1"] not in REDIRECT_ALLOWLIST:
                res["risk_flags"].append("oauth_provider_with_untrusted_redirect")

        if re.search(r"[^a-z0-9.:-]", redirect_host):
            res["risk_flags"].append("non_ascii_or_unusual_chars_in_redirect_host")
        if any(x in redirect_host for x in ["blob.core.windows.net","s3.amazonaws.com"]):
            res["risk_flags"].append("cloud_storage_redirect")

        try:
            who = whois_lookup(redirect_host)
            tls = get_cert_info(redirect_host)
            res["enrichment"] = {"whois": who, "tls": tls}
        except Exception as e:
            res["enrichment"] = {"error": str(e)}

    if "client_id" in params and res.get("redirect_etld1"):
        res["client_id"] = params.get("client_id")
        if re.match(r"^[0-9a-fA-F-]{20,}$", str(params.get("client_id"))):
            res["risk_flags"].append("valid_format_client_id")

    return res
