import re
from urllib.parse import urlparse, unquote
import tldextract
from modules.oauth_analyzer import analyze_oauth_url

SHORTENERS = set([
    'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','rb.gy','tiny.one','shorturl.at'
])

def normalize_urls(urls):
    out = []
    seen = set()
    for u in urls:
        try:
            u2 = u.strip()
            if u2 not in seen:
                seen.add(u2)
                out.append(u2)
        except Exception:
            continue
    return out

def detect_evasion_techniques(url):
    findings = []
    try:
        u = url.strip()
        parsed = urlparse(u)
        host = parsed.netloc.lower()
        path = parsed.path or ''
        query = parsed.query or ''

        if '%' in u:
            findings.append({'technique':'url_encoding','description':'Percent-encoding present','severity':'MEDIUM','confidence':80,'evidence':u})

        if re.search(r"^\d+$", host.replace('.','')) or re.search(r'0x[0-9a-fA-F]+', host):
            findings.append({'technique':'ip_obfuscation','description':'Numeric/hex host detected','severity':'HIGH','confidence':90,'evidence':host})

        if any(ord(c) > 127 for c in host):
            findings.append({'technique':'homograph_idn','description':'Non-ASCII characters in host (possible confusable)','severity':'CRITICAL','confidence':95,'evidence':host})

        if host in SHORTENERS or any(s in host for s in SHORTENERS):
            findings.append({'technique':'url_shortener','description':'Shortener or redirector detected','severity':'MEDIUM','confidence':85,'evidence':host})

        ext = tldextract.extract(host)
        eTLD1 = ext.registered_domain
        labels = host.split('.')
        brand_tokens = ['docusign','microsoft','office','google','dropbox']
        for token in brand_tokens:
            if token in labels[:-2] and token not in eTLD1:
                findings.append({'technique':'misleading_subdomain','description':f'Brand token {token} appears in subdomain','severity':'HIGH','confidence':90,'evidence':host})

        if re.search(r'\.(zip|rar|exe|php|scr|js)$', path, re.I):
            findings.append({'technique':'suspicious_extension','description':'Executable or archive in path','severity':'HIGH','confidence':90,'evidence':path})

        if parsed.scheme and parsed.scheme not in ['http','https']:
            findings.append({'technique':'alternate_scheme','description':f'Non-http scheme {parsed.scheme}','severity':'HIGH','confidence':95,'evidence':parsed.scheme})

        # OAuth analysis integration
        try:
            oauth = analyze_oauth_url(u)
            if oauth and oauth.get('oauth_params'):
                findings.append({'technique':'oauth_parameters','description':'OAuth parameters present (redirect_uri/client_id)','severity':'HIGH','confidence':90,'evidence':oauth})
                if 'oauth_provider_with_untrusted_redirect' in oauth.get('risk_flags', []):
                    findings.append({'technique':'oauth_redirect_untrusted','description':'OAuth provider with untrusted redirect', 'severity':'CRITICAL','confidence':98,'evidence':oauth})
        except Exception as e:
            findings.append({'technique':'oauth_analysis_error','description':str(e),'severity':'LOW','confidence':50,'evidence':u})

    except Exception as e:
        findings.append({'technique':'analysis_error','description':str(e),'severity':'LOW','confidence':50,'evidence':url})
    return findings