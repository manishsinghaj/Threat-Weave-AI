# modules/tls_enrich.py
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def _iso(dt):
    # dt may be datetime with tzinfo or naive
    try:
        return dt.isoformat()
    except Exception:
        try:
            return str(dt)
        except Exception:
            return None

def get_cert_info(host, port=443, timeout=5):
    """
    Return certificate metadata for host:port.
    Uses timezone-aware properties if available to avoid CryptographyDeprecationWarning.
    """
    try:
        host_only = host.split(":")[0]
        ctx = ssl.create_default_context()
        with socket.create_connection((host_only, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host_only) as ssock:
                der = ssock.getpeercert(binary_form=True)

        cert = x509.load_der_x509_certificate(der, default_backend())

        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()

        # Prefer timezone-aware properties if available (cryptography >= deprecation change)
        not_before = None
        not_after = None
        # try utc properties first (recommended)
        if hasattr(cert, "not_valid_before_utc") and hasattr(cert, "not_valid_after_utc"):
            try:
                not_before = cert.not_valid_before_utc.isoformat()
            except Exception:
                not_before = _iso(getattr(cert, "not_valid_before", None))
            try:
                not_after = cert.not_valid_after_utc.isoformat()
            except Exception:
                not_after = _iso(getattr(cert, "not_valid_after", None))
        else:
            # fallback for older cryptography versions
            not_before = _iso(getattr(cert, "not_valid_before", None))
            not_after = _iso(getattr(cert, "not_valid_after", None))

        sans = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            sans = []

        return {
            "issuer": issuer,
            "subject": subject,
            "not_before": not_before,
            "not_after": not_after,
            "san": sans,
        }
    except Exception as e:
        return {"error": str(e)}
