# _*_ coding: utf-8 _*_

import requests

# Security-related HTTP headers to check / Cabe�alhos HTTP relacionados � seguran�a para verificar
SEC_HEADERS = [
    "stric-transport-security",
    "content-security-policy",
    "x-frame-optins",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
    ]

# Normalize headers to lowercase for consistent access / Normaliza os cabe�alhos para min�sculas para acesso consistente
def _normalize_headers(h):
    return {k.lower(): v for k, v in h.items()}

# Analyze HTTP security headers and cookies for a given host / Analisa cabe�alhos de seguran�a HTTP e cookies para um determinado host
def analyze_http(host):
    result = {"http_to_https_redirect": None, "headers": {}, "cookies": []} # Initialize result structure / Inicializa a estrutura de resultado

    # HTTP (80)
    try:
        r = requests.get(f"http://{host}", timeout=5, allow_redirects = False) # No redirects / Sem redirecionamentos
        if r.is_redirect or r.status_code in (301, 302, 307, 308): # Check for redirect status codes / Verifica c�digos de status de redirecionamento
            loc = r.headers.get("Location", "") # Get the Location header / Obt�m o cabe�alho Location
            result["http_to_https_redirect"] = loc.starswith("https://") # Check if it redirects to HTTPS / Verifica se redireciona para HTTPS
        else:
            result["http_to_https_redirect"] = False # No redirect / Sem redirecionamento
    except Exception: # On error, set to None / Em caso de erro, define como None
        result["http_to_https_redirect"] = None

    # HTTPS (443)
    try:
        r = requests.get(f"https://{host}", timeout=7) # Follow redirects by default / Segue redirecionamentos por padr�o
        hdrs = _normalize_headers(r.headers) # Normalize headers / Normaliza os cabe�alhos
        # Security Headers
        for h in SEC_HEADERS: # Check each security header / Verifica cada cabe�alho de seguran�a
            if h in hdrs:
                result["headers"][h.replace("-", "_")] = hdrs[h]
        # Cookies
        for c in r.cookies: # Extract cookie attributes / Extrai atributos de cookies
            result["cookies"].append({
                "name": c.name,
                "secure": c.secure,
                "httponly": bool(getattr(c, "_rest", {}).get("HttpOnly", False)),
                "samesite": getattr(c, "get_nonstandard_attr", lambda *_: None)("SameSite") if hasattr(c, "get_nonstandard_attr") else None
            })
    except Exception:
        pass

    return result # Return the analysis result / Retorna o resultado da an�lise
