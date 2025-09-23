# -*- coding: utf-8 -*-

"""
Normaliza e gera achados padronizados (id/category/severity/title/...)
Saída de severidade padronizada: 'high' | 'medium' | 'low'
Categorias: 'HTTP' | 'TLS' | 'PORTS' | 'GENERAL'
"""

FID = {
    "HTTP_NO_HTTPS_REDIRECT": "HTTP_NO_HTTPS_REDIRECT",
    "HSTS_MISSING": "HSTS_MISSING",
    "CSP_MISSING": "CSP_MISSING",
    "TLS_CERT_EXPIRED": "TLS_CERT_EXPIRED",
    "TLS_MIN_VERSION": "TLS_MIN_VERSION",  # < TLS 1.2
}

def _sev(s):  # garante mapeamento PT/EN -> en
    s = (s or "").strip().lower()
    mapping = {
        "alto": "high", "alta": "high", "high": "high",
        "médio": "medium", "medio": "medium", "medium": "medium",
        "baixo": "low", "baixa": "low", "low": "low",
    }
    return mapping.get(s, s if s in ("high","medium","low") else "low")

def assess_findings(scan_data: dict) -> list[dict]:
    findings: list[dict] = []
    http = (scan_data.get("http") or {})
    headers = http.get("headers") or {}
    tls = (scan_data.get("tls") or {})
    cert = (tls.get("certificate") or {})

    # HTTP → HTTPS redirect
    http_to_https = http.get("http_to_https_redirect")
    if http_to_https is False:
        findings.append({
            "id": FID["HTTP_NO_HTTPS_REDIRECT"],
            "category": "HTTP",
            "title": "Sem redirecionamento HTTP→HTTPS",
            "severity": "high",
            "score": 8.0,
            "standards": {"owasp": ["Secure Headers"], "cwe": ["CWE-319"], "gdpr_lgpd": []},
            "evidence": "Acesso via HTTP não redireciona para HTTPS",
            "recommendation": "Forçar redirecionamento 301 de HTTP para HTTPS em todo o domínio.",
            "references": ["https://owasp.org/www-project-secure-headers/"],
            "affected": http.get("affected", []) or [],
            "false_positive": False,
        })

    # HSTS
    if "strict_transport_security" not in headers:
        findings.append({
            "id": FID["HSTS_MISSING"],
            "category": "HTTP",
            "title": "HSTS ausente",
            "severity": "high",
            "score": 7.5,
            "standards": {"owasp": ["Secure Headers"], "cwe": []},
            "evidence": "Cabeçalho Strict-Transport-Security não encontrado",
            "recommendation": "Adicionar HSTS: max-age=63072000; includeSubDomains; preload.",
            "references": ["https://owasp.org/www-project-secure-headers/"],
            "affected": [],
            "false_positive": False,
        })

    # CSP
    if "content_security_policy" not in headers:
        findings.append({
            "id": FID["CSP_MISSING"],
            "category": "HTTP",
            "title": "CSP ausente",
            "severity": "medium",
            "score": 6.0,
            "standards": {"owasp": ["A03-Injection (XSS) – mitigação por CSP"], "cwe": ["CWE-79"]},
            "evidence": "Cabeçalho Content-Security-Policy não encontrado",
            "recommendation": "Definir CSP mínima (ex.: default-src 'self') e ampliar gradualmente.",
            "references": ["https://developer.mozilla.org/docs/Web/HTTP/CSP"],
            "affected": [],
            "false_positive": False,
        })

    # TLS expirado
    if cert:
        valid = cert.get("valid", True)
        if not valid:
            findings.append({
                "id": FID["TLS_CERT_EXPIRED"],
                "category": "TLS",
                "title": "Certificado TLS expirado/ inválido",
                "severity": "high",
                "score": 8.5,
                "standards": {"owasp": [], "cwe": []},
                "evidence": f"Expira em {cert.get('not_after')}",
                "recommendation": "Renovar o certificado e automatizar a renovação (ex.: Let's Encrypt).",
                "references": ["https://letsencrypt.org/"],
                "affected": [],
                "false_positive": False,
            })

        # TLS mínimo (exigir >=1.2)
        v = (scan_data.get("tls") or {}).get("version") or ""
        if v and ("1.0" in v or "1.1" in v):
            findings.append({
                "id": FID["TLS_MIN_VERSION"],
                "category": "TLS",
                "title": "Versão TLS inferior ao mínimo recomendado",
                "severity": "medium",
                "score": 6.5,
                "standards": {"owasp": [], "cwe": []},
                "evidence": f"Versão negociada: {v}",
                "recommendation": "Desabilitar TLS 1.0/1.1; exigir TLS 1.2 ou superior.",
                "references": ["https://datatracker.ietf.org/doc/rfc8996/"],
                "affected": [],
                "false_positive": False,
            })

    # Normaliza severidade
    for f in findings:
        f["severity"] = _sev(f.get("severity", "low"))

    return findings
