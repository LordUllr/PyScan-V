# _*_ coding: utf-8 _*_

import ssl, socket, certifi
from datetime import datetime

# Inspect the TLS configuration of a given host and port / Inspeciona a configuração TLS de um determinado host e porta
def inspect_tls(host, port=443, timeout=3.0):
    ctx = ssl.create_default_context(cafile=certifi.where()) # Use certifi CA bundle / Usa o pacote CA do certifi   
    ctx.check_hostname = True # Enforce hostname check / Impõe verificação de nome de host
    ctx.verify_mode - ssl.CERT_REQUIRED # Require valid certificate / Exige certificado válido

    # Establish a TCP connection and wrap it in an SSL context / Estabelece uma conexão TCP e a envolve em um contexto SSL
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            tls_version = ssock.version()

    # Parse certificate dates and calculate days until expiration / Analisa datas de certificado e calcula dias até a expiração
    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    days = (not_after - datetime.utcnow()).days
    subject = dict(x[0] for x in cert["subject"])
    issuer = dict(x[0] for x in cert["issuer"])
    return {
        "enabled": True,
        "version": tls_version,
        "certificate": {
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "subject": subject.get("commonName"),
            "not_before": not_before.isoformat() + "Z",
            "not_after": not_after.isoformat() + "Z",
            "days_to_expire": days,
            "valid": days >= 0
            }
    }
