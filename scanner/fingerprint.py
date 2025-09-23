# -*- coding: utf-8 -*-
# Banner grabbing, service fingerprinting over TCP. / Coleta de banners, fingerprinting de serviços via TCP.


from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import re

# Small heuristics for common services / Pequenas heurísticas para serviços comuns
FINGERPRINT_PATTERNS = [
    (re.compile(r"^SSH-([\d\.]+)-?(.+)?", re.I), "ssh"),
    (re.compile(r"(?i)^(?:HTTP/1\.[01]|HTTP/2)"), "http"),
    (re.compile(r"(?i)apache"), "apache"),
    (re.compile(r"(?i)nginx"), "nginx"),
    (re.compile(r"(?i)mysql"), "mysql"),
    (re.compile(r"(?i)postgres"), "postgresql"),
    (re.compile(r"(?i)microsoft-iis"), "iis"),
    (re.compile(r"(?i)redis"), "redis"),
    (re.compile(r"(?i)mongo"), "mongodb"),
    (re.compile(r"(?i)smtp"), "smtp"),
    (re.compile(r"(?i)ftp"), "ftp"),
    (re.compile(r"(?i)stunnel"), "stunnel"),
    (re.compile(r"(?i)tomcat"), "tomcat"),
]

# Attempt to connect to a TCP port and grab banner / Tenta conectar a uma porta TCP e coletar o banner
def _recv_banner(host: str, port: int, timeout: float = 1.0, max_bytes: int = 1024) -> bytes | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        # some services send banner immediately (SSH/SMTP),
        # others respond after we send something (HTTP) — send minimal probe for HTTP-like ports
        try:
            # for HTTP-like ports send simple GET if port looks like web
            if port in (80, 8080, 8000, 3000, 5000, 8443):
                s.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
        except Exception:
            pass
        data = s.recv(max_bytes)
        return data
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass

# Identify service/product/version from banner text / Identifica serviço/produto/versão a partir do texto do banner
def _identify_banner_text(b: bytes | None) -> dict:
    if not b:
        return {"banner": None, "service": None, "product": None, "version": None, "raw": None}
    try:
        text = b.decode("utf-8", errors="replace").strip()
    except Exception:
        text = repr(b)
    result = {"banner": text, "raw": b.hex()[:400]}
    # guess service/product/version
    svc = None
    prod = None
    ver = None
    for patt, name in FINGERPRINT_PATTERNS:
        if patt.search(text):
            svc = name
            # try to capture product/version in groups
            m = patt.search(text)
            if m and m.groups():
                # best-effort: group 1 might be version
                if len(m.groups()) >= 1 and m.group(1):
                    maybe_ver = m.group(1)
                    ver = maybe_ver.strip()
                if len(m.groups()) >= 2 and m.group(2):
                    prod = m.group(2).strip()
            break
    # Additional heuristics for HTTP Server header / Heurísticas adicionais para o cabeçalho Server do HTTP
    if not svc and "server:" in text.lower():
        svc = "http"
        # Attempt to parse Server: header / Tentar analisar o cabeçalho Server:
        m = re.search(r"Server:\s*([^\r\n]+)", text, re.I)
        if m:
            prod = m.group(1).strip()
            # try version inside prod
            mv = re.search(r"([A-Za-z\-]+)[/ ]?([\d\.p\-]*)", prod)
            if mv:
                prod = mv.group(1)
                ver = mv.group(2) if mv.group(2) else ver
    result.update({"service": svc, "product": prod, "version": ver})
    return result

# Main function to fingerprint multiple ports concurrently / Função principal para fingerprinting de múltiplas portas simultaneamente
def fingerprint_ports(host: str, ports: list[int], timeout: float = 1.0, workers: int = 50) -> list[dict]:
    """
    Attempt to grab banners from given ports. Returns list of dicts sorted by port.
    Each dict: port, open (bool), banner (text|null), service, product, version, raw.
    """
    out = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_recv_banner, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            p = futures[fut]
            data = None
            try:
                data = fut.result()
            except Exception:
                data = None
            info = _identify_banner_text(data)
            # If banner present => open True, else unknown (we don't change open detection here)
            entry = {
                "port": p,
                "banner": info.get("banner"),
                "service": info.get("service"),
                "product": info.get("product"),
                "version": info.get("version"),
                "raw": info.get("raw"),
            }
            out.append(entry)
    out.sort(key=lambda x: x["port"])
    return out
