# -*- coding: utf-8 -*-

import socket
import hashlib
import platform
import sys
from datetime import datetime, timezone

# Current UTC time in ISO 8601 format with 'Z' suffix  / Hora UTC atual no formato ISO 8601 com sufixo 'Z'
def now_utc_iso_z():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

# Resolve a hostname to its IP address, returning None on failure / Resolve um nome de host para seu endereço IP, retornando None em caso de falha
def resolve_host(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

# Compute the SHA-256 hash of a file's contents / Calcula o hash SHA-256 do conteúdo de um arquivo
def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# Gather host environment information / Coleta informações do ambiente do host
def host_env():
    try:
        return {
            "os": platform.platform(),
            "python": sys.version.split()[0],
            "hostname": socket.gethostname(),
            "ip": _guess_local_ip(),
        }
    except Exception:
        return {}

# Attempt to guess the local IP address by connecting to a public DNS server / Tenta adivinhar o endereço IP local conectando-se a um servidor DNS público
def _guess_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

