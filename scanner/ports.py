# _*_ coding: utf-8 _*_

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Check if a TCP port is open / Verifica se uma porta TCP está aberta
def _probe(host, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a TCP socket / Cria um soquete TCP
    s.settimeout(timeout) # Set the timeout / Define o tempo limite
    try:
        return s.connect_ex((host, port)) == 0 # Return True if port is open / Retorna True se a porta estiver aberta
    except Exception: # On error, assume port is closed / Em caso de erro, assume que a porta está fechada
        return False
    finally: 
        try:s.close() # Ensure the socket is closed / Garante que o soquete seja fechado
        except: pass # Ignore errors on close / Ignora erros ao fechar


# Scan a list of TCP ports on a given host / Escaneia uma lista de portas TCP em um determinado host
def scan_tcp(host, ports, timeout=1.0, workers=100):
    results = [] # List to hold scan results / Lista para armazenar resultados de varredura
    # Use a thread pool to scan ports concurrently / Usa um pool de threads para escanear portas simultaneamente
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_probe, host, p, timeout): p for p in ports} 
        for fut in as_completed(futures):
            p = futures[fut]
            is_open = fut.result()
            results.append({"port": p, "open": bool(is_open), "service_guess": "https" if p == 443 else ("http" if p == 80 else None)})
    results.sort(key=lambda x: x["port"]) # Sort results by port number / Ordena os resultados pelo número da porta
    return results