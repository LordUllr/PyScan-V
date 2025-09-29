# -*- coding: utf-8 -*-

import argparse
import json
from datetime import datetime, timezone

# Modulos internos / Internal modules
from scanner.ports import scan_tcp
from scanner.tls import inspect_tls
from scanner.httpsec import analyze_http
from scanner.severity import assess_findings
from scanner.report import to_json, to_html
from scanner.utils import now_utc_iso_z, resolve_host, file_sha256, host_env
from scanner.fingerprint import fingerprint_ports

# Funcao para analisar a especificacao de portas / Function to parse port specification
def parse_ports(spec: str):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

# Funcao principal / Main function
def main():
    ap = argparse.ArgumentParser(description="Security Scanner (MVP+JSON Pro)")
    ap.add_argument("--target", required=True, help="domain or IP")
    ap.add_argument("--ports", default="80,443", help="e.g. 80,443,8080 or 1-1024")
    ap.add_argument("--out", default="report.json")
    ap.add_argument("--html", default=None)
    ap.add_argument("--tcp-timeout", type=float, default=1.0)
    ap.add_argument("--http-timeout", type=float, default=7.0)
    ap.add_argument("--workers", type=int, default=100)
    ap.add_argument("--follow-redirects", action="store_true", default=False)
    args = ap.parse_args()

    t0 = datetime.now(timezone.utc) # in�cio da varredura / scan start

    # --- Parametros e metadados / Parameters and metadata
    ports = parse_ports(args.ports)
    resolved = resolve_host(args.target)

    #--- Parametros de varredura / Scan parameters
    scan_params = {
        "ports_spec": args.ports,
        "tcp_timeout_s": args.tcp_timeout,
        "workers": args.workers,
        "http_timeout_s": args.http_timeout,
        "user_agent": "PyScan/0.1.0",
        "dns_resolver": "system",
        "follow_redirects": bool(args.follow_redirects),
    }

    # --- Coleta de dados / Data collection
    errors, warnings = [], []

    port_results = scan_tcp(args.target, ports, timeout=args.tcp_timeout, workers=args.workers)
    tls_result = None
    if any(p.get("open") and p.get("port") == 443 for p in port_results): # apenas se 443 estiver aberta
        try:
            tls_result = inspect_tls(args.target, 443)
        except Exception as e:
            tls_result = None
            errors.append({"where": "tls.inspect", "message": str(e)})

    try:
        http_result = analyze_http(args.target)
        if isinstance(http_result, dict) and "http_to_https_redirect" in http_result:
            http_result.setdefault("affected", [f"http://{args.target}/"])
    except Exception as e:
        http_result = {}
        errors.append({"where": "http.fetch", "message": str(e)})

    # Gather fingerprints only for open ports (or all scanned ports if you prefer)
    open_ports = [p["port"] for p in port_results if p.get("open")]

    # if none open, fingerprint a subset like common web ports
    if not open_ports:
        # fallback to ports scanned for visibility
        open_ports = ports

    fingerprints = fingerprint_ports(args.target, open_ports, timeout=1.0, workers=min(50, args.workers))

    # --- estrutura intermediaria compativel com severity.assess_findings
    data = {
        "target": args.target,
        "ports": port_results,
        "tls": tls_result or {},
        "http": http_result or {},
        "fingerprints": fingerprints,
        }

    # --- Findings normalizados / Normalized findings
    findings = assess_findings(data)

    # --- Resumo e por categoria / Summary and by category
    summary = {"high": 0, "medium": 0, "low": 0}
    by_category = {}
    for f in findings:
        sev = f.get("severity", "low")
        summary[sev] = summary.get(sev, 0) + 1
        cat = f.get("category", "GENERAL")
        by_category[cat] = by_category.get(cat, 0) + 1

    # --- compliance/baseline
    http_headers = (http_result or {}).get("headers") or {}
    compliance = {
        "https_enforced": (http_result or {}).get("http_to_https_redirect") is True,
        "hsts_present": "strict_transport_security" in http_headers,
        "csp_present": "content_security_policy" in http_headers,
        "min_tls_version": (tls_result or {}).get("version"),
    }
    compliance["meets_baseline"] = (
        compliance["https_enforced"] and compliance["hsts_present"] and compliance["csp_present"]
    )

    t1 = datetime.now(timezone.utc)

    report = {
        "scan_meta": {
            "schema_version": "1.0.0",
            "scanner_name": "PyScan",
            "scanner_version": "0.1.0",
            "started_at": t0.isoformat().replace("+00:00", "Z"),
            "finished_at": t1.isoformat().replace("+00:00", "Z"),
            "duration_ms": int((t1 - t0).total_seconds() * 1000),
            "host_env": host_env(),
        },
        "target": {
            "input": args.target,
            "resolved_ip": resolved,
            "scope_note": "Somente dominio raiz",
            "network": {
                "ports_scanned": ports,
                "open_ports": [p["port"] for p in port_results if p.get("open")],
            },
        },
        "scan_params": scan_params,
        "results": {
            "tls": tls_result,
            "http": http_result,
            "fingerprints": fingerprints,
        },
        "findings": findings,
        "summary": {
            "totals": summary,
            "by_category": by_category,
        },
        "errors": errors,
        "warnings": warnings,
        "compliance": compliance,
        "signing": {
            "sha256": None,
            "signed_at": t1.isoformat().replace("+00:00", "Z"),
            "signature": None
        }
    }

    # Escreve JSON / Write JSON
    to_json(report, args.out)

    # Preenche o hash SHA-256 do arquivo gerado / Fill in the SHA-256 hash of the generated file
    try:
        from scanner.utils import file_sha256
        sha = file_sha256(args.out)
        report["signing"]["sha256"] = sha
        to_json(report, args.out)
    except Exception:
        pass

    # HTML (usa o mesmo dicionario "report") / HTML (uses the same "report" dictionary)
    if args.html:
        to_html(report, args.html)

if __name__ == "__main__":
    main()
