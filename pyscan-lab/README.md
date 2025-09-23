#  Lab de Teste Local do PyScan

Este laboratório serve para simular um **servidor HTTPS local** com alguns **headers de segurança presentes** e outros **ausentes**, permitindo validar a detecção e geração de relatórios do PyScan.

---

## Pré-requisitos
- Python 3.10 ou superior
- [mkcert](https://github.com/FiloSottile/mkcert) instalado (para gerar certificados locais confiáveis)

---

## Passo 1 — Gerar certificados

Na pasta `lab/`, execute:

```powershell
mkcert -install
mkcert -cert-file certs/server.crt -key-file certs/server.key localhost 127.0.0.1 ::1

## Passo 2 — Rodar o servidor HTTPS

Ainda na pasta lab/:

python https_server.py


O servidor ficará disponível em:

https://localhost:8443/

O servidor envia alguns headers de segurança (X-Frame-Options, X-Content-Type-Options, Referrer-Policy) e omite outros (HSTS, CSP) para simular falhas reais.

## Passo 3 — Escanear com PyScan

No diretório raiz do projeto (onde está o cli.py):

python cli.py --target localhost --ports 8443 --out examples/https_test.json --html examples/https_test.html

## Passo 4 — Analisar o relatório

Abra examples/https_test.html no navegador.

Você deve ver:

 Headers presentes: X-Frame-Options, X-Content-Type-Options, Referrer-Policy

 Headers ausentes: Strict-Transport-Security (HSTS), Content-Security-Policy (CSP)

Também é gerado o examples/https_test.json, validável com o report.schema.json.