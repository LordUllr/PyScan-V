# PyScan — Security Scanner em Python

[![Made with Python](https://img.shields.io/badge/Made%20with-Python-3776AB?logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

PyScan é um scanner de segurança simples em **Python**, focado em aprendizado e portfólio.  
Ele realiza varreduras TCP, coleta informações de TLS/HTTPS e analisa cabeçalhos de segurança HTTP, gerando relatórios em **JSON estruturado** e **HTML estilizado**.

---

## Funcionalidades
- Varredura de **portas TCP** (connect scan multithread)
- Coleta de informações de **TLS** (versão, validade, certificado)
- Análise de cabeçalhos de segurança HTTP (HSTS, CSP, etc.)
- Relatório em **JSON** (machine-readable) validado com **JSON Schema**
- Relatório em **HTML** (modo escuro/claro, pronto para clientes)
- Achados normalizados por severidade: `high`, `medium`, `low`

---

## Instalação

```bash
git clone https://github.com/<seu-usuario>/PyScan.git
cd PyScan
python -m venv .venv
source .venv/bin/activate    # Linux/macOS
.venv\Scripts\Activate.ps1   # Windows PowerShell
pip install -r requirements.txt
