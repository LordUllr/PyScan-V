# 🔬 Lab de Teste Local do PyScan

Este laboratório serve para simular um **servidor HTTPS local** com alguns **headers de segurança presentes** e outros **ausentes**, permitindo validar a detecção e geração de relatórios do PyScan.

---

## ⚙️ Pré-requisitos
- Python 3.10 ou superior
- [mkcert](https://github.com/FiloSottile/mkcert) instalado (para gerar certificados locais confiáveis)

---

## 📥 Passo 1 — Gerar certificados

Na pasta `lab/`, execute:

```powershell
mkcert -install
mkcert -cert-file certs/server.crt -key-file certs/server.key localhost 127.0.0.1 ::1
