from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

CERT_FILE = "certs/server.crt"
KEY_FILE = "certs/server.key"

class SecureHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        # Headers de segurança adicionados
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        # Headers intencionalmente ausentes:
        # - Strict-Transport-Security (HSTS)
        # - Content-Security-Policy (CSP)
        super().end_headers()

server_address = ('0.0.0.0', 8443)
httpd = HTTPServer(server_address, SecureHandler)

# Configuração moderna de SSL
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("Servidor HTTPS rodando em https://localhost:8443")
httpd.serve_forever()
