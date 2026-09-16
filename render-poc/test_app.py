"""
================================================================================
 PoC DE HOSTING — confirma Playwright + Nuclei dentro de un contenedor
================================================================================
Servidor HTTP mínimo (sin dependencias más allá de la librería estándar,
aparte de Playwright) que expone GET /test. Ese endpoint:

1. Lanza un Chromium headless con Playwright, navega a example.com y lee
   el título de la página — confirma que el navegador arranca y puede
   hacer red saliente real dentro del contenedor.
2. Corre `nuclei -version` como subproceso — confirma que el binario
   externo instalado en el Dockerfile es ejecutable y responde.

No hay lógica de negocio ni checks de seguridad reales acá — el único
objetivo es medir si la infraestructura (permisos, recursos, red) del
hosting sostiene este tipo de carga. Ver README.md en esta carpeta para
el resultado de la prueba real contra Render.
================================================================================
"""

import json
import os
import subprocess
import time
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer

from playwright.sync_api import sync_playwright


def probar_playwright() -> dict:
    inicio = time.time()
    with sync_playwright() as p:
        # --no-sandbox: Chromium no puede usar su sandbox normal dentro de
        # la mayoría de contenedores Docker sin capacidades extra de kernel
        # (seccomp/user namespaces) que los PaaS no suelen exponer. Es el
        # workaround estándar para correr headless Chrome en contenedores —
        # reduce el aislamiento del propio navegador, pero como este proceso
        # ya corre aislado dentro de un contenedor efímero de un solo uso
        # por escaneo, el riesgo residual es aceptable para este caso de uso.
        navegador = p.chromium.launch(args=["--no-sandbox"])
        pagina = navegador.new_page()
        pagina.goto("https://example.com", timeout=15000)
        titulo = pagina.title()
        navegador.close()
    return {"ok": True, "titulo": titulo, "segundos": round(time.time() - inicio, 2)}


def probar_nuclei() -> dict:
    inicio = time.time()
    resultado = subprocess.run(
        ["nuclei", "-version"], capture_output=True, text=True, timeout=15
    )
    return {
        "ok": resultado.returncode == 0,
        "salida": (resultado.stdout + resultado.stderr).strip(),
        "segundos": round(time.time() - inicio, 2),
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/test":
            self._responder_texto(200, "PoC Render: Playwright + Nuclei. Probar en /test")
            return

        resultado = {}
        for nombre, fn in (("playwright", probar_playwright), ("nuclei", probar_nuclei)):
            try:
                resultado[nombre] = fn()
            except Exception as e:
                resultado[nombre] = {"ok": False, "error": str(e), "traceback": traceback.format_exc()}

        exito_total = all(r.get("ok") for r in resultado.values())
        self._responder_json(200 if exito_total else 500, resultado)

    def _responder_json(self, status: int, data: dict):
        cuerpo = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def _responder_texto(self, status: int, texto: str):
        cuerpo = texto.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def log_message(self, format, *args):
        pass  # Silencia el log por request de BaseHTTPRequestHandler; Render ya captura stdout/stderr.


if __name__ == "__main__":
    puerto = int(os.environ.get("PORT", 8000))
    print(f"PoC escuchando en 0.0.0.0:{puerto} — probar GET /test")
    HTTPServer(("0.0.0.0", puerto), Handler).serve_forever()
