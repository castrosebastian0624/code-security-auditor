# ==============================================================================
# PoC de hosting — NO es el Dockerfile de producción de la app.
# ==============================================================================
# Objetivo único: confirmar que Render puede correr Playwright (Chromium
# headless) y un binario externo de escaneo (Nuclei) dentro de un contenedor,
# sin problemas de permisos o recursos. Sin lógica de negocio — ver
# test_app.py y README.md en esta misma carpeta.
# ==============================================================================
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        wget \
        unzip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Nuclei: se instala el binario ya compilado desde GitHub Releases, no
# requiere el toolchain de Go dentro de la imagen.
ARG NUCLEI_VERSION=3.3.7
RUN wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --with-deps instala tanto los binarios del navegador como las librerías
# de sistema Debian que Chromium headless necesita para correr (libnss3,
# libatk, etc.) — este es el paso que, según el foro de Streamlit, falla o
# queda incompleto en Community Cloud. `playwright install chromium` ya
# descarga TANTO el Chrome completo COMO el "Chrome Headless Shell" (el que
# usa page.launch() por defecto) en la misma corrida -- confirmado con
# `playwright install --dry-run chromium`, no hace falta un paso separado
# para el headless shell.
#
# El retry es defensivo, no cosmético: durante Fase 2 el downloader de
# Playwright falló repetidas veces con timeout contra el mismo host que
# `curl` resolvía sin problema -- una falla de red real, reproducida varias
# veces en un entorno de desarrollo. Nunca pasó dentro de un build de Render
# (el PoC de Fase 1 construyó limpio), pero no hay garantía de que no pase
# ahí también -- un retry de 3 intentos es barato y evita que un build entero
# falle por un solo timeout transitorio de descarga.
RUN for i in 1 2 3; do \
        playwright install --with-deps chromium && break || sleep 5; \
    done

COPY test_app.py .

EXPOSE 8000
CMD ["python", "test_app.py"]
