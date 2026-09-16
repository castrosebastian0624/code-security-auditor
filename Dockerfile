# ==============================================================================
# Dockerfile de producción -- Auditor IA (v1 código + v2 pivote por URL)
# ==============================================================================
# Basado en render-poc/Dockerfile (la prueba de infraestructura de Fase 1 que
# confirmó que Render sostiene Playwright + Chromium sin problemas de
# permisos/recursos), pero para la app real, no para test_app.py.
#
# Secretos NO van en la imagen:
#   - .streamlit/secrets.toml (login de Clerk) -- se excluye vía
#     .dockerignore. En Render, usar la función "Secret Files" para montarlo
#     en tiempo de ejecución en esa misma ruta dentro del contenedor.
#   - OPENROUTER_API_KEY / DATABASE_URL / AI_MODEL -- variables de entorno
#     configuradas en el dashboard de Render (Environment), no un .env
#     copiado a la imagen (.env también está en .dockerignore).
# ==============================================================================
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        wget \
        unzip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --with-deps instala tanto los binarios del navegador (Chrome completo +
# Chrome Headless Shell, el que usa Playwright por defecto en launch() --
# confirmado con `playwright install --dry-run chromium` que ambos vienen en
# la misma corrida) como las librerías de sistema Debian que necesita correr
# headless (libnss3, libatk, etc.).
#
# El retry es defensivo: durante el desarrollo de Fase 2 este mismo comando
# falló repetidas veces con timeout de descarga en un entorno local, aunque
# la conectividad de red en sí funcionaba (`curl` a la misma URL sí
# resolvía) -- una falla de red real y reproducible, no hipotética. Nunca
# pasó todavía dentro de un build de Render, pero un retry de 3 intentos es
# barato y evita que el build entero se caiga por un timeout transitorio de
# descarga.
RUN for i in 1 2 3; do \
        playwright install --with-deps chromium && break || sleep 5; \
    done

COPY . .

# Render inyecta $PORT en tiempo de ejecución (no siempre 8501) -- el default
# de abajo solo aplica corriendo el contenedor localmente sin definir PORT.
EXPOSE 8501

CMD streamlit run app.py --server.port=${PORT:-8501} --server.address=0.0.0.0 --server.headless=true
