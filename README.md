# Auditor IA de Ciberseguridad

Micro-SaaS que usa un LLM para encontrar vulnerabilidades de seguridad y devolver
un reporte priorizado y accionable. Nació como auditor de código fuente y está en
proceso de pivotar hacia auditoría de seguridad de sitios en producción.

## Qué hace hoy (v1 — código fuente por archivo)

- App Streamlit (`app.py`) donde el usuario sube un archivo de código (`.py`,
  `.js`, `.ts`, `.go`, `.java`, `.php`, `.rb`, `.txt`).
- El archivo se envía a **GLM-5.2** (Zhipu AI) vía **OpenRouter**, con
  **Zero Data Retention** forzado (`extra_body={"zdr": True}`) para que el
  proveedor no almacene ni entrene con el contenido enviado.
- El modelo devuelve un JSON estricto con vulnerabilidades clasificadas por
  severidad (CRITICA/ALTA/MEDIA/BAJA/INFORMATIVA), siguiendo una rúbrica y
  reglas de consolidación definidas en el `SYSTEM_PROMPT` de `app.py` (evita
  reportar 25 tarjetas casi idénticas cuando el mismo patrón se repite en
  varios endpoints).
- El acceso está controlado por **códigos de acceso** (tabla `codigos_acceso`
  en **Neon Postgres**): cada prospecto recibe un código con un número
  limitado de auditorías gratuitas. Cuando se agotan, la UI ofrece un botón
  de contacto por WhatsApp.
- Desplegado en **Streamlit Community Cloud**.

`generar_codigo.py` es una herramienta interna que se corre **localmente**
(no se despliega) para crear códigos de acceso nuevos sin escribir SQL a mano.

## Hacia dónde va (v2 — pivote a escaneo por URL)

El producto está pivotando de "sube tu código fuente" a **escaneo de
seguridad externo por URL**, dirigido a founders no técnicos que construyen
apps con Lovable, Bolt.new, Replit o Base44 sobre Supabase o Firebase — gente
que despliega sin tener a nadie revisando seguridad detrás.

En vez de un archivo, la entrada es la URL de una app en producción. Los
checks del MVP nuevo:

**Fase 2 (implementada, solo checks pasivos — ver `motor_escaneo.py`):**
1. **Cabeceras de seguridad faltantes** (CSP, HSTS, X-Frame-Options, CORS mal
   configurado) — `checks_pasivos.py`, vía `safe_http.py`.
2. **Secretos/API keys expuestas** en el bundle de JS servido al navegador —
   patrones conocidos por proveedor + heurística de entropía.
3. **Dependencias con vulnerabilidades conocidas** — matcher propio contra la
   base de datos de Retire.js (vendored en `data/retire_js_repository.json`).

**Fase 3 Parte A (implementada — escaneo ACTIVO de lectura, con consentimiento
explícito y separado del de verificación de dominio; ver `checks_activos.py` /
`motor_escaneo_activo.py`):**
4. **RLS mal configurado en Supabase** — descubre tablas vía el schema OpenAPI
   de PostgREST, prueba conteo con la anon key (nunca contenido real).
5. **Storage buckets expuestos** (Supabase y Firebase) — lista buckets/objetos
   sin autenticación; guarda conteo y nombres de archivo, nunca contenido.
6. **Equivalentes de Firebase** — Firestore y Realtime Database (lectura sin
   auth, mismo patrón de conteo/existencia), sobre nombres de colección/ruta
   extraídos del propio bundle (no una wordlist adivinando nombres).
7. **Detección estática de RPC/Edge Functions** — solo se detecta el nombre en
   el bundle, nunca se invoca (severidad MEDIA, "requiere verificación manual").

Un `CircuitBreaker` (`circuit_breaker.py`) protege estos checks: límite duro de
requests, espera entre cada uno, y aborto automático si la latencia o la tasa
de error del objetivo se vuelve anómala — el escaneo se detiene solo y queda
marcado `abortado`, no sigue insistiendo contra un objetivo degradado.

**Pendiente, con documento de diseño ya escrito pero sin implementar
(`docs/DISENO_FASE3_ESCRITURA_RPC.md`) — se revisa antes de construirse:**
8. Prueba de escritura de RLS (INSERT+DELETE reversible, nunca UPDATE de datos
   ajenos).
9. Invocación real de RPC/Edge Functions detectadas (o, la alternativa que se
   recomienda en el documento: generar instrucciones para que el propio dueño
   las pruebe a mano, en vez de automatizar la invocación).
10. **Endpoints sin autenticación / IDOR** — enumeración de IDs.

El renderizado usa Playwright (headless Chromium) porque una SPA de
Lovable/Bolt/Base44 no se ve completa con un request HTTP plano — ver
`ingesta.py`. El fingerprinting de stack (Supabase vs. Firebase, sobre el
bundle ya extraído) vive en `fingerprinting.py`.

El motor de LLM migra a **GLM-5.3** (mismo precio que GLM-5.2, mejor en
benchmarks de ciberseguridad). Modelo de negocio: freemium con dos tiers
pagos ($19/mes escaneos + fixes desbloqueados, $39/mes monitoreo semanal +
alertas). Toda la interfaz y los reportes son en español.

Antes de escanear cualquier dominio, el sistema exige **verificar propiedad**
del dominio (registro DNS TXT o archivo en ruta conocida) — ver
`verificacion_dominio.py` y `pages/1_Verificar_Dominio.py`.

La identidad del usuario en el flujo del pivote es **Clerk** (login OIDC vía
`st.login()` nativo de Streamlit, no email sin verificar) — ver `auth.py`
para el detalle de por qué se eligió esa opción y qué queda resuelto por la
librería vs. construido a mano.

El nuevo esquema de base de datos (`usuarios`, `proyectos`, `escaneos`,
`hallazgos`) convive con `codigos_acceso` durante la transición — ver
`migrations/`.

## Cómo levantar el entorno local

Requisitos: Python 3.11+, una cuenta de OpenRouter con créditos, y acceso a
un proyecto de Neon Postgres.

```bash
python -m venv venv
source venv/bin/activate        # En Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m playwright install chromium
```

El último paso descarga el binario de Chromium que usa `ingesta.py` (no
viene con `pip install`). **Fricción real encontrada**: el downloader de
Playwright puede fallar con timeout en algunas redes aunque la conectividad
esté bien (confirmado: `curl` a la misma URL funcionaba mientras el
downloader de Playwright fallaba repetidamente). Si `playwright install`
falla varias veces seguidas, se puede instalar a mano: descargar el zip de
`https://cdn.playwright.dev/builds/cft/<version>/win64/chrome-win64.zip` (y
el `chrome-headless-shell-win64.zip` equivalente — Playwright usa ESE por
default en `launch()`, no el Chrome completo) con `curl -L`, extraerlos en
`%LOCALAPPDATA%\ms-playwright\chromium-<build>\` y
`chromium_headless_shell-<build>\` respectivamente, y crear un archivo vacío
`INSTALLATION_COMPLETE` en cada carpeta. La versión/build exacta que espera
tu instalación de Playwright sale de `python -m playwright install --dry-run chromium`.

Crea un archivo `.env` en la raíz del proyecto (nunca lo comitees — ya está
en `.gitignore`) con:

```
OPENROUTER_API_KEY=tu_api_key_de_openrouter
DATABASE_URL=postgresql://usuario:password@host/dbname
```

Opcional: `AI_MODEL=z-ai/glm-5.2` (si no se define, ese es el default).

Para el login con Clerk, copia `.streamlit/secrets.toml.example` a
`.streamlit/secrets.toml` (ya está en `.gitignore`) y completa las claves
`client_id`, `client_secret` y `server_metadata_url` con los valores que
Clerk muestra al crear una OAuth application (Config > OAuth applications en
su dashboard) — ver comentarios en el archivo de ejemplo para el detalle.

**Redirect URIs registrados en la OAuth application de Clerk** (Config >
OAuth applications > la app > Redirect URIs): hoy tiene dos —
`http://localhost:8501/oauth2callback` (local) y
`https://auditor-ia.onrender.com/oauth2callback` (placeholder de producción,
registrado por adelantado para no bloquear el primer deploy real). **Cuando
se defina el nombre real del servicio en Render, hay que actualizar los DOS
lados**: el redirect URI en el dashboard de Clerk, y `redirect_uri` en el
`secrets.toml` de producción — si no coinciden exactamente, Clerk rechaza el
login con `invalid_request`.

Aplica las migraciones SQL en orden contra tu base de Neon (ver
`migrations/README.md` para el detalle de cada una):

```bash
psql "$DATABASE_URL" -f migrations/001_codigos_acceso.sql
psql "$DATABASE_URL" -f migrations/002_pivot_schema.sql
psql "$DATABASE_URL" -f migrations/003_expiracion_token.sql
psql "$DATABASE_URL" -f migrations/004_clerk_identity.sql
psql "$DATABASE_URL" -f migrations/005_evidencia_checks_pasivos.sql
psql "$DATABASE_URL" -f migrations/006_fase3_lectura_activa.sql
```

Corre la app:

```bash
streamlit run app.py
```

Para crear un código de acceso de prueba localmente:

```bash
python generar_codigo.py
```

## Estructura del repo

```
app.py                          Flujo actual: sube código -> auditoría por archivo
verificacion_dominio.py         Verificación de propiedad de dominio (DNS TXT / archivo HTTP)
safe_http.py                    Cliente HTTP compartido: resuelve DNS una vez, bloquea SSRF, fija la IP (cierra DNS rebinding)
auth.py                         Login con Clerk (OIDC vía st.login() nativo de Streamlit)
db_pivot.py                     Acceso a las tablas nuevas del pivote (usuarios/proyectos/escaneos/hallazgos)
ingesta.py                      Renderizado con Playwright + extracción del bundle JS (Fase 2)
proxy_saliente.py               Proxy de reenvío local: único canal de salida de Playwright, cierra SSRF en subrecursos cross-origin (Fase 2)
fingerprinting.py               Detección de Supabase/Firebase sobre el bundle ya extraído (Fase 2)
checks_pasivos.py               3 checks pasivos: headers, secretos en el bundle, dependencias vulnerables (Fase 2)
jwt_utils.py                    Decodificar payload de JWT sin verificar firma (compartido por checks_pasivos.py y fingerprinting.py)
motor_escaneo.py                Orquesta ingesta + fingerprinting + checks pasivos + LLM -> hallazgos (Fase 2)
circuit_breaker.py              Límite de requests + detección de latencia/tasa de error anómala (Fase 3)
checks_activos.py               RLS de Supabase, Storage buckets, Firebase, detección estática de RPC (Fase 3 Parte A)
motor_escaneo_activo.py         Orquesta el escaneo activo con consentimiento + circuit breaker -> hallazgos (Fase 3 Parte A)
docs/DISENO_FASE3_ESCRITURA_RPC.md  Diseño (NO implementado) de prueba de escritura RLS e invocación de RPC
data/retire_js_repository.json  Snapshot vendored de la base de vulnerabilidades de Retire.js (Apache-2.0)
pages/                          Páginas adicionales de la app multipágina de Streamlit
generar_codigo.py               Script interno (NO se despliega) para generar códigos de acceso
migrations/                     Migraciones SQL, en orden, con su propio README
.streamlit/config.toml          Tema visual de la app
.streamlit/secrets.toml.example Plantilla de configuración de Clerk (el archivo real NO se comitea)
```

## Estado del proyecto

MVP en validación de mercado 1-a-1 (ventas manuales por código de acceso)
para v1. El pivote a escaneo por URL (v2) tiene la fundación (Fase 1: auth,
verificación de dominio, cliente HTTP seguro), los 3 checks pasivos (Fase 2)
y el escaneo activo de lectura con consentimiento (Fase 3 Parte A: RLS de
Supabase, Storage, Firebase, detección de RPC) implementados y probados en
vivo -- Supabase contra un fixture propio en Render, Firebase contra un
proyecto real desechable. IDOR y las partes de escritura/invocación de Fase
3 (documento de diseño ya escrito, ver `docs/DISENO_FASE3_ESCRITURA_RPC.md`)
siguen pendientes de implementar.
`app.py` sigue siendo un monolito intencional del flujo v1 — el pivote vive
en módulos separados desde el principio (`db_pivot.py`, `auth.py`,
`safe_http.py`, `ingesta.py`, `proxy_saliente.py`, `fingerprinting.py`,
`checks_pasivos.py`, `motor_escaneo.py`, `circuit_breaker.py`,
`checks_activos.py`, `motor_escaneo_activo.py`), no se acumula ahí.
