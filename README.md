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
primeros checks del MVP nuevo:

1. **RLS mal configurado en Supabase** — extraer la anon key del bundle de JS
   público y probar qué tablas quedan expuestas sin restricción.
2. **Secretos/API keys expuestas** en el bundle de JS servido al navegador.
3. **Endpoints sin autenticación / IDOR** — enumeración de IDs.
4. **Cabeceras de seguridad faltantes** (CSP, HSTS, X-Frame-Options, CORS mal
   configurado).
5. **Dependencias con vulnerabilidades conocidas.**

El motor de LLM migra a **GLM-5.3** (mismo precio que GLM-5.2, mejor en
benchmarks de ciberseguridad). Modelo de negocio: freemium con dos tiers
pagos ($19/mes escaneos + fixes desbloqueados, $39/mes monitoreo semanal +
alertas). Toda la interfaz y los reportes son en español.

Antes de escanear cualquier dominio, el sistema exige **verificar propiedad**
del dominio (registro DNS TXT o archivo en ruta conocida) — ver
`verificacion_dominio.py` y `pages/1_Verificar_Dominio.py`.

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
```

Crea un archivo `.env` en la raíz del proyecto (nunca lo comitees — ya está
en `.gitignore`) con:

```
OPENROUTER_API_KEY=tu_api_key_de_openrouter
DATABASE_URL=postgresql://usuario:password@host/dbname
```

Opcional: `AI_MODEL=z-ai/glm-5.2` (si no se define, ese es el default).

Aplica las migraciones SQL en orden contra tu base de Neon (ver
`migrations/README.md` para el detalle de cada una):

```bash
psql "$DATABASE_URL" -f migrations/001_codigos_acceso.sql
psql "$DATABASE_URL" -f migrations/002_pivot_schema.sql
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
app.py                      Flujo actual: sube código -> auditoría por archivo
verificacion_dominio.py     Verificación de propiedad de dominio (DNS TXT / archivo HTTP)
db_pivot.py                 Acceso a las tablas nuevas del pivote (usuarios/proyectos/escaneos/hallazgos)
pages/                      Páginas adicionales de la app multipágina de Streamlit
generar_codigo.py           Script interno (NO se despliega) para generar códigos de acceso
migrations/                 Migraciones SQL, en orden, con su propio README
.streamlit/config.toml      Tema visual de la app
```

## Estado del proyecto

MVP en validación de mercado 1-a-1 (ventas manuales por código de acceso).
`app.py` es un monolito intencional: la prioridad hoy es velocidad de
iteración, no arquitectura perfecta. Cuando el pivote a escaneo por URL
tenga checks reales (Fase 2 en adelante), este archivo se divide en módulos.
