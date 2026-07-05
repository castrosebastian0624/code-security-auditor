"""
================================================================================
 AUDITOR AUTOMATIZADO DE CÓDIGO Y CIBERSEGURIDAD
 Micro-SaaS MVP - Powered by GLM-5.2 (Zhipu AI) via OpenRouter
================================================================================
Autor: Generado como MVP técnico para validación de negocio en Colombia.

Este archivo es un MONOLITO intencional (todo en app.py) porque en etapa de
MVP la prioridad es velocidad de iteración y validación de mercado, no
arquitectura perfecta. Cuando el negocio valide tracción, este archivo debe
dividirse en módulos (ui.py, openrouter_client.py, parsers.py, etc).

Cómo correrlo -> ver instrucciones al final de la respuesta del chat.
================================================================================
"""

import streamlit as st
from openai import OpenAI
import json
import os
import re
from datetime import datetime
from dotenv import load_dotenv

# ------------------------------------------------------------------------------
# Carga variables desde un archivo .env local (si existe) hacia el entorno del
# proceso. Así no hay que exportar la variable manualmente en cada terminal.
# En producción (VPS, Streamlit Cloud, etc.) esto es un no-op inofensivo: ahí
# la variable se configura directamente en la plataforma de hosting, no aquí.
# ------------------------------------------------------------------------------
load_dotenv()

# ------------------------------------------------------------------------------
# Carga la API Key desde una variable de entorno del servidor/máquina, NUNCA
# desde la UI. Esto es clave para el modelo de negocio "Opción B": el cliente
# final jamás ve ni maneja la key de OpenRouter, solo usa la app.
# ------------------------------------------------------------------------------
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")

# ==============================================================================
# 1. CONFIGURACIÓN GENERAL DE LA PÁGINA
# ==============================================================================
st.set_page_config(
    page_title="Auditor IA de Ciberseguridad",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ------------------------------------------------------------------------------
# 1.1 CSS custom: tarjetas con bordes limpios + colores por severidad.
#     Streamlit no permite "tarjetas" nativas con color de borde condicional,
#     así que inyectamos CSS mínimo. Esto NO reemplaza componentes nativos,
#     solo les da estilo (siguen siendo st.container, st.metric, etc).
# ------------------------------------------------------------------------------
CUSTOM_CSS = """
<style>
    /* Tipografía y espaciados generales */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    /* Tarjeta base reutilizable */
    .vuln-card {
        border-radius: 12px;
        padding: 1.1rem 1.3rem;
        margin-bottom: 0.9rem;
        border: 1px solid rgba(255,255,255,0.08);
        background: rgba(255,255,255,0.02);
    }

    .vuln-card h4 {
        margin: 0 0 0.35rem 0;
        font-size: 1.05rem;
    }

    .vuln-meta {
        font-size: 0.82rem;
        opacity: 0.75;
        margin-bottom: 0.5rem;
    }

    .badge {
        display: inline-block;
        padding: 0.15rem 0.6rem;
        border-radius: 999px;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.03em;
        text-transform: uppercase;
        margin-right: 0.4rem;
    }

    /* Colores por severidad */
    .sev-critica, .sev-alta {
        border-left: 5px solid #ef4444;
    }
    .badge-critica, .badge-alta {
        background: rgba(239,68,68,0.15);
        color: #ef4444;
    }

    .sev-media {
        border-left: 5px solid #f59e0b;
    }
    .badge-media {
        background: rgba(245,158,11,0.15);
        color: #f59e0b;
    }

    .sev-baja, .sev-informativa {
        border-left: 5px solid #3b82f6;
    }
    .badge-baja, .badge-informativa {
        background: rgba(59,130,246,0.15);
        color: #3b82f6;
    }

    .code-line-tag {
        font-family: 'Courier New', monospace;
        background: rgba(255,255,255,0.06);
        padding: 0.1rem 0.5rem;
        border-radius: 6px;
        font-size: 0.78rem;
    }

    .fix-box {
        background: rgba(16,185,129,0.08);
        border: 1px solid rgba(16,185,129,0.25);
        border-radius: 8px;
        padding: 0.6rem 0.8rem;
        margin-top: 0.5rem;
        font-size: 0.88rem;
    }

    .fix-box b {
        color: #10b981;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ==============================================================================
# 2. SYSTEM PROMPT — el corazón del producto.
#    Está optimizado para forzar SIEMPRE una salida JSON estricta y parseable,
#    evitando que el modelo agregue texto conversacional alrededor.
# ==============================================================================
SYSTEM_PROMPT = """Eres un Auditor Senior de Ciberseguridad y Revisor de Código con más de 15 años
de experiencia en Application Security (AppSec), especializado en OWASP Top 10,
CWE, IDOR (Insecure Direct Object Reference), fugas de datos sensibles, inyección
de código (SQLi, NoSQLi, Command Injection), manejo inseguro de secretos/API Keys,
fallas de autenticación/autorización, y vulnerabilidades de deserialización.

Tu tarea: analizar el código fuente que el usuario te entrega y devolver
EXCLUSIVAMENTE un objeto JSON válido, sin texto adicional antes o después,
sin markdown, sin backticks, sin explicaciones fuera del JSON.

Debes analizar el archivo buscando específicamente (pero no limitándote a):
- IDOR: falta de validación de que el usuario autenticado es dueño del recurso solicitado.
- Fugas de datos: logs con información sensible, respuestas de API que exponen
  campos que no deberían (passwords, tokens, PII innecesaria).
- Secretos hardcodeados: API keys, contraseñas, tokens o connection strings en el código.
- Inyección: concatenación insegura de queries SQL, comandos de sistema o eval() sobre input de usuario.
- Autenticación/Autorización rota: endpoints sin verificación de sesión o de rol.
- Validación de input insuficiente o ausente.
- Manejo inseguro de archivos (path traversal, subida de archivos sin restricción de tipo).
- Uso de funciones o librerías conocidas como inseguras o deprecadas para criptografía.

Devuelve ÚNICAMENTE un JSON con esta estructura EXACTA (respeta los nombres de las llaves):

{
  "nombre_archivo": "string",
  "lenguaje_detectado": "string",
  "estado_general": "CRITICO" | "ADVERTENCIA" | "ACEPTABLE" | "SEGURO",
  "resumen_ejecutivo": "string de 2 a 4 frases explicando el estado general del archivo en lenguaje claro, no técnico en exceso",
  "total_vulnerabilidades": number,
  "vulnerabilidades": [
    {
      "titulo": "string corto, ej: 'IDOR en endpoint de perfil de usuario'",
      "severidad": "CRITICA" | "ALTA" | "MEDIA" | "BAJA" | "INFORMATIVA",
      "categoria_owasp_o_cwe": "string, ej: 'CWE-639 IDOR' o 'OWASP A01:2021'",
      "linea_estimada": "string, ej: '42' o '42-48' o 'No determinable con certeza'",
      "descripcion": "string explicando el problema técnico específico encontrado en ESTE código, citando la lógica real vista",
      "impacto_potencial": "string explicando qué podría hacer un atacante si explota esto",
      "sugerencia_tecnica": "string con la corrección concreta, puede incluir snippet corto de código corregido"
    }
  ]
}

Reglas estrictas:
1. Si el archivo no tiene vulnerabilidades relevantes, "vulnerabilidades" debe ser una lista vacía [] y "estado_general" debe ser "SEGURO".
2. Nunca inventes vulnerabilidades genéricas que no correspondan a líneas reales del código entregado. Sé específico y basado en evidencia real del archivo.
3. La "linea_estimada" debe ser tu mejor estimación basada en el código visible, no un placeholder falso.
4. No incluyas comentarios, texto markdown (```), ni ningún carácter fuera del objeto JSON.
5. El JSON debe ser válido y parseable por json.loads() de Python sin modificaciones.
"""


# ==============================================================================
# 3. FUNCIONES AUXILIARES
# ==============================================================================

def extraer_json(texto_respuesta: str) -> dict:
    """
    Los modelos LLM a veces envuelven el JSON en ```json ... ``` a pesar de las
    instrucciones. Esta función limpia y extrae el JSON de forma robusta.
    """
    texto = texto_respuesta.strip()

    # Quitar posibles fences de markdown
    texto = re.sub(r"^```json\s*", "", texto)
    texto = re.sub(r"^```\s*", "", texto)
    texto = re.sub(r"```\s*$", "", texto)

    # Si aún así hay texto sobrante, buscamos el primer '{' y el último '}'
    inicio = texto.find("{")
    fin = texto.rfind("}")
    if inicio != -1 and fin != -1:
        texto = texto[inicio:fin + 1]

    return json.loads(texto)


def llamar_auditor(api_key: str, modelo: str, codigo: str, nombre_archivo: str) -> dict:
    """
    Llama a OpenRouter usando la librería oficial `openai` (compatible por diseño
    con el formato OpenAI, que es el que expone OpenRouter).
    """
    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
        # Headers recomendados por OpenRouter para atribución/ranking (opcionales
        # pero buena práctica, no afectan la funcionalidad si se dejan genéricos).
        default_headers={
            "HTTP-Referer": "https://ghostflow-auditor.local",
            "X-Title": "GhostFlow Security Auditor MVP",
        },
    )

    user_prompt = f"""Analiza el siguiente archivo de código.

Nombre del archivo: {nombre_archivo}

--- INICIO DEL CÓDIGO ---
{codigo}
--- FIN DEL CÓDIGO ---

Recuerda: responde ÚNICAMENTE con el objeto JSON especificado en tus instrucciones."""

    respuesta = client.chat.completions.create(
        model=modelo,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.1,  # Baja temperatura: queremos consistencia técnica, no creatividad
        max_tokens=4000,
    )

    contenido = respuesta.choices[0].message.content
    return extraer_json(contenido)


def color_estado(estado: str) -> str:
    mapa = {
        "CRITICO": "🔴",
        "ADVERTENCIA": "🟡",
        "ACEPTABLE": "🔵",
        "SEGURO": "🟢",
    }
    return mapa.get(estado.upper(), "⚪")


def slug_severidad(sev: str) -> str:
    """Normaliza la severidad a un slug de clase CSS."""
    return sev.strip().lower().replace("í", "i").replace("á", "a")


# ==============================================================================
# 4. SIDEBAR — Configuración (API Key, modelo, archivo)
# ==============================================================================
with st.sidebar:
    st.markdown("### 🛡️ Configuración")

    # La API Key ya NO se pide en la interfaz. Vive como variable de entorno
    # del lado del servidor (OPENROUTER_API_KEY) y es 100% transparente para
    # el cliente final. Solo mostramos un indicador de estado de conexión.
    if OPENROUTER_API_KEY:
        st.success("✅ Motor de IA conectado")
    else:
        st.error("⚠️ Falta configurar OPENROUTER_API_KEY en el servidor.")

    modelo_seleccionado = st.text_input(
        "Modelo (slug de OpenRouter)",
        value="z-ai/glm-5.2",
        help="Verifica el slug exacto y vigente en openrouter.ai/models. Zhipu actualiza versiones con frecuencia.",
    )

    st.divider()

    archivo_subido = st.file_uploader(
        "Carga tu archivo de código",
        type=["py", "js", "ts", "go", "txt", "java", "php", "rb"],
        accept_multiple_files=False,
        help="Formatos soportados: Python, JavaScript/TypeScript, Go, Java, PHP, Ruby o texto plano.",
    )

    st.divider()
    iniciar = st.button("🔍 Iniciar Auditoría de Seguridad", type="primary", use_container_width=True)

    st.divider()
    st.caption("💡 GLM-5.2 vía OpenRouter — bajo costo, alta capacidad de razonamiento sobre código.")


# ==============================================================================
# 5. HEADER PRINCIPAL
# ==============================================================================
col_titulo, col_spacer = st.columns([3, 1])
with col_titulo:
    st.title("🛡️ Auditor Automatizado de Código")
    st.markdown(
        "<p style='opacity:0.7; margin-top:-0.6rem;'>Detección de IDOR, fugas de datos, "
        "secretos hardcodeados e inyecciones — impulsado por GLM-5.2.</p>",
        unsafe_allow_html=True,
    )

st.divider()

# Guardamos el resultado en session_state para que no se pierda al re-renderizar
if "resultado_auditoria" not in st.session_state:
    st.session_state.resultado_auditoria = None


# ==============================================================================
# 6. LÓGICA PRINCIPAL — Al presionar el botón
# ==============================================================================
if iniciar:
    if not OPENROUTER_API_KEY:
        st.error(
            "⚠️ El servidor no tiene configurada la variable de entorno "
            "OPENROUTER_API_KEY. Este es un problema de configuración interna, "
            "no algo que el usuario deba resolver."
        )
    elif not archivo_subido:
        st.error("⚠️ Por favor carga un archivo de código para auditar.")
    else:
        try:
            codigo_bytes = archivo_subido.read()
            codigo_texto = codigo_bytes.decode("utf-8", errors="ignore")

            # Límite de seguridad básico para no reventar el contexto/costos en el MVP
            LIMITE_CARACTERES = 60_000
            if len(codigo_texto) > LIMITE_CARACTERES:
                st.warning(
                    f"El archivo supera los {LIMITE_CARACTERES} caracteres. "
                    "Se analizarán solo los primeros para controlar costos en este MVP."
                )
                codigo_texto = codigo_texto[:LIMITE_CARACTERES]

            with st.spinner("🧠 GLM-5.2 está analizando tu código en busca de vulnerabilidades..."):
                resultado = llamar_auditor(
                    api_key=OPENROUTER_API_KEY,
                    modelo=modelo_seleccionado,
                    codigo=codigo_texto,
                    nombre_archivo=archivo_subido.name,
                )
                st.session_state.resultado_auditoria = resultado
                st.session_state.hora_auditoria = datetime.now().strftime("%d/%m/%Y %H:%M")

        except json.JSONDecodeError:
            st.error(
                "❌ El modelo no devolvió un JSON válido. Esto puede pasar ocasionalmente con "
                "LLMs. Intenta de nuevo — normalmente se resuelve en el segundo intento."
            )
        except Exception as e:
            # Errores típicos: 401 (API key inválida), 402 (sin créditos), 404 (modelo no existe)
            st.error(f"❌ Ocurrió un error al conectar con OpenRouter: {e}")


# ==============================================================================
# 7. SECCIÓN DE RESULTADOS
# ==============================================================================
resultado = st.session_state.resultado_auditoria

if resultado:
    st.subheader("📋 Resultado de la Auditoría")
    st.caption(f"Última ejecución: {st.session_state.get('hora_auditoria', '')}")

    # --- 7.1 Resumen general en tarjetas de métricas nativas ---
    estado = resultado.get("estado_general", "N/D")
    total_vulns = resultado.get("total_vulnerabilidades", len(resultado.get("vulnerabilidades", [])))

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Estado General", f"{color_estado(estado)} {estado}")
    with c2:
        st.metric("Vulnerabilidades Encontradas", total_vulns)
    with c3:
        st.metric("Archivo Analizado", resultado.get("nombre_archivo", "—"))

    with st.container(border=True):
        st.markdown("**Resumen Ejecutivo**")
        st.write(resultado.get("resumen_ejecutivo", "Sin resumen disponible."))

    st.divider()

    # --- 7.2 Lista de vulnerabilidades, ordenadas por gravedad ---
    vulnerabilidades = resultado.get("vulnerabilidades", [])

    orden_severidad = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BAJA": 3, "INFORMATIVA": 4}
    vulnerabilidades_ordenadas = sorted(
        vulnerabilidades,
        key=lambda v: orden_severidad.get(v.get("severidad", "").upper(), 99),
    )

    if not vulnerabilidades_ordenadas:
        st.success("✅ No se encontraron vulnerabilidades relevantes en este archivo.")
    else:
        st.markdown("### 🔎 Vulnerabilidades Detectadas")

        for vuln in vulnerabilidades_ordenadas:
            severidad = vuln.get("severidad", "INFORMATIVA").upper()
            css_sev = slug_severidad(severidad)

            html_card = f"""
            <div class="vuln-card sev-{css_sev}">
                <h4>{vuln.get('titulo', 'Vulnerabilidad sin título')}</h4>
                <div class="vuln-meta">
                    <span class="badge badge-{css_sev}">{severidad}</span>
                    <span class="code-line-tag">Línea: {vuln.get('linea_estimada', 'N/D')}</span>
                    &nbsp;·&nbsp; {vuln.get('categoria_owasp_o_cwe', '')}
                </div>
                <p style="margin:0.4rem 0;">{vuln.get('descripcion', '')}</p>
                <p style="margin:0.4rem 0; opacity:0.85;"><b>Impacto potencial:</b> {vuln.get('impacto_potencial', '')}</p>
                <div class="fix-box">
                    <b>💡 Sugerencia técnica:</b><br>{vuln.get('sugerencia_tecnica', '')}
                </div>
            </div>
            """
            st.markdown(html_card, unsafe_allow_html=True)

    st.divider()

    # --- 7.3 Descarga del reporte en JSON crudo (útil para integraciones futuras) ---
    st.download_button(
        label="⬇️ Descargar reporte en JSON",
        data=json.dumps(resultado, indent=2, ensure_ascii=False),
        file_name=f"auditoria_{resultado.get('nombre_archivo', 'reporte')}.json",
        mime="application/json",
    )

else:
    st.info("👈 Carga un archivo y presiona **Iniciar Auditoría de Seguridad** en la barra lateral para comenzar.")