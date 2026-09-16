"""
================================================================================
 MOTOR DE ESCANEO — orquesta ingesta + fingerprinting + checks pasivos + LLM
================================================================================
Fase 2: solo 3 checks pasivos (headers, secretos en el bundle, dependencias
vulnerables). Deliberadamente NO incluye RLS de Supabase ni IDOR -- esos
necesitan su propio diseño de "conteo, no contenido" (Fase 3), porque sí
tocan datos que podrían ser de terceros.

El LLM nunca ve el contenido crudo del sitio ni de los archivos JS -- solo
recibe evidencia ya agregada (qué header falta, el patrón de secreto
encontrado con el valor YA enmascarado, el nombre y versión de una librería
vulnerable). Esto es la misma regla que ya rige evidencia_metadata en
hallazgos (ver migrations/002 y 005): el riesgo de exponer datos reales es
bajo en estos 3 checks porque no tocan RLS, pero la regla se aplica igual
por consistencia y porque el propio código fuente del cliente (si un secreto
suyo aparece) tampoco debería viajar completo innecesariamente.
================================================================================
"""

import json
import os
import re

from openai import OpenAI

import checks_pasivos
import db_pivot
import fingerprinting
import ingesta

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")


class EscaneoError(Exception):
    """El escaneo no se pudo completar -- ver la causa encadenada."""


SYSTEM_PROMPT_V2 = """Eres un Auditor Senior de Ciberseguridad especializado en aplicaciones web
construidas con builders de IA (Lovable, Bolt.new, Replit, Base44) sobre
backends serverless (Supabase, Firebase), dirigidas a founders no técnicos
que despliegan sin nadie revisando seguridad detrás.

Tu tarea: recibir evidencia YA RECOLECTADA de un escaneo pasivo (nunca el
contenido crudo del sitio) y devolver EXCLUSIVAMENTE un objeto JSON válido,
sin texto adicional antes o después, sin markdown, sin backticks.

La evidencia que recibes viene de exactamente 3 checks pasivos -- ninguno
modifica estado ni intenta explotar nada, solo inspeccionan lo que el sitio
ya expone públicamente a cualquier visitante:

1. HEADERS DE SEGURIDAD: qué cabeceras de defensa en profundidad faltan
   (Content-Security-Policy, Strict-Transport-Security, X-Frame-Options), y
   si CORS está configurado de forma permisiva (Access-Control-Allow-Origin: *
   u otro valor que refleje cualquier origen).

2. SECRETOS EN EL BUNDLE JS: API keys o credenciales que quedaron
   hardcodeadas en el código JavaScript que CUALQUIER visitante descarga
   (OpenAI, Stripe, AWS, Slack, GitHub, claves privadas PEM, connection
   strings de bases de datos). El valor real SIEMPRE llega enmascarado
   (ej. "sk-a1b2…c3d4") -- nunca vas a ver el secreto completo, y no debes
   inventar ni completar el resto. Un hallazgo de tipo "entropia_alta" es un
   string sospechoso por su aleatoriedad que no matcheó ningún patrón
   conocido -- trátalo con MENOS certeza que un patrón identificado (podría
   ser un hash, un ID de build, o un asset codificado, no necesariamente un
   secreto real) y refléjalo en la severidad y en el lenguaje del hallazgo.

3. DEPENDENCIAS VULNERABLES: librerías JavaScript de terceros detectadas en
   el bundle cuya versión tiene CVEs públicos conocidos (vía la base de
   datos de Retire.js). Evalúa el impacto real del CVE descrito, no asumas
   automáticamente severidad CRITICA solo porque existe un CVE -- muchas
   vulnerabilidades de librerías viejas requieren condiciones específicas
   para ser explotables.

También recibes el `stack_detectado` (Supabase, Firebase, o desconocido) --
es solo contexto para tu redacción (ej. mencionar que las credenciales de
Supabase visibles en el bundle son normales por diseño y NO son en sí mismas
el hallazgo, a menos que el check de secretos haya encontrado algo más
específico). NO evalúes RLS ni permisos de base de datos -- no tienes esa
evidencia todavía, eso es de una fase posterior.

===============================================================================
REGLAS DE CONSOLIDACIÓN Y PRIORIZACIÓN (igual de válidas aquí que en la
auditoría de código -- un reporte con muchas tarjetas casi idénticas es
ruido, no ayuda)
===============================================================================
1. Si el mismo patrón de secreto aparece en 3 o más archivos distintos,
   CONSOLÍDALO en una sola tarjeta que liste todos los archivos afectados,
   en vez de una tarjeta por archivo.
2. Si faltan varias cabeceras de seguridad a la vez, considera si tiene más
   sentido UNA tarjeta "Cabeceras de seguridad ausentes" listando todas,
   en vez de una tarjeta separada por cabecera -- especialmente si no hay
   ningún otro hallazgo más grave que las acompañe.
3. Si hay varias dependencias vulnerables, una tarjeta por librería está
   bien (cada una tiene su propio CVE/impacto), pero no repitas la misma
   librería+versión en más de una tarjeta.
4. El objetivo: el número de tarjetas debe reflejar problemas DISTINTOS por
   su naturaleza técnica, no el conteo bruto de cada coincidencia individual.

===============================================================================
RÚBRICA DE SEVERIDAD (aplícala de forma consistente, no la varíes entre análisis)
===============================================================================
- CRITICA: explotable sin autenticación previa, o compromete completamente
  datos/dinero/sistema con esfuerzo bajo (ej. una clave secreta de Stripe o
  de un proveedor de pagos expuesta, una clave privada PEM completa).
- ALTA: impacto severo pero requiere alguna condición adicional (ej. una API
  key de un servicio de pago/facturación que no es de Stripe pero sí puede
  generar cargos, una librería con CVE de ejecución remota bien establecido).
- MEDIA: defensa en profundidad ausente o requiere condiciones más
  específicas para explotarse (ej. CORS permisivo sin que se vea un endpoint
  sensible detrás, una librería vulnerable con CVE de XSS que requiere
  interacción de la víctima).
- BAJA/INFORMATIVA: buenas prácticas de higiene ausentes que reducen
  superficie de ataque pero no son explotables por sí solas (ej. falta un
  header CSP pero no hay evidencia de que el sitio renderice HTML de
  usuario sin escapar; un candidato de entropía alta sin patrón conocido).

Devuelve ÚNICAMENTE un JSON con esta estructura EXACTA (respeta los nombres de las llaves):

{
  "url_escaneada": "string",
  "stack_detectado": "supabase" | "firebase" | "desconocido",
  "estado_general": "CRITICO" | "ADVERTENCIA" | "ACEPTABLE" | "SEGURO",
  "resumen_ejecutivo": "string de 2 a 4 frases explicando el estado general en lenguaje claro, no técnico en exceso -- recuerda que quien lee esto es un founder no técnico",
  "total_vulnerabilidades": number,
  "vulnerabilidades": [
    {
      "titulo": "string corto, ej: 'Clave de OpenAI expuesta en el bundle'",
      "severidad": "CRITICA" | "ALTA" | "MEDIA" | "BAJA" | "INFORMATIVA",
      "categoria_owasp_o_cwe": "string, ej: 'CWE-798 Uso de credenciales hardcodeadas'",
      "ubicacion": "string -- un endpoint, un nombre de header, o el archivo del bundle donde apareció, según corresponda al tipo de hallazgo",
      "descripcion": "string explicando el problema técnico específico, citando la evidencia real recibida",
      "impacto_potencial": "string explicando qué podría hacer un atacante si explota esto",
      "sugerencia_tecnica": "string con la corrección concreta y accionable para alguien que usa un builder de IA (ej. qué pedirle a la IA que agregue, o qué configurar en el dashboard del proveedor)"
    }
  ]
}

Reglas estrictas:
1. Si no hay vulnerabilidades relevantes, "vulnerabilidades" debe ser una lista vacía [] y "estado_general" debe ser "SEGURO".
2. Nunca inventes hallazgos que no correspondan a evidencia real recibida. Sé específico y basado en la evidencia entregada.
3. "ubicacion" debe ser tu mejor descripción concreta de dónde vive el problema (un header, un archivo JS, un endpoint) -- nunca un placeholder falso.
4. No incluyas comentarios, texto markdown (```), ni ningún carácter fuera del objeto JSON.
5. El JSON debe ser válido y parseable por json.loads() de Python sin modificaciones.
"""


def _extraer_json(texto_respuesta: str) -> dict:
    texto = texto_respuesta.strip()
    texto = re.sub(r"^```json\s*", "", texto)
    texto = re.sub(r"^```\s*", "", texto)
    texto = re.sub(r"```\s*$", "", texto)
    inicio = texto.find("{")
    fin = texto.rfind("}")
    if inicio != -1 and fin != -1:
        texto = texto[inicio : fin + 1]
    return json.loads(texto)


def _construir_evidencia(
    url: str,
    fp: fingerprinting.ResultadoFingerprint,
    headers: checks_pasivos.ResultadoHeaders,
    secretos: list[checks_pasivos.SecretoDetectado],
    dependencias: list[checks_pasivos.DependenciaVulnerable],
) -> dict:
    return {
        "url_escaneada": url,
        "stack_detectado": {"proveedor": fp.proveedor, "evidencia": fp.evidencia},
        "headers_seguridad": {
            "headers_faltantes": headers.headers_faltantes,
            "cors_permisivo": headers.cors_permisivo,
            "cors_valor": headers.cors_valor,
        },
        "secretos_detectados": [
            {"archivo": s.archivo, "patron": s.patron, "valor_parcial": s.valor_parcial} for s in secretos
        ],
        "dependencias_vulnerables": [
            {
                "libreria": d.libreria,
                "version_detectada": d.version_detectada,
                "archivo": d.archivo,
                "cve_ids": d.cve_ids,
                "resumenes": d.resumenes,
            }
            for d in dependencias
        ],
    }


def _llamar_llm(evidencia: dict) -> dict:
    if not OPENROUTER_API_KEY:
        raise EscaneoError("Falta OPENROUTER_API_KEY en el entorno -- no se puede generar el reporte.")

    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=OPENROUTER_API_KEY,
        default_headers={
            "HTTP-Referer": "https://code-security-auditor.streamlit.app",
            "X-Title": "Auditor de Seguridad -- Escaneo por URL",
        },
    )

    modelo = os.environ.get("AI_MODEL", "z-ai/glm-5.2")
    user_prompt = f"""Evidencia recolectada por el escaneo pasivo (JSON, ya agregada -- no es el contenido crudo del sitio):

{json.dumps(evidencia, ensure_ascii=False, indent=2)}

Recuerda: responde ÚNICAMENTE con el objeto JSON especificado en tus instrucciones."""

    respuesta = client.chat.completions.create(
        model=modelo,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT_V2},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.1,
        max_tokens=16000,
        extra_body={"zdr": True},
    )
    return _extraer_json(respuesta.choices[0].message.content)


def ejecutar_escaneo(proyecto_id: int, disparado_por: str = "manual") -> int:
    """
    Punto de entrada único de Fase 2. Requiere que el proyecto ya esté
    verificado -- crear_escaneo() lo valida (aplicación + trigger de base de
    datos, defensa en profundidad ya existente desde Fase 1).
    """
    proyecto = db_pivot.obtener_proyecto(proyecto_id)
    if proyecto is None:
        raise EscaneoError(f"El proyecto {proyecto_id} no existe.")

    escaneo_id = db_pivot.crear_escaneo(proyecto_id, disparado_por=disparado_por)
    db_pivot.marcar_escaneo_en_progreso(escaneo_id)

    url = f"https://{proyecto['dominio']}"

    try:
        resultado_ingesta = ingesta.ingerir_url(url)
        fp = fingerprinting.detectar_stack(resultado_ingesta.html_renderizado, resultado_ingesta.archivos_js)
        db_pivot.guardar_stack_detectado(proyecto_id, fp.proveedor)

        headers = checks_pasivos.revisar_headers_seguridad(url)
        secretos = checks_pasivos.detectar_secretos_bundle(resultado_ingesta.archivos_js)
        dependencias = checks_pasivos.detectar_dependencias_vulnerables(resultado_ingesta.archivos_js)

        evidencia = _construir_evidencia(url, fp, headers, secretos, dependencias)
        reporte = _llamar_llm(evidencia)

        for vuln in reporte.get("vulnerabilidades", []):
            tipo_check = _inferir_tipo_check(vuln, fp)
            db_pivot.crear_hallazgo(
                escaneo_id=escaneo_id,
                tipo_check=tipo_check,
                severidad=vuln.get("severidad", "INFORMATIVA").upper(),
                titulo=vuln.get("titulo", "Hallazgo sin título"),
                descripcion=vuln.get("descripcion"),
                impacto_potencial=vuln.get("impacto_potencial"),
                sugerencia_tecnica=vuln.get("sugerencia_tecnica"),
                evidencia_metadata=_evidencia_para_hallazgo(tipo_check, vuln, headers, secretos, dependencias),
            )

        db_pivot.marcar_escaneo_completado(escaneo_id)
        return escaneo_id
    except Exception as e:
        db_pivot.marcar_escaneo_fallido(escaneo_id)
        raise EscaneoError(f"El escaneo {escaneo_id} falló: {e}") from e


def _evidencia_para_hallazgo(
    tipo_check: str,
    vuln: dict,
    headers: checks_pasivos.ResultadoHeaders,
    secretos: list[checks_pasivos.SecretoDetectado],
    dependencias: list[checks_pasivos.DependenciaVulnerable],
) -> dict | None:
    """
    Intenta atar el hallazgo (redactado en lenguaje natural por el LLM) de
    vuelta a la evidencia estructurada que Python ya calculó, para que
    evidencia_metadata sea reproducible y no solo la paráfrasis del modelo.
    Si no logra emparejar nada específico, cae a guardar la ubicación tal
    cual la dio el LLM en `nota` -- sigue siendo mejor que nada, pero no es
    el caso ideal.
    """
    ubicacion = (vuln.get("ubicacion") or "").lower()
    titulo = (vuln.get("titulo") or "").lower()
    texto = f"{titulo} {ubicacion}"

    if tipo_check == "headers":
        for nombre_header in checks_pasivos.HEADERS_ESPERADOS:
            if nombre_header.replace("-", " ") in texto or nombre_header in texto:
                return {"header": nombre_header}
        if "cors" in texto and headers.cors_valor:
            return {"header": "access-control-allow-origin", "valor_header": headers.cors_valor}
        if headers.headers_faltantes:
            return {"nota": f"Headers faltantes: {', '.join(headers.headers_faltantes)}"}

    elif tipo_check == "secretos_bundle":
        for s in secretos:
            if s.patron in texto or s.archivo.lower() in texto:
                return {"archivo": s.archivo, "patron_detectado": s.patron, "valor_parcial": s.valor_parcial}
        if secretos:
            s = secretos[0]
            return {"archivo": s.archivo, "patron_detectado": s.patron, "valor_parcial": s.valor_parcial}

    elif tipo_check == "dependencias":
        for d in dependencias:
            if d.libreria.lower() in texto:
                return {
                    "libreria": d.libreria,
                    "version_detectada": d.version_detectada,
                    "archivo": d.archivo,
                    "cve_ids": ", ".join(d.cve_ids) if d.cve_ids else "",
                }

    ubicacion_original = vuln.get("ubicacion")
    return {"nota": ubicacion_original[:500]} if ubicacion_original else None


def _inferir_tipo_check(vuln: dict, fp: fingerprinting.ResultadoFingerprint) -> str:
    """
    hallazgos.tipo_check tiene un CHECK constraint fijo (ver 002_pivot_schema.sql):
    'rls' | 'secretos_bundle' | 'idor' | 'headers' | 'dependencias' | 'otro'.
    El LLM no nos devuelve directamente esta categoría (su JSON está pensado
    para lectura humana, no para mapear 1:1 a nuestro enum interno), así que
    la inferimos por palabras clave del título/categoría -- 'otro' es el
    fallback seguro si no reconocemos ninguna.
    """
    texto = f"{vuln.get('titulo', '')} {vuln.get('categoria_owasp_o_cwe', '')}".lower()
    if any(p in texto for p in ("header", "cabecera", "csp", "hsts", "cors", "x-frame")):
        return "headers"
    if any(p in texto for p in ("secreto", "api key", "clave", "credencial", "token", "entrop")):
        return "secretos_bundle"
    if any(p in texto for p in ("dependencia", "librería", "libreria", "cve", "versión vulnerable")):
        return "dependencias"
    return "otro"
