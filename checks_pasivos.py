"""
================================================================================
 CHECKS PASIVOS — headers, secretos en el bundle, dependencias vulnerables
================================================================================
"Pasivo" quiere decir: ninguno de estos tres checks intenta explotar nada ni
cambia estado en el sitio escaneado. Solo inspeccionan lo que el sitio ya le
expone a cualquier visitante (los headers de su propia respuesta HTTP, el
contenido de los archivos JS que cualquier navegador ya descarga). No tocan
datos de terceros -- eso es la distinción que separa esto del check de RLS
(Fase 3), que si necesita su propio diseño de "conteo, no contenido".

a) Headers de seguridad -- un GET vía safe_http.py (nunca requests/httpx
   directo), inspecciona CSP/HSTS/X-Frame-Options/CORS.
b) Secretos en el bundle -- patrones conocidos por proveedor + heurística de
   entropía de Shannon para strings sospechosos sin patrón conocido. Nunca
   se guarda ni se le pasa al LLM el secreto completo (ver _enmascarar) --
   aunque sea del propio dueño del proyecto y no de un tercero, no hace
   falta el valor completo para que el hallazgo sea accionable.
c) Dependencias vulnerables -- en vez de mantener a mano una lista de CVEs
   por librería (que se desactualiza el día que se escribe), se reusa la
   base de datos de Retire.js (Apache-2.0, activamente mantenida -- ver
   data/retire_js_repository.json, snapshot vendored) y se escribe un
   matcher mínimo en Python contra sus extractors de filename/filecontent.
   Retire.js en sí es una CLI de Node; lo que se reusa es su INTELIGENCIA de
   vulnerabilidades, no el motor -- así no se agrega una dependencia de
   Node a una app Python por un solo check.
================================================================================
"""

import base64
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from packaging.version import InvalidVersion, Version

import safe_http
from ingesta import ArchivoJS

# ==============================================================================
# a) Headers de seguridad
# ==============================================================================

HEADERS_ESPERADOS = ["content-security-policy", "strict-transport-security", "x-frame-options"]


@dataclass
class ResultadoHeaders:
    url_final: str
    headers_encontrados: dict
    headers_faltantes: list[str]
    cors_valor: str | None
    cors_permisivo: bool


def revisar_headers_seguridad(url: str) -> ResultadoHeaders:
    """
    Sigue como máximo UN redirect (algunos sitios 301 de apex a www o
    viceversa) -- cada llamada a safe_http.get() vuelve a validar SSRF de
    forma independiente, así que seguir el redirect no reabre el hueco de
    DNS rebinding que safe_http.py ya cierra.
    """
    respuesta = safe_http.get(url)
    if respuesta.status_code in (301, 302, 303, 307, 308):
        location = respuesta.headers.get("Location") or respuesta.headers.get("location")
        if location:
            if location.startswith("/"):
                from urllib.parse import urlsplit

                partes = urlsplit(url)
                location = f"{partes.scheme}://{partes.netloc}{location}"
            if location.startswith("https://"):
                respuesta = safe_http.get(location)
                url = location

    headers = {k.lower(): v for k, v in respuesta.headers.items()}
    cors_valor = headers.get("access-control-allow-origin")

    return ResultadoHeaders(
        url_final=url,
        headers_encontrados=headers,
        headers_faltantes=[h for h in HEADERS_ESPERADOS if h not in headers],
        cors_valor=cors_valor,
        cors_permisivo=(cors_valor == "*"),
    )


# ==============================================================================
# b) Secretos expuestos en el bundle
# ==============================================================================

# Deliberadamente EXCLUIDOS: claves de Firebase (AIza...) y anon keys de
# Supabase -- ambas están diseñadas para ser públicas en el frontend (la
# seguridad real vive en Firebase Security Rules / RLS de Postgres, no en
# esconder la clave). Flaggearlas como "secreto filtrado" sería un falso
# positivo conocido en este tipo de escáner.
PATRONES_SECRETOS = {
    "openai_api_key": re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "stripe_secret_key": re.compile(r"sk_live_[A-Za-z0-9]{20,}"),
    "stripe_restricted_key": re.compile(r"rk_live_[A-Za-z0-9]{20,}"),
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "private_key_pem": re.compile(r"-----BEGIN (?:RSA |EC |)PRIVATE KEY-----"),
    "connection_string_postgres": re.compile(r"postgres(?:ql)?://[^:\s\"']+:[^@\s\"']+@[^/\s\"']+"),
    "connection_string_mongo": re.compile(r"mongodb(?:\+srv)?://[^:\s\"']+:[^@\s\"']+@[^/\s\"']+"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
}

_PATRON_STRING_LITERAL = re.compile(r"[\"']([A-Za-z0-9+/_=\-.]{24,})[\"']")
_UMBRAL_ENTROPIA = 4.3
_MAX_HALLAZGOS_ENTROPIA_POR_ARCHIVO = 5
# Formato JWT (tres segmentos base64url separados por ".", el primero suele
# empezar "eyJ") -- excluido de la heurística de ENTROPÍA sin importar el
# rol: un JWT siempre va a tener alta entropía por diseño (es su forma, no
# una señal de secreto). Pero "es un JWT" no distingue un anon key (público
# por diseño) de una service_role key (la llave maestra, bypassea RLS por
# completo) -- esa distinción se resuelve decodificando el payload, no
# excluyendo o incluyendo el formato entero. Ver _detectar_jwts_sensibles.
_PATRON_JWT = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_PATRON_JWT_BUSCAR = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

PATRON_SERVICE_ROLE_KEY = "supabase_service_role_key"


@dataclass
class SecretoDetectado:
    archivo: str
    patron: str
    valor_parcial: str


def _decodificar_payload_jwt(jwt: str) -> dict | None:
    """
    Decodifica el segundo segmento (payload) de un JWT -- base64url, SIN
    verificar firma. No hace falta ni tenemos la clave para verificarla: solo
    queremos leer el claim "role" que Supabase pone en claro en el payload,
    no confiar en el token para autenticar nada. Cualquier fallo de decode
    (no es JSON, no es un JWT real, longitud rara) devuelve None -- se trata
    igual que un JWT no reconocible: se ignora, no se reporta con falsa
    certeza.
    """
    partes = jwt.split(".")
    if len(partes) != 3:
        return None
    payload_b64 = partes[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload = json.loads(payload_bytes)
        return payload if isinstance(payload, dict) else None
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _detectar_jwts_sensibles(contenido: str, archivo_url: str) -> list[SecretoDetectado]:
    """
    role == "anon" (o el JWT no decodifica como algo reconocible): se deja
    pasar, sigue siendo ruido esperado -- Supabase publica el anon key en el
    frontend a propósito.
    role != "anon" (service_role, u otro rol elevado que no debería estar
    en el bundle público): SIEMPRE se reporta -- ver la instrucción explícita
    en motor_escaneo.SYSTEM_PROMPT_V2 que fuerza CRITICA para este patrón.
    """
    hallazgos = []
    vistos: set[str] = set()
    for m in _PATRON_JWT_BUSCAR.finditer(contenido):
        jwt = m.group(0)
        if jwt in vistos:
            continue
        vistos.add(jwt)

        payload = _decodificar_payload_jwt(jwt)
        if payload is None:
            continue

        role = payload.get("role")
        if not role or role == "anon":
            continue

        hallazgos.append(
            SecretoDetectado(
                archivo=archivo_url,
                patron=PATRON_SERVICE_ROLE_KEY if role == "service_role" else f"jwt_rol_no_anon_{role}",
                valor_parcial=_enmascarar(jwt),
            )
        )
    return hallazgos


def _entropia_shannon(cadena: str) -> float:
    if not cadena:
        return 0.0
    conteos = Counter(cadena)
    longitud = len(cadena)
    return -sum((n / longitud) * math.log2(n / longitud) for n in conteos.values())


def _enmascarar(valor: str) -> str:
    if len(valor) <= 8:
        return "*" * len(valor)
    return f"{valor[:4]}…{valor[-4:]}"


def _candidatos_alta_entropia(contenido: str, ya_reportados: set[str]) -> list[str]:
    """
    `ya_reportados` son los strings que un patrón CONOCIDO ya capturó en este
    mismo archivo -- se excluyen acá para no duplicar el mismo secreto una
    vez con su patrón real y otra vez como "entropia_alta" genérico.
    """
    vistos: set[str] = set()
    candidatos = []
    for m in _PATRON_STRING_LITERAL.finditer(contenido):
        valor = m.group(1)
        if valor in vistos or valor in ya_reportados or _PATRON_JWT.match(valor):
            continue
        vistos.add(valor)
        if _entropia_shannon(valor) >= _UMBRAL_ENTROPIA:
            candidatos.append(valor)
    candidatos.sort(key=_entropia_shannon, reverse=True)
    return candidatos[:_MAX_HALLAZGOS_ENTROPIA_POR_ARCHIVO]


def detectar_secretos_bundle(archivos_js: list[ArchivoJS]) -> list[SecretoDetectado]:
    hallazgos = []
    for archivo in archivos_js:
        valores_con_patron_conocido: set[str] = set()
        for nombre_patron, patron in PATRONES_SECRETOS.items():
            for m in patron.finditer(archivo.contenido):
                valores_con_patron_conocido.add(m.group(0))
                hallazgos.append(
                    SecretoDetectado(archivo=archivo.url, patron=nombre_patron, valor_parcial=_enmascarar(m.group(0)))
                )

        hallazgos.extend(_detectar_jwts_sensibles(archivo.contenido, archivo.url))

        for candidato in _candidatos_alta_entropia(archivo.contenido, valores_con_patron_conocido):
            hallazgos.append(
                SecretoDetectado(archivo=archivo.url, patron="entropia_alta", valor_parcial=_enmascarar(candidato))
            )
    return hallazgos


# ==============================================================================
# c) Dependencias vulnerables -- matcher contra la base de datos de Retire.js
# ==============================================================================

_RUTA_REPOSITORIO = Path(__file__).parent / "data" / "retire_js_repository.json"
_MARCADOR_VERSION = "§§version§§"  # §§version§§, tal cual lo usa retire.js
# Nada de [0-9A-Za-z_.\-]* -- eso es TAN codicioso que en "jquery-1.8.3.min.js"
# se come el ".min" como si fuera parte de la versión ("1.8.3.min"), lo cual
# después revienta como InvalidVersion y silenciosamente nunca reporta nada.
# Probado en vivo contra un fixture local -- no es una preocupación teórica.
_GRUPO_VERSION = r"([0-9]+(?:\.[0-9]+)*(?:[a-zA-Z][0-9]*)?)"


def _cargar_repositorio() -> dict:
    with _RUTA_REPOSITORIO.open(encoding="utf-8") as f:
        return json.load(f)


# Datos estáticos de solo lectura (snapshot vendored de Retire.js), cargados
# una vez al importar el módulo -- NO es estado mutable por usuario/sesión,
# así que no reabre el tipo de riesgo de fuga entre sesiones que se descartó
# explícitamente para auth.py/db_pivot.py (ver prueba de concurrencia).
_REPOSITORIO = _cargar_repositorio()


def _compilar_patrones(lista_patrones: list[str]) -> list[re.Pattern]:
    compilados = []
    for patron_crudo in lista_patrones:
        try:
            compilados.append(re.compile(patron_crudo.replace(_MARCADOR_VERSION, _GRUPO_VERSION)))
        except re.error:
            continue  # algunas regex de retire.js usan construcciones que Python no soporta -- se omiten, no son fatales
    return compilados


def _version_en_rango(version_str: str, vuln: dict) -> bool:
    try:
        v = Version(version_str)
    except InvalidVersion:
        return False  # no comparamos con confianza -- mejor no reportar que reportar un falso positivo
    if "below" in vuln:
        try:
            if not v < Version(vuln["below"]):
                return False
        except InvalidVersion:
            return False
    if "atOrAbove" in vuln:
        try:
            if not v >= Version(vuln["atOrAbove"]):
                return False
        except InvalidVersion:
            return False
    return True


@dataclass
class DependenciaVulnerable:
    libreria: str
    version_detectada: str
    archivo: str
    cve_ids: list[str]
    resumenes: list[str]


def detectar_dependencias_vulnerables(archivos_js: list[ArchivoJS]) -> list[DependenciaVulnerable]:
    hallazgos = []
    for lib_nombre, lib_data in _REPOSITORIO.items():
        extractores = lib_data.get("extractors", {})
        patrones_filename = _compilar_patrones(extractores.get("filename", []))
        patrones_contenido = _compilar_patrones(extractores.get("filecontent", []))
        if not patrones_filename and not patrones_contenido:
            continue

        for archivo in archivos_js:
            version_detectada = None
            for patron in patrones_filename:
                m = patron.search(archivo.url)
                if m:
                    version_detectada = m.group(1)
                    break
            if version_detectada is None:
                for patron in patrones_contenido:
                    m = patron.search(archivo.contenido)
                    if m:
                        version_detectada = m.group(1)
                        break
            if version_detectada is None:
                continue

            vulns_aplicables = [v for v in lib_data.get("vulnerabilities", []) if _version_en_rango(version_detectada, v)]
            if not vulns_aplicables:
                continue

            cve_ids = []
            resumenes = []
            for v in vulns_aplicables:
                cve_ids.extend(v.get("identifiers", {}).get("CVE", []))
                resumen = v.get("identifiers", {}).get("summary")
                if resumen:
                    resumenes.append(resumen)

            hallazgos.append(
                DependenciaVulnerable(
                    libreria=lib_nombre,
                    version_detectada=version_detectada,
                    archivo=archivo.url,
                    cve_ids=cve_ids,
                    resumenes=resumenes,
                )
            )
    return hallazgos
