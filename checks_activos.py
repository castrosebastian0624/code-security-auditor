"""
================================================================================
 CHECKS ACTIVOS DE LECTURA — Fase 3 Parte A
================================================================================
"Activos" a diferencia de los checks pasivos de Fase 2: acá SÍ hacemos
requests dirigidos a las APIs de datos del proyecto (PostgREST, Supabase
Storage, Firestore, Realtime Database, Firebase Storage) usando la misma
identidad anónima que cualquier visitante de la app (el anon key / sin
autenticación) -- exactamente lo que un atacante sin cuenta podría hacer.

Por eso requieren consentimiento explícito y separado (ver
proyectos.consentimiento_escaneo_activo, migrations/006) antes de correr,
y por eso todo pasa por un CircuitBreaker (ver circuit_breaker.py): más
requests y más variados que los checks pasivos, contra APIs que si se
abusan pueden generar carga real o (en el peor caso) alertas de seguridad
del lado del cliente.

Regla de evidencia, sin excepción: NUNCA se lee ni se guarda el contenido
real de una fila, documento, o archivo. Solo CONTEOS y NOMBRES (de tabla,
bucket, colección, archivo) -- ver cada función abajo, todas usan HEAD o
piden conteo/listado de metadatos, nunca el cuerpo de un GET sobre una fila
específica.

Todo el tráfico de red pasa por safe_http.py (GET/HEAD/POST, todos
SSRF-safe) -- nunca requests/httpx directo.

Lo que este módulo NO hace (por diseño, pendiente de documento de diseño
aparte antes de construirse): ninguna escritura (INSERT/UPDATE/DELETE, ni
POST/PUT a un bucket), y ninguna invocación real de RPC/Edge
Functions/Callable Functions -- eso solo se DETECTA de forma estática sobre
el bundle (ver detectar_rpc_edge_functions), nunca se llama.
================================================================================
"""

import json
import re
from dataclasses import dataclass

import safe_http
from circuit_breaker import CircuitBreaker, EscaneoAbortadoError, ejecutar_con_breaker
from ingesta import ArchivoJS

TIMEOUT_DEFAULT_SEGUNDOS = 8.0
MAX_NOMBRES_ARCHIVOS_EVIDENCIA = 10


def _es_5xx(respuesta) -> bool:
    """Un 5xx es el objetivo diciendo 'tengo un problema' -- cuenta como
    error para el circuit breaker aunque el request en sí no haya lanzado
    ninguna excepción de red."""
    return respuesta.status_code >= 500


# ==============================================================================
# 1. RLS de Supabase (lectura) -- descubrimiento de tablas + HEAD count=exact
# ==============================================================================


@dataclass
class TablaExpuesta:
    tabla: str
    conteo_filas_expuestas: int
    comando_reproduccion: str


def descubrir_tablas_postgrest(
    supabase_url: str, anon_key: str, breaker: CircuitBreaker, timeout: float = TIMEOUT_DEFAULT_SEGUNDOS
) -> list[str]:
    """
    El schema OpenAPI de PostgREST (/rest/v1/ con Accept: application/openapi+json)
    autodescribe qué tablas/vistas expone la API -- no hace falta adivinar
    nombres. Cada llave de nivel raíz en "paths" es una tabla o vista.
    """

    def _hacer():
        return safe_http.get(
            f"{supabase_url}/rest/v1/",
            timeout=timeout,
            headers={
                "apikey": anon_key,
                "Authorization": f"Bearer {anon_key}",
                "Accept": "application/openapi+json",
            },
        )

    try:
        respuesta = ejecutar_con_breaker(breaker, _hacer, es_error_de_respuesta=_es_5xx)
    except safe_http.SolicitudSeguraError:
        return []

    if respuesta.status_code != 200:
        return []
    try:
        esquema = json.loads(respuesta.texto)
    except json.JSONDecodeError:
        return []

    tablas = []
    for ruta in esquema.get("paths", {}):
        nombre = ruta.lstrip("/")
        if nombre and "/" not in nombre:
            tablas.append(nombre)
    return tablas


def _conteo_de_content_range(headers: dict) -> int | None:
    valor = headers.get("Content-Range") or headers.get("content-range")
    if not valor or "/" not in valor:
        return None
    total_str = valor.rsplit("/", 1)[-1]
    return int(total_str) if total_str.isdigit() else None


def check_rls_tablas(
    supabase_url: str,
    anon_key: str,
    tablas: list[str],
    breaker: CircuitBreaker,
    timeout: float = TIMEOUT_DEFAULT_SEGUNDOS,
    hallazgos: list | None = None,
) -> list[TablaExpuesta]:
    """
    HEAD (nunca GET) con Prefer: count=exact -- PostgREST devuelve el
    conteo total en el header Content-Range incluso sin cuerpo de
    respuesta. Un conteo > 0 sin ningún token de usuario significa que RLS
    está desactivado o mal configurado para esa tabla.

    `hallazgos`: lista mutable donde acumular (por defecto, una nueva). Si
    el circuit breaker aborta a mitad de la lista de tablas, la excepción
    se propaga (como debe) pero lo ya encontrado sigue en esta lista -- el
    llamador no pierde los hallazgos reales solo porque el escaneo se frenó
    después de encontrarlos.
    """
    if hallazgos is None:
        hallazgos = []
    for tabla in tablas:
        url = f"{supabase_url}/rest/v1/{tabla}"

        def _hacer(url=url):
            return safe_http.head(
                url,
                timeout=timeout,
                headers={
                    "apikey": anon_key,
                    "Authorization": f"Bearer {anon_key}",
                    "Prefer": "count=exact",
                },
            )

        try:
            respuesta = ejecutar_con_breaker(breaker, _hacer, es_error_de_respuesta=_es_5xx)
        except EscaneoAbortadoError:
            raise
        except safe_http.SolicitudSeguraError:
            continue

        if respuesta.status_code not in (200, 206):
            continue
        conteo = _conteo_de_content_range(respuesta.headers)
        if conteo is not None and conteo > 0:
            hallazgos.append(
                TablaExpuesta(
                    tabla=tabla,
                    conteo_filas_expuestas=conteo,
                    comando_reproduccion=(
                        f"curl -I '{url}' -H 'apikey: <anon_key>' -H 'Prefer: count=exact'"
                    ),
                )
            )
    return hallazgos


# ==============================================================================
# 2. Storage buckets de Supabase
# ==============================================================================


@dataclass
class BucketExpuesto:
    bucket: str
    conteo_archivos_expuestos: int
    nombres_archivos: list[str]
    comando_reproduccion: str


def _descubrir_buckets(
    supabase_url: str, anon_key: str, breaker: CircuitBreaker, timeout: float
) -> list[dict]:
    def _hacer():
        return safe_http.get(
            f"{supabase_url}/storage/v1/bucket",
            timeout=timeout,
            headers={"apikey": anon_key, "Authorization": f"Bearer {anon_key}"},
        )

    try:
        respuesta = ejecutar_con_breaker(breaker, _hacer, es_error_de_respuesta=_es_5xx)
    except EscaneoAbortadoError:
        raise
    except safe_http.SolicitudSeguraError:
        return []

    if respuesta.status_code != 200:
        return []
    try:
        buckets = json.loads(respuesta.texto)
    except json.JSONDecodeError:
        return []
    return buckets if isinstance(buckets, list) else []


def check_storage_buckets(
    supabase_url: str,
    anon_key: str,
    breaker: CircuitBreaker,
    timeout: float = TIMEOUT_DEFAULT_SEGUNDOS,
    hallazgos: list | None = None,
) -> list[BucketExpuesto]:
    """
    Lista buckets con el anon key, y para cada uno intenta listar objetos
    (POST /storage/v1/object/list/<bucket> -- esa API específica de Supabase
    Storage es POST, no GET). Se guardan los NOMBRES de archivo como
    evidencia (hasta MAX_NOMBRES_ARCHIVOS_EVIDENCIA) -- nunca se descarga ni
    se lee el contenido de ningún archivo. `hallazgos`: ver check_rls_tablas.
    """
    if hallazgos is None:
        hallazgos = []
    for bucket in _descubrir_buckets(supabase_url, anon_key, breaker, timeout):
        nombre_bucket = bucket.get("name") or bucket.get("id")
        if not nombre_bucket:
            continue

        url = f"{supabase_url}/storage/v1/object/list/{nombre_bucket}"

        def _hacer(url=url):
            return safe_http.post(
                url,
                json={"limit": 100, "offset": 0},
                timeout=timeout,
                headers={"apikey": anon_key, "Authorization": f"Bearer {anon_key}"},
            )

        try:
            respuesta = ejecutar_con_breaker(breaker, _hacer, es_error_de_respuesta=_es_5xx)
        except EscaneoAbortadoError:
            raise
        except safe_http.SolicitudSeguraError:
            continue

        if respuesta.status_code != 200:
            continue
        try:
            objetos = json.loads(respuesta.texto)
        except json.JSONDecodeError:
            continue
        if not isinstance(objetos, list) or not objetos:
            continue

        nombres = [str(o.get("name", "?")) for o in objetos[:MAX_NOMBRES_ARCHIVOS_EVIDENCIA]]
        hallazgos.append(
            BucketExpuesto(
                bucket=nombre_bucket,
                conteo_archivos_expuestos=len(objetos),
                nombres_archivos=nombres,
                comando_reproduccion=(
                    f"curl -X POST '{url}' -H 'apikey: <anon_key>' -d '{{\"limit\":100}}'"
                ),
            )
        )
    return hallazgos


# ==============================================================================
# 3. Firebase -- equivalentes de lectura (Firestore, RTDB, Storage)
# ==============================================================================
# Firestore/RTDB no se autodescriben como PostgREST -- no hay un endpoint
# público que liste "qué colecciones existen". Por eso los nombres de
# colección/ruta se extraen del propio bundle JS (análisis estático, ver
# extraer_colecciones_firestore / extraer_rutas_rtdb) -- se prueba lectura
# SOLO sobre nombres que el código del cliente ya referencia, nunca una
# wordlist genérica adivinando nombres comunes.

_PATRON_FIRESTORE_COLECCION = re.compile(r"(?:collection|doc)\s*\(\s*\w+\s*,\s*[\"'`]([a-zA-Z0-9_-]+)[\"'`]")
_PATRON_RTDB_REF = re.compile(r"ref\s*\(\s*\w+\s*,\s*[\"'`]([a-zA-Z0-9_/-]+)[\"'`]")


def extraer_colecciones_firestore(archivos_js: list[ArchivoJS]) -> list[str]:
    nombres = set()
    for archivo in archivos_js:
        for m in _PATRON_FIRESTORE_COLECCION.finditer(archivo.contenido):
            nombres.add(m.group(1))
    return sorted(nombres)


def extraer_rutas_rtdb(archivos_js: list[ArchivoJS]) -> list[str]:
    rutas = set()
    for archivo in archivos_js:
        for m in _PATRON_RTDB_REF.finditer(archivo.contenido):
            rutas.add(m.group(1))
    return sorted(rutas)


@dataclass
class ColeccionFirestoreExpuesta:
    coleccion: str
    conteo_documentos_expuestos: int
    comando_reproduccion: str


def check_firestore(
    project_id: str,
    colecciones: list[str],
    breaker: CircuitBreaker,
    timeout: float = TIMEOUT_DEFAULT_SEGUNDOS,
    hallazgos: list | None = None,
) -> list[ColeccionFirestoreExpuesta]:
    """`hallazgos`: ver check_rls_tablas."""
    if hallazgos is None:
        hallazgos = []
    for coleccion in colecciones:
        url = (
            f"https://firestore.googleapis.com/v1/projects/{project_id}"
            f"/databases/(default)/documents/{coleccion}?pageSize=10"
        )

        def _hacer(url=url):
            return safe_http.get(url, timeout=timeout)

        try:
            respuesta = ejecutar_con_breaker(breaker, _hacer, es_error_de_respuesta=_es_5xx)
        except EscaneoAbortadoError:
            raise
        except safe_http.SolicitudSeguraError:
            continue

        if respuesta.status_code != 200:
            continue
        try:
            cuerpo = json.loads(respuesta.texto)
        except json.JSONDecodeError:
            continue

        documentos = cuerpo.get("documents", [])
        if documentos:  # mismo umbral que RLS: >0, no solo "lectura permitida"
            hallazgos.append(
                ColeccionFirestoreExpuesta(
                    coleccion=coleccion,
                    conteo_documentos_expuestos=len(documentos),
                    comando_reproduccion=f"curl '{url}'",
                )
            )
    return hallazgos


@dataclass
class RutaRtdbExpuesta:
    ruta: str
    conteo_claves_expuestas: int
    comando_reproduccion: str


def check_rtdb(
    database_url: str,
    rutas: list[str],
    breaker: CircuitBreaker,
    timeout: float = TIMEOUT_DEFAULT_SEGUNDOS,
    hallazgos: list | None = None,
) -> list[RutaRtdbExpuesta]:
    """
    shallow=true es la clave: Realtime Database devuelve solo las CLAVES
    hijas directas (o el valor si es una hoja simple), nunca el árbol
    completo de contenido -- exactamente el mismo espíritu que un HEAD/count
    en PostgREST, adaptado a la forma de la API de RTDB. `hallazgos`: ver
    check_rls_tablas.
    """
    if hallazgos is None:
        hallazgos = []
    base = database_url.rstrip("/")
    for ruta in rutas:
        url = f"{base}/{ruta}.json?shallow=true"

        def _hacer(url=url):
            return safe_http.get(url, timeout=timeout)

        try:
            respuesta = ejecutar_con_breaker(breaker, _hacer, es_error_de_respuesta=_es_5xx)
        except EscaneoAbortadoError:
            raise
        except safe_http.SolicitudSeguraError:
            continue

        if respuesta.status_code != 200:
            continue
        try:
            cuerpo = json.loads(respuesta.texto)
        except json.JSONDecodeError:
            continue

        if cuerpo is None:
            continue
        conteo = len(cuerpo) if isinstance(cuerpo, dict) else 1
        if conteo > 0:
            hallazgos.append(
                RutaRtdbExpuesta(ruta=ruta, conteo_claves_expuestas=conteo, comando_reproduccion=f"curl '{url}'")
            )
    return hallazgos


@dataclass
class FirebaseStorageExpuesto:
    bucket: str
    conteo_archivos_expuestos: int
    nombres_archivos: list[str]
    comando_reproduccion: str


def check_firebase_storage(
    storage_bucket: str, breaker: CircuitBreaker, timeout: float = TIMEOUT_DEFAULT_SEGUNDOS
) -> FirebaseStorageExpuesto | None:
    url = f"https://firebasestorage.googleapis.com/v0/b/{storage_bucket}/o?maxResults={MAX_NOMBRES_ARCHIVOS_EVIDENCIA}"

    def _hacer():
        return safe_http.get(url, timeout=timeout)

    try:
        respuesta = ejecutar_con_breaker(breaker, _hacer, es_error_de_respuesta=_es_5xx)
    except EscaneoAbortadoError:
        raise
    except safe_http.SolicitudSeguraError:
        return None

    if respuesta.status_code != 200:
        return None
    try:
        cuerpo = json.loads(respuesta.texto)
    except json.JSONDecodeError:
        return None

    items = cuerpo.get("items", [])
    if not items:
        return None
    nombres = [str(i.get("name", "?")) for i in items[:MAX_NOMBRES_ARCHIVOS_EVIDENCIA]]
    return FirebaseStorageExpuesto(
        bucket=storage_bucket,
        conteo_archivos_expuestos=len(items),
        nombres_archivos=nombres,
        comando_reproduccion=f"curl '{url}'",
    )


# ==============================================================================
# 4. Detección (SIN invocar) de RPC / Edge Functions / Callable Functions
# ==============================================================================
# Puro análisis estático del bundle ya extraído -- CERO requests de red.
# El hallazgo es "encontramos una función invocable en el código, alguien
# tiene que revisar a mano si está protegida" -- MEDIA, no CRITICA, porque
# no sabemos si está protegida o no sin invocarla, y eso es justo lo que
# NO hacemos todavía (ver documento de diseño pendiente).

_PATRON_SUPABASE_RPC = re.compile(r"\.rpc\s*\(\s*[\"'`]([a-zA-Z0-9_-]+)[\"'`]")
_PATRON_FIREBASE_CALLABLE = re.compile(r"httpsCallable\s*\(\s*\w+\s*,\s*[\"'`]([a-zA-Z0-9_-]+)[\"'`]")


@dataclass
class FuncionInvocableDetectada:
    nombre_funcion: str
    archivo: str
    tipo: str  # "supabase_rpc" | "firebase_callable"


def detectar_rpc_edge_functions(archivos_js: list[ArchivoJS]) -> list[FuncionInvocableDetectada]:
    hallazgos = []
    vistos: set[tuple] = set()
    for archivo in archivos_js:
        for m in _PATRON_SUPABASE_RPC.finditer(archivo.contenido):
            clave = ("supabase_rpc", m.group(1), archivo.url)
            if clave in vistos:
                continue
            vistos.add(clave)
            hallazgos.append(
                FuncionInvocableDetectada(nombre_funcion=m.group(1), archivo=archivo.url, tipo="supabase_rpc")
            )
        for m in _PATRON_FIREBASE_CALLABLE.finditer(archivo.contenido):
            clave = ("firebase_callable", m.group(1), archivo.url)
            if clave in vistos:
                continue
            vistos.add(clave)
            hallazgos.append(
                FuncionInvocableDetectada(nombre_funcion=m.group(1), archivo=archivo.url, tipo="firebase_callable")
            )
    return hallazgos
