"""
================================================================================
 FINGERPRINTING DE STACK — detecta Supabase o Firebase en el bundle
================================================================================
Fase 2: puramente informativo (proveedor + evidencia en texto), se guarda en
proyectos.stack_detectado.

Fase 3: además de la evidencia en texto, expone los datos ESTRUCTURADOS que
los checks activos necesitan para poder hacer requests reales -- la URL del
proyecto Supabase y su anon key, o el project_id/database_url/storage_bucket
de Firebase. Ninguno de estos son secretos: el anon key de Supabase y los
identificadores de config de Firebase están diseñados para ser públicos en
el frontend (la seguridad real vive en RLS / Security Rules, no en esconder
estos valores) -- por eso es seguro tenerlos en memoria durante el escaneo.
No se persisten en la base de datos more allá de lo que ya se guardaba antes
(proyectos.stack_detectado sigue siendo solo el nombre del proveedor).
================================================================================
"""

import re
from dataclasses import dataclass

import jwt_utils
from ingesta import ArchivoJS

PROVEEDOR_SUPABASE = "supabase"
PROVEEDOR_FIREBASE = "firebase"
PROVEEDOR_DESCONOCIDO = "desconocido"

_PATRON_SUPABASE_URL = re.compile(r"[a-z0-9]{15,25}\.supabase\.co")
_PATRON_SUPABASE_JS = re.compile(r"@supabase/supabase-js|createClient\s*\(")
_PATRON_JWT_BUSCAR = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

_PATRON_FIREBASE_AUTHDOMAIN = re.compile(r"([a-z0-9-]+)\.firebaseapp\.com")
_PATRON_FIREBASE_CONFIG = re.compile(r"firebaseConfig|initializeApp\s*\(")
_PATRON_FIREBASE_RTDB = re.compile(r"[a-z0-9-]+\.firebaseio\.com")
_PATRON_FIREBASE_DATABASE_URL = re.compile(r"databaseURL\s*:\s*[\"'](https://[a-z0-9.-]+)[\"']")
_PATRON_FIREBASE_STORAGE_BUCKET = re.compile(r"storageBucket\s*:\s*[\"']([a-z0-9.-]+)[\"']")


@dataclass
class ResultadoFingerprint:
    proveedor: str  # supabase | firebase | desconocido
    evidencia: str
    # Campos estructurados -- solo poblados cuando proveedor es el que corresponde.
    supabase_url: str | None = None
    supabase_anon_key: str | None = None
    firebase_project_id: str | None = None
    firebase_database_url: str | None = None
    firebase_storage_bucket: str | None = None


def _extraer_anon_key_supabase(contenido: str) -> str | None:
    """
    Busca entre TODOS los JWT del bundle el que decodifica con role=="anon"
    -- ese es el anon key de Supabase. Si hay un service_role key también en
    el bundle (checks_pasivos.py ya lo reporta como hallazgo CRITICA por
    separado), NO lo devolvemos acá: los checks activos de Fase 3 deben usar
    la misma identidad que cualquier visitante anónimo, no una elevada.
    """
    for m in _PATRON_JWT_BUSCAR.finditer(contenido):
        jwt = m.group(0)
        payload = jwt_utils.decodificar_payload(jwt)
        if payload and payload.get("role") == "anon":
            return jwt
    return None


def detectar_stack(html_renderizado: str, archivos_js: list[ArchivoJS]) -> ResultadoFingerprint:
    contenido_total = html_renderizado + "\n".join(a.contenido for a in archivos_js)

    m_supabase_url = _PATRON_SUPABASE_URL.search(contenido_total)
    if m_supabase_url and _PATRON_SUPABASE_JS.search(contenido_total):
        return ResultadoFingerprint(
            proveedor=PROVEEDOR_SUPABASE,
            evidencia=f"URL de proyecto Supabase encontrada en el bundle: {m_supabase_url.group(0)}",
            supabase_url=f"https://{m_supabase_url.group(0)}",
            supabase_anon_key=_extraer_anon_key_supabase(contenido_total),
        )

    m_firebase_domain = _PATRON_FIREBASE_AUTHDOMAIN.search(contenido_total)
    if m_firebase_domain and _PATRON_FIREBASE_CONFIG.search(contenido_total):
        project_id = m_firebase_domain.group(1)
        m_db_url = _PATRON_FIREBASE_DATABASE_URL.search(contenido_total)
        m_bucket = _PATRON_FIREBASE_STORAGE_BUCKET.search(contenido_total)
        return ResultadoFingerprint(
            proveedor=PROVEEDOR_FIREBASE,
            evidencia=f"authDomain de Firebase encontrado en el bundle: {m_firebase_domain.group(0)}",
            firebase_project_id=project_id,
            # Si el bundle no declara databaseURL explícito pero sí usa RTDB,
            # el patrón por defecto de Firebase es {project_id}-default-rtdb.firebaseio.com
            # -- se usa como mejor esfuerzo, nunca se inventa un project_id.
            firebase_database_url=m_db_url.group(1) if m_db_url else f"https://{project_id}-default-rtdb.firebaseio.com",
            firebase_storage_bucket=m_bucket.group(1) if m_bucket else f"{project_id}.appspot.com",
        )

    m_firebase_rtdb = _PATRON_FIREBASE_RTDB.search(contenido_total)
    if m_firebase_rtdb:
        return ResultadoFingerprint(
            proveedor=PROVEEDOR_FIREBASE,
            evidencia=f"Dominio de Firebase Realtime Database encontrado: {m_firebase_rtdb.group(0)}",
            firebase_database_url=f"https://{m_firebase_rtdb.group(0)}",
        )

    return ResultadoFingerprint(
        proveedor=PROVEEDOR_DESCONOCIDO,
        evidencia="No se encontró ningún patrón reconocible de Supabase ni Firebase en el HTML renderizado ni en los archivos JS capturados.",
    )
