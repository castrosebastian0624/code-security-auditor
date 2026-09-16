"""
================================================================================
 FINGERPRINTING DE STACK — detecta Supabase o Firebase en el bundle (Fase 2)
================================================================================
Puramente informativo por ahora: guarda qué backend usa el proyecto y con
qué evidencia. Fase 3 (RLS de Supabase) va a NECESITAR esto para saber si
tiene sentido correr ese check; hoy solo se guarda en proyectos.stack_detectado.

No se guarda ninguna clave/credencial encontrada -- solo el dominio del
proyecto (Supabase) o el authDomain (Firebase), que son identificadores
públicos del proyecto del cliente, no secretos.
================================================================================
"""

import re
from dataclasses import dataclass

from ingesta import ArchivoJS

PROVEEDOR_SUPABASE = "supabase"
PROVEEDOR_FIREBASE = "firebase"
PROVEEDOR_DESCONOCIDO = "desconocido"

_PATRON_SUPABASE_URL = re.compile(r"[a-z0-9]{15,25}\.supabase\.co")
_PATRON_SUPABASE_JS = re.compile(r"@supabase/supabase-js|createClient\s*\(")
_PATRON_FIREBASE_AUTHDOMAIN = re.compile(r"[a-z0-9-]+\.firebaseapp\.com")
_PATRON_FIREBASE_CONFIG = re.compile(r"firebaseConfig|initializeApp\s*\(")
_PATRON_FIREBASE_RTDB = re.compile(r"[a-z0-9-]+\.firebaseio\.com")


@dataclass
class ResultadoFingerprint:
    proveedor: str  # supabase | firebase | desconocido
    evidencia: str


def detectar_stack(html_renderizado: str, archivos_js: list[ArchivoJS]) -> ResultadoFingerprint:
    contenido_total = html_renderizado + "\n".join(a.contenido for a in archivos_js)

    m_supabase_url = _PATRON_SUPABASE_URL.search(contenido_total)
    if m_supabase_url and _PATRON_SUPABASE_JS.search(contenido_total):
        return ResultadoFingerprint(
            proveedor=PROVEEDOR_SUPABASE,
            evidencia=f"URL de proyecto Supabase encontrada en el bundle: {m_supabase_url.group(0)}",
        )

    m_firebase_domain = _PATRON_FIREBASE_AUTHDOMAIN.search(contenido_total)
    if m_firebase_domain and _PATRON_FIREBASE_CONFIG.search(contenido_total):
        return ResultadoFingerprint(
            proveedor=PROVEEDOR_FIREBASE,
            evidencia=f"authDomain de Firebase encontrado en el bundle: {m_firebase_domain.group(0)}",
        )

    m_firebase_rtdb = _PATRON_FIREBASE_RTDB.search(contenido_total)
    if m_firebase_rtdb:
        return ResultadoFingerprint(
            proveedor=PROVEEDOR_FIREBASE,
            evidencia=f"Dominio de Firebase Realtime Database encontrado: {m_firebase_rtdb.group(0)}",
        )

    return ResultadoFingerprint(
        proveedor=PROVEEDOR_DESCONOCIDO,
        evidencia="No se encontró ningún patrón reconocible de Supabase ni Firebase en el HTML renderizado ni en los archivos JS capturados.",
    )
