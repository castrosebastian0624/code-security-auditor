"""
================================================================================
 UTILIDADES DE JWT -- decodificar payload sin verificar firma
================================================================================
Usado por checks_pasivos.py (distinguir anon key de service_role key) y por
fingerprinting.py (identificar cuál JWT del bundle es el anon key de
Supabase). Un solo lugar para esta lógica -- antes vivía duplicada dentro de
checks_pasivos.py.

Nunca verifica firma -- no hace falta ni se tiene la clave para eso, el
objetivo es solo leer claims en claro (como "role") que Supabase pone sin
cifrar en el payload.
================================================================================
"""

import base64
import json


def decodificar_payload(jwt: str) -> dict | None:
    """
    Decodifica el segundo segmento (payload) de un JWT -- base64url. Devuelve
    None ante cualquier fallo (no es un JWT real, no es JSON, etc.) en vez de
    lanzar -- quien llama debe tratar None como "no se pudo determinar", no
    como un error fatal.
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
