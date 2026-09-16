"""
================================================================================
 VERIFICACIÓN DE PROPIEDAD DE DOMINIO
================================================================================
Antes de que el producto pueda escanear activamente un dominio (Fase 2 en
adelante: RLS, IDOR, enumeración de endpoints), necesitamos alguna evidencia
de que quien pide el escaneo controla ese dominio. Sin esto, cualquiera
podría usar la herramienta para escanear infraestructura ajena sin permiso.

Dos métodos, porque el público objetivo (founders no técnicos en Lovable/
Bolt.new/Replit/Base44) se divide en dos perfiles distintos:

- dns_txt: para quien tiene un dominio propio y acceso a su DNS. Es el
  método más confiable (nadie más puede agregar un registro TXT en tu zona
  DNS sin acceso a tu proveedor de dominio).
- http_file: para quien todavía usa el subdominio que le dio el builder
  (ej. *.lovable.app) y no tiene ningún control de DNS sobre ese dominio,
  pero sí puede pedirle a su builder (o a la IA que lo generó) que agregue
  un archivo estático en una ruta conocida.

Este módulo NO toca la base de datos — solo hace la verificación en vivo
(resolución DNS / request HTTP). La persistencia vive en db_pivot.py.

El chequeo por archivo HTTP usa safe_http.py (no `requests` directo) para
que la resolución DNS y la validación anti-SSRF/rebinding sean una sola
operación atómica — ver safe_http.py para el detalle de por qué importa.
================================================================================
"""

import ipaddress
import re
import secrets
from urllib.parse import urlparse

import dns.resolver
import dns.exception

import safe_http

PREFIJO_TXT = "_auditoria-verificacion"
RUTA_HTTP = "/.well-known/auditoria-verificacion.txt"
TIMEOUT_SEGUNDOS = 6


class DominioInvalidoError(ValueError):
    """El dominio ingresado no tiene una forma válida."""


def normalizar_dominio(entrada: str) -> str:
    """
    Convierte 'https://Miapp.com/algo/' o 'Miapp.com' en 'miapp.com'.
    Rechaza IPs, localhost y dominios sin al menos un punto (evita que
    alguien intente "verificar" un host interno o una IP directamente).
    """
    entrada = entrada.strip().lower()
    if "://" not in entrada:
        entrada = "https://" + entrada

    parsed = urlparse(entrada)
    host = parsed.hostname

    if not host:
        raise DominioInvalidoError("No se pudo interpretar un dominio válido.")

    # Sin esto, alguien podría "verificar" 127.0.0.1 o un hostname interno.
    # OJO: DominioInvalidoError hereda de ValueError, así que el chequeo de
    # "es una IP" y el raise de rechazo NO pueden compartir el mismo bloque
    # try/except ValueError (el except capturaría su propia excepción).
    es_ip = True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        es_ip = False  # No es una IP literal, como se espera.

    if es_ip:
        raise DominioInvalidoError(
            "Debes ingresar un nombre de dominio (ej. miapp.com), no una IP."
        )

    if host in ("localhost",) or "." not in host:
        raise DominioInvalidoError(
            "El dominio debe tener un formato válido (ej. miapp.com)."
        )

    if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", host):
        raise DominioInvalidoError(f"'{host}' no tiene un formato de dominio válido.")

    return host


def generar_token() -> str:
    """Token único por intento de verificación."""
    return "auditoria-verify-" + secrets.token_hex(16)


def verificar_dns_txt(dominio: str, token_esperado: str) -> tuple[bool, str]:
    """
    Busca el token en un registro TXT de _auditoria-verificacion.<dominio>.
    Se usa un subdominio dedicado (en vez del apex) para no arriesgar chocar
    con TXT records que ya existan ahí (SPF, DKIM, etc.) — muchos proveedores
    de DNS manejan mal agregar un segundo valor TXT en el mismo nombre.

    Devuelve (encontrado: bool, detalle: str) — el detalle es para mostrarle
    al usuario qué pasó, nunca una excepción cruda.
    """
    nombre_registro = f"{PREFIJO_TXT}.{dominio}"
    try:
        respuestas = dns.resolver.resolve(nombre_registro, "TXT", lifetime=TIMEOUT_SEGUNDOS)
    except dns.resolver.NXDOMAIN:
        return False, f"No existe el registro TXT en {nombre_registro}."
    except dns.resolver.NoAnswer:
        return False, f"El nombre {nombre_registro} existe pero no tiene registros TXT."
    except dns.exception.Timeout:
        return False, "Tiempo de espera agotado consultando el DNS. Intenta de nuevo en unos minutos."
    except dns.exception.DNSException as e:
        return False, f"Error consultando DNS: {e}"

    for respuesta in respuestas:
        valor = b"".join(respuesta.strings).decode("utf-8", errors="ignore")
        if valor.strip() == token_esperado:
            return True, f"Token encontrado en {nombre_registro}."

    return False, (
        f"El registro TXT en {nombre_registro} existe pero no contiene el "
        "token esperado (¿copiaste el valor completo?)."
    )


def verificar_archivo_http(dominio: str, token_esperado: str) -> tuple[bool, str]:
    """
    Busca el token como contenido exacto de https://<dominio>/.well-known/
    auditoria-verificacion.txt, usando safe_http.get() — resuelve el DNS una
    sola vez, valida que la IP sea pública, y conecta directo a esa IP sin
    volver a resolver (cierra el hueco de DNS rebinding que tenía la versión
    anterior de este chequeo, que validaba con una resolución y luego dejaba
    que `requests` resolviera otra vez por su cuenta al conectar).
    """
    url = f"https://{dominio}{RUTA_HTTP}"
    try:
        respuesta = safe_http.get(url)
    except safe_http.SsrfBlockedError as e:
        return False, str(e)
    except safe_http.SolicitudSeguraError as e:
        return False, str(e)

    if respuesta.status_code != 200:
        return False, f"El archivo respondió con código {respuesta.status_code} (se esperaba 200)."

    contenido = respuesta.texto.strip()
    if contenido == token_esperado:
        return True, f"Token encontrado en {url}."

    return False, (
        f"El archivo en {url} existe pero su contenido no coincide con el "
        "token esperado."
    )


def verificar(dominio: str, metodo: str, token_esperado: str) -> tuple[bool, str]:
    """Despacha al verificador correspondiente según el método elegido."""
    if metodo == "dns_txt":
        return verificar_dns_txt(dominio, token_esperado)
    elif metodo == "http_file":
        return verificar_archivo_http(dominio, token_esperado)
    raise ValueError(f"Método de verificación desconocido: {metodo!r}")
