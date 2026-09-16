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
================================================================================
"""

import ipaddress
import re
import secrets
import socket
from urllib.parse import urlparse

import dns.resolver
import dns.exception
import requests

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


def _resolver_ips_publicas(host: str) -> list[str]:
    """
    Resuelve el host y devuelve solo IPs públicas. Si CUALQUIER IP resuelta
    es privada/loopback/link-local/reservada, se rechaza el host completo:
    es la señal típica de un intento de SSRF (apuntar el "dominio a verificar"
    a un recurso interno de nuestra propia infraestructura).

    Limitación conocida: esto no protege contra DNS rebinding (que el DNS
    cambie de IP pública a privada entre esta resolución y el request HTTP
    real que hace `requests`). Mitigar eso del todo requiere fijar la conexión
    a la IP ya resuelta — no se implementó en esta fase, queda como pregunta
    abierta para cuando se conecten los checks activos reales.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise DominioInvalidoError(f"No se pudo resolver el dominio '{host}': {e}")

    ips = {info[4][0] for info in infos}
    if not ips:
        raise DominioInvalidoError(f"El dominio '{host}' no resolvió a ninguna IP.")

    for ip_str in ips:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise DominioInvalidoError(
                f"El dominio '{host}' resuelve a una IP no pública ({ip_str}). "
                "No se puede verificar ni escanear infraestructura interna."
            )

    return list(ips)


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
    auditoria-verificacion.txt. Antes de pedir el archivo, resuelve el host y
    rechaza IPs no públicas (protección básica anti-SSRF — ver
    _resolver_ips_publicas). No sigue redirects (allow_redirects=False): un
    redirect a otro host podría usarse para desviar la verificación.
    """
    try:
        _resolver_ips_publicas(dominio)
    except DominioInvalidoError as e:
        return False, str(e)

    url = f"https://{dominio}{RUTA_HTTP}"
    try:
        respuesta = requests.get(
            url,
            timeout=TIMEOUT_SEGUNDOS,
            allow_redirects=False,
            headers={"User-Agent": "AuditorIA-VerificacionDominio/1.0"},
        )
    except requests.exceptions.SSLError:
        return False, f"El sitio no tiene un certificado HTTPS válido en {url}."
    except requests.exceptions.ConnectionError:
        return False, f"No se pudo conectar a {url}. ¿El sitio está activo?"
    except requests.exceptions.Timeout:
        return False, "Tiempo de espera agotado esperando respuesta del sitio."
    except requests.exceptions.RequestException as e:
        return False, f"Error obteniendo el archivo de verificación: {e}"

    if respuesta.status_code != 200:
        return False, f"El archivo respondió con código {respuesta.status_code} (se esperaba 200)."

    contenido = respuesta.text.strip()
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
