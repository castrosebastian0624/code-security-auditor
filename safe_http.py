"""
================================================================================
 CLIENTE HTTP SEGURO COMPARTIDO — infraestructura central, no un parche puntual
================================================================================
Cualquier código de este proyecto que necesite pedirle algo por HTTP a un
dominio que NO controlamos (hoy: verificación de propiedad de dominio;
Fase 2 en adelante: chequeo de cabeceras de seguridad, extracción del bundle
JS, sondeo de endpoints) debe pasar por este módulo, no por `requests` u
otra librería HTTP directamente.

Por qué existe — el hueco que cierra:

Un chequeo "ingenuo" (resolver el hostname, validar que la IP es pública,
y LUEGO dejar que la librería HTTP resuelva el hostname otra vez por su
cuenta al conectar) tiene una ventana de TOCTOU clásica: DNS rebinding.
Un atacante que controle el DNS de su propio dominio puede responder con
una IP pública legítima en la resolución que usamos para validar, y con
una IP interna (127.0.0.1, 169.254.169.254, una IP de la red privada del
propio hosting del escáner, etc.) en la resolución que hace la librería
HTTP milisegundos después al conectar de verdad. El resultado: el escáner
termina haciendo un request a SU PROPIA infraestructura interna creyendo
que le está pegando al dominio del usuario.

La forma de cerrar esto (y lo que hace `get()` acá abajo) es resolver UNA
sola vez, validar esa IP, y conectar el socket TCP directamente a esa IP
literal — sin que ninguna capa posterior vuelva a resolver el hostname.
El hostname real se sigue usando para SNI y para la validación del
certificado TLS (si no, romperíamos cualquier sitio detrás de un balanceador
o CDN que dependa de SNI para saber qué certificado servir).

Este módulo es deliberadamente mínimo (solo GET, sin seguir redirects,
sin sesiones/cookies) porque cada capacidad nueva que se le agregue tiene
que pasar por el mismo análisis de seguridad. Ampliarlo con cuidado.
================================================================================
"""

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

TIMEOUT_DEFAULT_SEGUNDOS = 6.0
USER_AGENT_DEFAULT = "AuditorIA-SafeHTTP/1.0"


class SsrfBlockedError(Exception):
    """El hostname resuelve a una IP no pública — request bloqueado."""


class SolicitudSeguraError(Exception):
    """Error de red/DNS/TLS al intentar el request seguro (no es SSRF)."""


@dataclass
class RespuestaSegura:
    status_code: int
    headers: dict
    texto: str
    ip_usada: str
    host: str


class _ConexionIPFija(http.client.HTTPSConnection):
    """
    HTTPSConnection que conecta el socket TCP a una IP ya resuelta y
    validada, pero usa el hostname real para SNI y verificación del
    certificado. `self.host` (heredado de HTTPSConnection) es el hostname
    real —se lo pasamos así al padre a propósito— por eso `wrap_socket`
    usa `server_hostname=self.host` y no la IP.
    """

    def __init__(self, ip: str, hostname: str, port: int, timeout: float, context: ssl.SSLContext):
        super().__init__(hostname, port, timeout=timeout, context=context)
        self._ip_fija = ip

    def connect(self):
        sock = socket.create_connection((self._ip_fija, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def resolver_ip_publica_unica(host: str) -> str:
    """
    Resuelve `host` UNA sola vez y devuelve una única IP pública para usar
    en la conexión. Si CUALQUIERA de las IPs devueltas por el DNS es
    privada/loopback/link-local/reservada/multicast/sin especificar, se
    rechaza el hostname completo — un resultado mixto (alguna IP pública,
    alguna interna) es en sí mismo una señal de mala configuración o de un
    intento de rebinding, no algo que debamos aceptar parcialmente.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise SolicitudSeguraError(f"No se pudo resolver '{host}': {e}")

    ips_vistas = []
    for info in infos:
        ip_str = info[4][0]
        if ip_str not in ips_vistas:
            ips_vistas.append(ip_str)

    if not ips_vistas:
        raise SolicitudSeguraError(f"'{host}' no resolvió a ninguna IP.")

    for ip_str in ips_vistas:
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise SsrfBlockedError(
                f"'{host}' resuelve a una IP no pública ({ip_str}). "
                "Bloqueado para prevenir SSRF."
            )

    # Preferimos IPv4 si está disponible (simplifica el caso común); si el
    # host solo tiene IPv6 público, usamos la primera.
    for ip_str in ips_vistas:
        if ipaddress.ip_address(ip_str).version == 4:
            return ip_str
    return ips_vistas[0]


def get(
    url: str,
    timeout: float = TIMEOUT_DEFAULT_SEGUNDOS,
    headers: dict | None = None,
) -> RespuestaSegura:
    """
    GET seguro contra SSRF y DNS rebinding.

    Deliberadamente NO sigue redirects: seguir un 3xx significa repetir
    TODO este proceso de validación contra el nuevo host del `Location`,
    porque ese host podría ser interno. Quien llama decide si le interesa
    seguir el redirect (puede leer `respuesta.headers.get("Location")` y
    llamar a `get()` de nuevo explícitamente).

    Solo soporta HTTPS a propósito: si algún check de Fase 2 necesita HTTP
    plano alguna vez, que sea una decisión explícita y documentada en ese
    momento, no un default silencioso.
    """
    partes = urlsplit(url)
    if partes.scheme != "https":
        raise SolicitudSeguraError("safe_http.get() solo soporta https:// por diseño.")

    host = partes.hostname
    if not host:
        raise SolicitudSeguraError(f"URL inválida: {url!r}")

    port = partes.port or 443
    ruta = partes.path or "/"
    if partes.query:
        ruta += f"?{partes.query}"

    ip = resolver_ip_publica_unica(host)

    contexto_tls = ssl.create_default_context()
    conexion = _ConexionIPFija(ip, host, port, timeout, contexto_tls)

    try:
        cabeceras = {"Host": host, "User-Agent": USER_AGENT_DEFAULT}
        if headers:
            cabeceras.update(headers)

        conexion.request("GET", ruta, headers=cabeceras)
        respuesta = conexion.getresponse()
        cuerpo = respuesta.read().decode("utf-8", errors="ignore")

        return RespuestaSegura(
            status_code=respuesta.status,
            headers=dict(respuesta.getheaders()),
            texto=cuerpo,
            ip_usada=ip,
            host=host,
        )
    except (socket.timeout, TimeoutError):
        raise SolicitudSeguraError(f"Tiempo de espera agotado conectando a {host} ({ip}).")
    except ssl.SSLError as e:
        raise SolicitudSeguraError(f"Error de certificado TLS para {host}: {e}")
    except OSError as e:
        raise SolicitudSeguraError(f"Error de conexión a {host} ({ip}): {e}")
    finally:
        conexion.close()
