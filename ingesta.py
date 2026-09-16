"""
================================================================================
 INGESTA DE URL — renderizado completo con Playwright (Fase 2)
================================================================================
Un request HTTP plano (safe_http.get) no sirve para esto: una SPA de
Lovable/Bolt.new/Base44 sirve un HTML casi vacío que se llena por JS después
de hidratar. Para ver lo mismo que ve un usuario real (y lo mismo que un
atacante vería) hace falta un navegador de verdad ejecutando ese JS.

Por qué esto NO pasa por safe_http.py: Playwright es un motor de navegador
completo, no un cliente HTTP que podamos enrutar a través de nuestra propia
resolución de IP fija sin reimplementar su networking interno. El dominio
que se renderiza aquí ya pasó la verificación de propiedad (tabla
`proyectos`, verification_status='verificado') antes de llegar a esta
función -- no es una URL arbitraria enviada por un tercero, es el propio
dominio que el dueño del proyecto demostró controlar. La regla de "todo
fetch adicional pasa por safe_http.py" aplica a los requests que ESTE
código hace por su cuenta DESPUÉS del renderizado inicial (ver
checks_pasivos.py, que sí usa safe_http.py) -- no al renderizado en sí, que
es un único paso, ya delimitado a un dominio ya verificado.

Los archivos JS no se vuelven a pedir por separado: se capturan de las
respuestas que el propio navegador ya descargó durante el renderizado, para
no duplicar requests innecesarios contra el sitio del usuario.

--------------------------------------------------------------------------------
SSRF: el dominio principal ya está verificado, pero su JS no está bajo
control nuestro -- un bundle comprometido (o simplemente un tercero
embebido, un pixel, un widget) podría hacer que el navegador pida algo a
169.254.169.254 (metadata de nube) o a una IP interna del propio host donde
corre el escáner. Dos capas:

  1. Antes de navegar: se resuelve y valida el dominio principal con
     safe_http.resolver_ip_publica_unica() -- la MISMA función que usa
     safe_http.py, no una reimplementación paralela que se pueda desincronizar.
  2. page.route("**/*", ...) intercepta TODA request que el navegador haga
     durante el render (no solo la navegación inicial) y la aborta si su
     host no resuelve a una IP pública.

Límite honesto de esta capa 2: page.route() nos deja inspeccionar/abortar/
continuar, pero NO fijar la IP de destino de la conexión real de Chromium
como sí hace _ConexionIPFija en safe_http.py -- entre que validamos el host
y Chromium conecta de verdad, hay una ventana de TOCTOU (DNS rebinding)
que esta capa NO cierra con la misma garantía que safe_http.get(). Se
documenta así a propósito en vez de aparentar paridad total.

CAPA 3 -- --host-resolver-rules para el dominio PRINCIPAL: se resuelve y
valida su IP una sola vez (otra vez, safe_http.resolver_ip_publica_unica)
y se la pasa a Chromium como `--host-resolver-rules=MAP <host> <ip>` al
lanzar el navegador. Esto sí cierra el TOCTOU para ese host específico --
Chromium ya no vuelve a resolver su DNS, conecta directo a la IP fijada
(el hostname real se sigue usando para SNI/Host, Chromium no lo toca) --
mismo patrón exacto que `_ConexionIPFija` en safe_http.py, aplicado ahora
al lanzamiento del navegador en vez de a un socket que controlamos nosotros.

Lo que esta capa 3 NO cubre, honestamente: cualquier subrecurso cross-origin
que la página cargue desde OTRO dominio (fuentes, CDNs, widgets, un
redirect del dominio principal a un host distinto) -- esos hosts no están
en la regla de `--host-resolver-rules`, así que Chromium los resuelve
normal y solo quedan cubiertos por la capa 2 (page.route()), con la misma
ventana de TOCTOU que esa capa ya reconoce no cerrar del todo. Cerrar ESE
residual necesita un filtro de red por debajo del navegador (proxy saliente
o reglas de firewall a nivel de red/contenedor) -- no se construye todavía.

TODO(fase-3-bloqueante): antes de que arranque el check de RLS/IDOR (Fase 3
-- ahí sí vamos a tocar credenciales/datos reales, no solo evidencia
agregada), este residual de subrecursos cross-origin tiene que cerrarse con
un proxy saliente o reglas de firewall a nivel de red, no quedarse solo con
page.route(). Para los 3 checks pasivos de Fase 2 el riesgo residual es
aceptable (el dominio principal SÍ está pineado, y no hay credenciales de
terceros de por medio); para Fase 3 ya no es aceptable dejarlo así.
================================================================================
"""

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Route
from playwright.sync_api import sync_playwright

import safe_http

TIMEOUT_DEFAULT_MS = 20_000
MAX_ARCHIVOS_JS = 40
MAX_BYTES_POR_ARCHIVO = 2_000_000  # 2MB -- cap defensivo, un bundle no debería pasar de esto


def _resolver_ip_publica(url: str) -> str | None:
    """
    Reusa safe_http.resolver_ip_publica_unica() -- misma lógica de rechazo
    de IPs privadas/loopback/link-local (incluye 169.254.0.0/16, que cubre
    169.254.169.254 y sus equivalentes en otros proveedores de nube) que ya
    usa el resto del proyecto, no una copia que se pueda desincronizar.
    Devuelve la IP pública validada, o None si el host es inválido/no
    público/no resoluble.
    """
    host = urlsplit(url).hostname
    if not host:
        return None
    try:
        return safe_http.resolver_ip_publica_unica(host)
    except (safe_http.SsrfBlockedError, safe_http.SolicitudSeguraError):
        return None


def _es_url_publica(url: str) -> bool:
    return _resolver_ip_publica(url) is not None


def _regla_host_resolver(host: str, ip: str) -> str:
    """
    Sintaxis de Chromium para --host-resolver-rules: `MAP <patrón> <IP>`.
    Los literales IPv6 van entre corchetes -- resolver_ip_publica_unica()
    prefiere IPv4 cuando está disponible, así que en la práctica esto casi
    siempre es una IPv4 sin corchetes, pero se cubre el caso igual.
    """
    ip_regla = f"[{ip}]" if ":" in ip else ip
    return f"MAP {host} {ip_regla}"


def _bloquear_si_no_publica(route: Route) -> None:
    if _es_url_publica(route.request.url):
        route.continue_()
    else:
        route.abort()


class IngestaError(Exception):
    """No se pudo renderizar la URL (timeout, dominio caído, etc.)."""


@dataclass
class ArchivoJS:
    url: str
    contenido: str


@dataclass
class ResultadoIngesta:
    url: str
    html_renderizado: str
    archivos_js: list[ArchivoJS] = field(default_factory=list)


def ingerir_url(url: str, timeout_ms: int = TIMEOUT_DEFAULT_MS) -> ResultadoIngesta:
    """
    Renderiza `url` con Chromium headless y captura el HTML final (post-JS)
    más el contenido de cada archivo .js que el navegador haya cargado.

    `url` debe ser la de un proyecto ya verificado -- quien llame a esta
    función es responsable de ese chequeo (ver motor_escaneo.py).
    """
    host_principal = urlsplit(url).hostname
    ip_principal = _resolver_ip_publica(url)
    if not host_principal or ip_principal is None:
        raise IngestaError(
            f"'{url}' no resuelve a una IP pública -- bloqueado antes de intentar navegar (SSRF)."
        )

    args_navegador = ["--no-sandbox", f"--host-resolver-rules={_regla_host_resolver(host_principal, ip_principal)}"]

    archivos_js: list[ArchivoJS] = []
    urls_vistas: set[str] = set()

    def _capturar_respuesta(response) -> None:
        if len(archivos_js) >= MAX_ARCHIVOS_JS:
            return
        try:
            content_type = response.headers.get("content-type", "")
            es_js = "javascript" in content_type or response.url.split("?")[0].endswith(".js")
            if not es_js or response.url in urls_vistas:
                return
            cuerpo = response.text()
            urls_vistas.add(response.url)
            archivos_js.append(ArchivoJS(url=response.url, contenido=cuerpo[:MAX_BYTES_POR_ARCHIVO]))
        except PlaywrightError:
            # Algunas respuestas no exponen body (streaming, ya abortadas,
            # redirects sin cuerpo) -- se ignoran, no son el bundle principal.
            pass

    try:
        with sync_playwright() as p:
            navegador = p.chromium.launch(args=args_navegador)
            try:
                pagina = navegador.new_page()
                pagina.route("**/*", _bloquear_si_no_publica)
                pagina.on("response", _capturar_respuesta)
                pagina.goto(url, timeout=timeout_ms, wait_until="networkidle")
                html_renderizado = pagina.content()
            finally:
                navegador.close()
    except PlaywrightError as e:
        raise IngestaError(f"No se pudo renderizar {url}: {e}")

    return ResultadoIngesta(url=url, html_renderizado=html_renderizado, archivos_js=archivos_js)
