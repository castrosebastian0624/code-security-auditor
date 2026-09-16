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
================================================================================
"""

from dataclasses import dataclass, field

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

TIMEOUT_DEFAULT_MS = 20_000
MAX_ARCHIVOS_JS = 40
MAX_BYTES_POR_ARCHIVO = 2_000_000  # 2MB -- cap defensivo, un bundle no debería pasar de esto


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
            navegador = p.chromium.launch(args=["--no-sandbox"])
            try:
                pagina = navegador.new_page()
                pagina.on("response", _capturar_respuesta)
                pagina.goto(url, timeout=timeout_ms, wait_until="networkidle")
                html_renderizado = pagina.content()
            finally:
                navegador.close()
    except PlaywrightError as e:
        raise IngestaError(f"No se pudo renderizar {url}: {e}")

    return ResultadoIngesta(url=url, html_renderizado=html_renderizado, archivos_js=archivos_js)
