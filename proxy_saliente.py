"""
================================================================================
 PROXY DE SALIDA LOCAL -- único canal de red de Playwright (Fase 2)
================================================================================
Reemplaza --host-resolver-rules como mecanismo PRINCIPAL de protección SSRF
en ingesta.py. La razón: --host-resolver-rules solo fija el dominio
PRINCIPAL; cualquier subrecurso cross-origin que la página cargue desde OTRO
dominio (fuentes, CDNs, un pixel, un widget) se resolvía y conectaba por
fuera de esa protección, y page.route() solo puede inspeccionar/abortar/
continuar -- no fijar la IP de destino de la conexión real de Chromium. Ese
era el residual marcado como TODO(fase-3-bloqueante) en ingesta.py.

Un proxy de reenvío SÍ es el único camino de salida real: se le dice a
Chromium (chromium.launch(proxy={...})) que TODO su tráfico, sin importar
el dominio, pase por acá. Cada conexión (CONNECT para HTTPS, o una request
HTTP en forma absoluta) se resuelve y valida UNA vez, justo antes de abrir
el socket -- mismo patrón exacto que safe_http.resolver_ip_publica_unica(),
ahora aplicado a TODO lo que el navegador intente tocar, no solo al dominio
principal.

Nada de MITM: para HTTPS, una vez validado el destino, se abre un túnel TCP
crudo y se hace splice bidireccional de bytes sin decriptar nada. Chromium
sigue haciendo su propio handshake TLS end-to-end contra el destino real y
valida el certificado real -- el proxy nunca ve el contenido, solo decide
si el destino puede conectarse.

Proceso único, en memoria, dentro del mismo contenedor -- no es un servicio
externo. Arranca una sola vez (singleton perezoso, thread-safe) en un hilo
en segundo plano con su propio loop de asyncio, porque Playwright en modo
síncrono (sync_playwright(), lo que usa ingesta.py) no puede compartir loop
con un servidor asyncio en el mismo hilo.
================================================================================
"""

import asyncio
import logging
import threading
from urllib.parse import urlsplit

import safe_http

logger = logging.getLogger(__name__)

HOST_LOCAL = "127.0.0.1"
TIMEOUT_CONEXION_UPSTREAM = 10.0

_hilo_proxy: threading.Thread | None = None
_puerto_proxy: int | None = None
_lock_arranque = threading.Lock()


async def _destino_permitido(host: str) -> tuple[bool, str | None]:
    """
    Reusa safe_http.resolver_ip_publica_unica() -- misma función, no una
    reimplementación paralela. Corre en threadpool porque esa función hace
    I/O bloqueante (socket.getaddrinfo) y este proxy es asyncio.
    """
    try:
        ip = await asyncio.to_thread(safe_http.resolver_ip_publica_unica, host)
        return True, ip
    except (safe_http.SsrfBlockedError, safe_http.SolicitudSeguraError) as e:
        logger.info("Proxy de salida: destino '%s' bloqueado -- %s", host, e)
        return False, None


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            datos = await reader.read(65536)
            if not datos:
                break
            writer.write(datos)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def _rechazar(writer: asyncio.StreamWriter, estado: bytes) -> None:
    try:
        writer.write(estado)
        await writer.drain()
    finally:
        writer.close()


async def _abrir_upstream(ip: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    try:
        return await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=TIMEOUT_CONEXION_UPSTREAM)
    except (OSError, asyncio.TimeoutError):
        return None


async def _manejar_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, port: int) -> None:
    permitido, ip = await _destino_permitido(host)
    if not permitido:
        await _rechazar(writer, b"HTTP/1.1 403 Forbidden\r\n\r\n")
        return

    conexion = await _abrir_upstream(ip, port)
    if conexion is None:
        await _rechazar(writer, b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        return
    upstream_reader, upstream_writer = conexion

    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()

    await asyncio.gather(
        _pipe(reader, upstream_writer),
        _pipe(upstream_reader, writer),
        return_exceptions=True,
    )


async def _manejar_http_plano(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    primera_linea: bytes,
    cabeceras_crudas: bytes,
    host: str,
    port: int,
) -> None:
    permitido, ip = await _destino_permitido(host)
    if not permitido:
        await _rechazar(writer, b"HTTP/1.1 403 Forbidden\r\n\r\n")
        return

    conexion = await _abrir_upstream(ip, port)
    if conexion is None:
        await _rechazar(writer, b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        return
    upstream_reader, upstream_writer = conexion

    upstream_writer.write(primera_linea)
    upstream_writer.write(cabeceras_crudas)
    await upstream_writer.drain()

    await asyncio.gather(
        _pipe(reader, upstream_writer),
        _pipe(upstream_reader, writer),
        return_exceptions=True,
    )


async def _leer_cabeceras(reader: asyncio.StreamReader) -> bytes:
    crudas = bytearray()
    while True:
        linea = await reader.readline()
        crudas += linea
        if linea in (b"\r\n", b"\n", b""):
            break
    return bytes(crudas)


async def _manejar_cliente(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        primera_linea = await reader.readline()
        if not primera_linea:
            writer.close()
            return

        partes = primera_linea.decode("latin-1", errors="replace").split()
        if len(partes) < 3:
            await _rechazar(writer, b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return

        metodo, objetivo, _version = partes[0], partes[1], partes[2]
        cabeceras_crudas = await _leer_cabeceras(reader)

        if metodo == "CONNECT":
            host, _, port_str = objetivo.partition(":")
            port = int(port_str) if port_str else 443
            await _manejar_connect(reader, writer, host, port)
            return

        partes_url = urlsplit(objetivo)
        host = partes_url.hostname
        if not host:
            await _rechazar(writer, b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        port = partes_url.port or (443 if partes_url.scheme == "https" else 80)
        await _manejar_http_plano(reader, writer, primera_linea, cabeceras_crudas, host, port)
    except (ConnectionResetError, asyncio.IncompleteReadError, UnicodeDecodeError, ValueError):
        try:
            writer.close()
        except OSError:
            pass


def _correr_servidor(listo: threading.Event, resultado: dict) -> None:
    async def _main() -> None:
        server = await asyncio.start_server(_manejar_cliente, HOST_LOCAL, 0)
        resultado["puerto"] = server.sockets[0].getsockname()[1]
        listo.set()
        async with server:
            await server.serve_forever()

    try:
        asyncio.run(_main())
    except Exception as e:  # pragma: no cover -- solo si el loop muere de forma inesperada
        resultado["error"] = str(e)
        listo.set()


def asegurar_proxy_corriendo() -> int:
    """
    Arranca el proxy la primera vez que se llama (singleton perezoso,
    thread-safe) y devuelve el puerto local donde está escuchando. Llamadas
    siguientes devuelven el mismo puerto sin volver a arrancar nada --
    el proxy es stateless por conexión, seguro de compartir entre escaneos
    (cada uno lanza su propio navegador de Playwright de todas formas, ver
    ingesta.py).
    """
    global _hilo_proxy, _puerto_proxy
    with _lock_arranque:
        if _hilo_proxy is not None and _hilo_proxy.is_alive():
            return _puerto_proxy

        listo = threading.Event()
        resultado: dict = {}
        hilo = threading.Thread(target=_correr_servidor, args=(listo, resultado), daemon=True)
        hilo.start()

        if not listo.wait(timeout=5.0):
            raise RuntimeError("El proxy de salida no arrancó a tiempo.")
        if "error" in resultado:
            raise RuntimeError(f"El proxy de salida falló al arrancar: {resultado['error']}")

        _hilo_proxy = hilo
        _puerto_proxy = resultado["puerto"]
        return _puerto_proxy


def url_proxy() -> str:
    puerto = asegurar_proxy_corriendo()
    return f"http://{HOST_LOCAL}:{puerto}"
