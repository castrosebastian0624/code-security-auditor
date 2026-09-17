"""
================================================================================
 CIRCUIT BREAKER — protege al objetivo (y al escáner) de un escaneo activo
 que se descontrola
================================================================================
Los checks pasivos (Fase 2) no necesitaban esto: son un puñado de requests
fijos por escaneo. Los checks activos de Fase 3 pueden terminar probando
docenas de tablas/buckets/colecciones -- sin un límite, un objetivo con
muchas tablas podría recibir un escaneo agresivo sin querer, o un objetivo
que empieza a fallar/degradarse podría seguir recibiendo requests inútiles.

Dos protecciones independientes:
  1. Límite duro de requests + espera entre cada uno -- determinístico,
     siempre aplica, no depende de ninguna medición.
  2. Detección de anomalía -- si la tasa de error o la latencia se disparan
     respecto a una línea base medida al principio del propio escaneo, el
     circuit breaker aborta el resto por su cuenta. No es una heurística de
     seguridad (no distingue "el objetivo nos está bloqueando" de "el
     objetivo simplemente está caído") -- en cualquiera de los dos casos,
     la respuesta correcta es la misma: dejar de insistir.
================================================================================
"""

import time
from dataclasses import dataclass, field


class EscaneoAbortadoError(Exception):
    """El circuit breaker detuvo el escaneo -- ver el mensaje para la causa exacta."""


@dataclass
class CircuitBreaker:
    max_requests: int = 30
    espera_entre_requests_segundos: float = 0.5
    minimo_muestras_para_evaluar: int = 5
    multiplicador_latencia_anomala: float = 4.0
    umbral_tasa_error: float = 0.5
    # Piso absoluto para la línea base de latencia -- sin esto, un objetivo
    # naturalmente rapidísimo (línea base ~0.001s) dispara el chequeo de
    # latencia por puro ruido de temporización ante la primera variación
    # mínima, incluso sin nada realmente anómalo pasando. Encontrado en
    # pruebas: enmascaraba el chequeo de tasa de error porque disparaba
    # primero. 50ms es conservador -- cualquier request real a través de
    # internet ya tiene más jitter que eso.
    piso_latencia_base_segundos: float = 0.05

    _contador_requests: int = field(default=0, init=False)
    _errores: int = field(default=0, init=False)
    _latencias: list = field(default_factory=list, init=False)
    _latencia_base: float | None = field(default=None, init=False)
    _abortado: bool = field(default=False, init=False)
    _razon_aborto: str | None = field(default=None, init=False)

    @property
    def contador_requests(self) -> int:
        return self._contador_requests

    @property
    def abortado(self) -> bool:
        return self._abortado

    @property
    def razon_aborto(self) -> str | None:
        return self._razon_aborto

    def _abortar(self, razon: str) -> None:
        """
        Una vez abortado, el breaker se queda abortado para siempre -- no
        se "recupera" si la siguiente muestra da rápida por casualidad.
        `antes_de_request()` vuelve a lanzar de inmediato en cualquier
        llamada posterior, incluso desde un check ACTIVO distinto que
        comparta esta misma instancia (todos los checks de un mismo
        escaneo comparten un único breaker -- ver motor_escaneo_activo.py).
        """
        self._abortado = True
        self._razon_aborto = razon
        raise EscaneoAbortadoError(razon)

    def antes_de_request(self) -> None:
        """Llamar ANTES de cada request. Aplica el límite duro y la espera entre requests."""
        if self._abortado:
            raise EscaneoAbortadoError(self._razon_aborto)
        if self._contador_requests >= self.max_requests:
            self._abortar(
                f"Límite duro de {self.max_requests} requests alcanzado para este objetivo "
                "-- el escaneo se detiene para no seguir insistiendo."
            )
        if self._contador_requests > 0:
            time.sleep(self.espera_entre_requests_segundos)

    def despues_de_request(self, duracion_segundos: float, fue_error: bool) -> None:
        """
        Llamar DESPUÉS de cada request (haya fallado o no) con cuánto tardó.
        Puede lanzar EscaneoAbortadoError si detecta anomalía -- quien llama
        debe dejar que esa excepción se propague, no capturarla en silencio.
        """
        self._contador_requests += 1
        self._latencias.append(duracion_segundos)
        if fue_error:
            self._errores += 1

        if len(self._latencias) < self.minimo_muestras_para_evaluar:
            return  # no hay suficientes muestras para juzgar "anómalo" con confianza todavía

        if self._latencia_base is None:
            muestras_iniciales = sorted(self._latencias[: self.minimo_muestras_para_evaluar])
            self._latencia_base = muestras_iniciales[len(muestras_iniciales) // 2]  # mediana

        tasa_error_actual = self._errores / self._contador_requests
        if tasa_error_actual > self.umbral_tasa_error:
            self._abortar(
                f"Tasa de error anómala: {self._errores}/{self._contador_requests} requests "
                f"({tasa_error_actual:.0%}) fallaron -- el objetivo parece tener problemas, "
                "el escaneo se detiene en vez de seguir insistiendo."
            )

        umbral_latencia = max(self._latencia_base, self.piso_latencia_base_segundos) * self.multiplicador_latencia_anomala
        if duracion_segundos > umbral_latencia:
            self._abortar(
                f"Latencia anómala: {duracion_segundos:.2f}s frente a una base de "
                f"{self._latencia_base:.2f}s medida al principio de este escaneo -- el "
                "objetivo parece estar degradado, el escaneo se detiene."
            )


def ejecutar_con_breaker(breaker: CircuitBreaker, fn, es_error_de_respuesta=None):
    """
    Envuelve una llamada HTTP (un callable sin argumentos que hace el
    request real) con el ciclo completo del circuit breaker: valida el
    límite antes, mide cuánto tardó, y evalúa latencia/tasa de error
    después.

    Dos formas de contar como "error": que `fn()` lance una excepción
    (network-level -- DNS, timeout, conexión rechazada), o que devuelva una
    respuesta que `es_error_de_respuesta(resultado)` clasifique como error
    (HTTP-level -- ej. `lambda r: r.status_code >= 500`). Sin esto último,
    un objetivo que empieza a devolver 500 en vez de fallar la conexión
    nunca contaría como "tasa de error" para el circuit breaker -- un
    request HTTP exitoso con un status 500 no lanza excepción por sí solo.

    Si `despues_de_request` decide abortar, esa excepción reemplaza a
    cualquier excepción original de `fn()` -- es deliberado: EscaneoAbortadoError
    es más informativo para quien orquesta el escaneo que el error de red
    crudo que lo disparó.
    """
    breaker.antes_de_request()
    inicio = time.time()
    fue_error = False
    try:
        resultado = fn()
        if es_error_de_respuesta is not None and es_error_de_respuesta(resultado):
            fue_error = True
        return resultado
    except Exception:
        fue_error = True
        raise
    finally:
        duracion = time.time() - inicio
        breaker.despues_de_request(duracion, fue_error)
