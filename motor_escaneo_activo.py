"""
================================================================================
 MOTOR DE ESCANEO ACTIVO — Fase 3 Parte A (lectura, con consentimiento)
================================================================================
Distinto de motor_escaneo.py (Fase 2, pasivo) en dos formas importantes:

1. Requiere consentimiento explícito y SEPARADO de la verificación de
   dominio -- tabla `consentimientos_escaneo`, por categoría (migrations/007,
   ver db_pivot.CATEGORIA_LECTURA_ACTIVA). Se valida ANTES de crear siquiera
   la fila de escaneo, no como un chequeo tardío -- un proyecto sin
   consentimiento no debe dejar ningún rastro de intento en la base. Una
   categoría futura (Fase 3 Parte B) necesitaría su propio chequeo acá, no
   hereda este.

2. Usa un CircuitBreaker COMPARTIDO entre todos los checks activos de un
   mismo escaneo (RLS, Storage, Firebase) -- si cualquiera de ellos dispara
   el límite duro o detecta anomalía, el resto tampoco corre (el breaker
   queda "pegajoso", ver circuit_breaker.py). El escaneo se marca
   'abortado' (no 'fallido' -- 'fallido' es un error nuestro, 'abortado' es
   que nos frenamos a propósito), pero los hallazgos reales encontrados
   ANTES del aborto se guardan igual -- no se pierden.

Reusa motor_escaneo.SYSTEM_PROMPT_V2 (ya extendido con las categorías de
Fase 3) y motor_escaneo.llamar_llm() -- no duplica la llamada al LLM.

NO implementa (a propósito, pendiente de documento de diseño revisado antes
de construirse): ninguna escritura, ninguna invocación real de RPC/Edge
Functions/Callable Functions.
================================================================================
"""

import checks_activos
import db_pivot
import fingerprinting
import ingesta
import motor_escaneo
from circuit_breaker import CircuitBreaker, EscaneoAbortadoError

MAX_REQUESTS_POR_ESCANEO = 30
ESPERA_ENTRE_REQUESTS_SEGUNDOS = 0.3
MAX_COLECCIONES_FIRESTORE = 15
MAX_RUTAS_RTDB = 15


class ConsentimientoRequeridoError(Exception):
    """El proyecto no tiene el consentimiento de la categoría requerida -- ver db_pivot.consentimientos_escaneo."""


def ejecutar_escaneo_activo(proyecto_id: int, disparado_por: str = "manual") -> tuple[int, bool, str | None]:
    """
    Punto de entrada de Fase 3 Parte A (categoría 'lectura_activa'). Devuelve
    (escaneo_id, abortado, razon_aborto).

    El consentimiento se valida ANTES de crear_escaneo() -- si falta, no se
    crea ninguna fila de escaneo, ni siquiera una marcada como fallida. Solo
    valida ESTA categoría -- Fase 3 Parte B (pendiente) va a necesitar su
    propia categoría y su propio chequeo acá, no hereda este.
    """
    proyecto = db_pivot.obtener_proyecto(proyecto_id)
    if proyecto is None:
        raise motor_escaneo.EscaneoError(f"El proyecto {proyecto_id} no existe.")
    if not db_pivot.tiene_consentimiento(proyecto_id, db_pivot.CATEGORIA_LECTURA_ACTIVA):
        raise ConsentimientoRequeridoError(
            f"El proyecto {proyecto_id} ({proyecto['dominio']}) no tiene consentimiento para "
            "la categoría 'lectura_activa'. Debe otorgarse explícitamente antes de correr "
            "cualquier check activo de Fase 3 Parte A."
        )

    escaneo_id = db_pivot.crear_escaneo(proyecto_id, disparado_por=disparado_por)
    db_pivot.marcar_escaneo_en_progreso(escaneo_id)

    url = f"https://{proyecto['dominio']}"
    breaker = CircuitBreaker(
        max_requests=MAX_REQUESTS_POR_ESCANEO,
        espera_entre_requests_segundos=ESPERA_ENTRE_REQUESTS_SEGUNDOS,
    )

    try:
        resultado_ingesta = ingesta.ingerir_url(url)
        fp = fingerprinting.detectar_stack(resultado_ingesta.html_renderizado, resultado_ingesta.archivos_js)

        rls_hallazgos: list = []
        storage_hallazgos: list = []
        firestore_hallazgos: list = []
        rtdb_hallazgos: list = []
        firebase_storage_hallazgo = None
        razon_aborto = None

        try:
            if fp.proveedor == fingerprinting.PROVEEDOR_SUPABASE and fp.supabase_url and fp.supabase_anon_key:
                tablas = checks_activos.descubrir_tablas_postgrest(fp.supabase_url, fp.supabase_anon_key, breaker)
                checks_activos.check_rls_tablas(
                    fp.supabase_url, fp.supabase_anon_key, tablas, breaker, hallazgos=rls_hallazgos
                )
                checks_activos.check_storage_buckets(
                    fp.supabase_url, fp.supabase_anon_key, breaker, hallazgos=storage_hallazgos
                )

            elif fp.proveedor == fingerprinting.PROVEEDOR_FIREBASE:
                colecciones = checks_activos.extraer_colecciones_firestore(resultado_ingesta.archivos_js)
                rutas_rtdb = checks_activos.extraer_rutas_rtdb(resultado_ingesta.archivos_js)

                if fp.firebase_project_id and colecciones:
                    checks_activos.check_firestore(
                        fp.firebase_project_id,
                        colecciones[:MAX_COLECCIONES_FIRESTORE],
                        breaker,
                        hallazgos=firestore_hallazgos,
                    )
                if fp.firebase_database_url and rutas_rtdb:
                    checks_activos.check_rtdb(
                        fp.firebase_database_url, rutas_rtdb[:MAX_RUTAS_RTDB], breaker, hallazgos=rtdb_hallazgos
                    )
                if fp.firebase_storage_bucket:
                    firebase_storage_hallazgo = checks_activos.check_firebase_storage(
                        fp.firebase_storage_bucket, breaker
                    )
        except EscaneoAbortadoError as e:
            razon_aborto = str(e)

        # Detección de RPC/Edge Functions: puro análisis estático, CERO red,
        # corre siempre -- el circuit breaker (que protege contra abuso de
        # red) no aplica acá y un aborto de los checks de arriba no debe
        # impedir esta detección, que no le cuesta nada al objetivo.
        funciones_detectadas = checks_activos.detectar_rpc_edge_functions(resultado_ingesta.archivos_js)

        evidencia = _construir_evidencia_activa(
            url, fp, rls_hallazgos, storage_hallazgos, firestore_hallazgos,
            rtdb_hallazgos, firebase_storage_hallazgo, funciones_detectadas,
        )

        hay_evidencia = any(
            [rls_hallazgos, storage_hallazgos, firestore_hallazgos, rtdb_hallazgos,
             firebase_storage_hallazgo, funciones_detectadas]
        )
        if hay_evidencia:
            reporte = motor_escaneo.llamar_llm(evidencia)
            for vuln in reporte.get("vulnerabilidades", []):
                tipo_check = _inferir_tipo_check_activo(vuln)
                db_pivot.crear_hallazgo(
                    escaneo_id=escaneo_id,
                    tipo_check=tipo_check,
                    severidad=vuln.get("severidad", "INFORMATIVA").upper(),
                    titulo=vuln.get("titulo", "Hallazgo sin título"),
                    descripcion=vuln.get("descripcion"),
                    impacto_potencial=vuln.get("impacto_potencial"),
                    sugerencia_tecnica=vuln.get("sugerencia_tecnica"),
                    evidencia_metadata=_evidencia_para_hallazgo_activo(
                        tipo_check, vuln, rls_hallazgos, storage_hallazgos,
                        firestore_hallazgos, rtdb_hallazgos, firebase_storage_hallazgo, funciones_detectadas,
                    ),
                )

        if razon_aborto:
            db_pivot.marcar_escaneo_abortado(escaneo_id)
            return escaneo_id, True, razon_aborto

        db_pivot.marcar_escaneo_completado(escaneo_id)
        return escaneo_id, False, None

    except Exception as e:
        db_pivot.marcar_escaneo_fallido(escaneo_id)
        raise motor_escaneo.EscaneoError(f"El escaneo activo {escaneo_id} falló: {e}") from e


def _construir_evidencia_activa(
    url, fp, rls_hallazgos, storage_hallazgos, firestore_hallazgos, rtdb_hallazgos,
    firebase_storage_hallazgo, funciones_detectadas,
) -> dict:
    return {
        "url_escaneada": url,
        "stack_detectado": {"proveedor": fp.proveedor, "evidencia": fp.evidencia},
        "rls_expuesto": [
            {"tabla": h.tabla, "conteo_filas_expuestas": h.conteo_filas_expuestas} for h in rls_hallazgos
        ],
        "storage_expuesto": [
            {"bucket": h.bucket, "conteo_archivos_expuestos": h.conteo_archivos_expuestos, "nombres_archivos": h.nombres_archivos}
            for h in storage_hallazgos
        ],
        "firestore_expuesto": [
            {"coleccion": h.coleccion, "conteo_documentos_expuestos": h.conteo_documentos_expuestos}
            for h in firestore_hallazgos
        ],
        "rtdb_expuesto": [
            {"ruta": h.ruta, "conteo_claves_expuestas": h.conteo_claves_expuestas} for h in rtdb_hallazgos
        ],
        "firebase_storage_expuesto": (
            {
                "bucket": firebase_storage_hallazgo.bucket,
                "conteo_archivos_expuestos": firebase_storage_hallazgo.conteo_archivos_expuestos,
                "nombres_archivos": firebase_storage_hallazgo.nombres_archivos,
            }
            if firebase_storage_hallazgo
            else None
        ),
        "funciones_detectadas": [
            {"nombre_funcion": f.nombre_funcion, "tipo": f.tipo, "archivo": f.archivo} for f in funciones_detectadas
        ],
    }


def _inferir_tipo_check_activo(vuln: dict) -> str:
    texto = f"{vuln.get('titulo', '')} {vuln.get('categoria_owasp_o_cwe', '')} {vuln.get('descripcion', '')}".lower()
    if any(p in texto for p in ("rpc", "función invocable", "callable", "edge function")):
        return "rpc_deteccion"
    if any(p in texto for p in ("bucket", "storage", "archivo expuesto", "almacenamiento")):
        return "storage_expuesto"
    if any(p in texto for p in ("rls", "fila", "tabla", "firestore", "documento", "realtime database", "rtdb")):
        return "rls"
    return "otro"


def _evidencia_para_hallazgo_activo(
    tipo_check, vuln, rls_hallazgos, storage_hallazgos, firestore_hallazgos,
    rtdb_hallazgos, firebase_storage_hallazgo, funciones_detectadas,
) -> dict | None:
    ubicacion = (vuln.get("ubicacion") or "").lower()
    titulo = (vuln.get("titulo") or "").lower()
    descripcion = (vuln.get("descripcion") or "").lower()
    texto = f"{titulo} {ubicacion} {descripcion}"

    if tipo_check == "rls":
        for h in rls_hallazgos:
            if h.tabla.lower() in texto:
                return {
                    "tabla": h.tabla,
                    "conteo_filas_expuestas": h.conteo_filas_expuestas,
                    "comando_reproduccion": h.comando_reproduccion,
                }
        for h in firestore_hallazgos:
            if h.coleccion.lower() in texto:
                return {"tabla": h.coleccion, "conteo_filas_expuestas": h.conteo_documentos_expuestos, "comando_reproduccion": h.comando_reproduccion}
        for h in rtdb_hallazgos:
            if h.ruta.lower() in texto:
                return {"tabla": h.ruta, "conteo_filas_expuestas": h.conteo_claves_expuestas, "comando_reproduccion": h.comando_reproduccion}

    elif tipo_check == "storage_expuesto":
        for h in storage_hallazgos:
            if h.bucket.lower() in texto:
                return {"bucket": h.bucket, "conteo_archivos_expuestos": h.conteo_archivos_expuestos, "nombres_archivos": ", ".join(h.nombres_archivos)}
        if firebase_storage_hallazgo and firebase_storage_hallazgo.bucket.lower() in texto:
            h = firebase_storage_hallazgo
            return {"bucket": h.bucket, "conteo_archivos_expuestos": h.conteo_archivos_expuestos, "nombres_archivos": ", ".join(h.nombres_archivos)}

    elif tipo_check == "rpc_deteccion":
        for f in funciones_detectadas:
            if f.nombre_funcion.lower() in texto:
                return {"nombre_funcion": f.nombre_funcion, "archivo": f.archivo}

    ubicacion_original = vuln.get("ubicacion")
    return {"nota": ubicacion_original[:500]} if ubicacion_original else None
