"""
================================================================================
 ACCESO A DATOS — esquema nuevo del pivote (usuarios/proyectos/escaneos/hallazgos)
================================================================================
Separado de app.py a propósito: app.py sigue siendo el monolito del flujo v1
(auditoría de código por archivo, tabla codigos_acceso) y no queremos seguir
apilando responsabilidades nuevas ahí mientras el pivote todavía no tiene
lógica de escaneo real. Este módulo es la contraparte de datos de
verificacion_dominio.py.

Mismo patrón de conexión que app.py (una conexión nueva por operación, no una
cacheada): el plan gratuito de Neon suspende la base tras inactividad, y una
conexión guardada de una sesión anterior quedaría muerta.
================================================================================
"""

import json
import os

import psycopg2
from dotenv import load_dotenv

from verificacion_dominio import generar_token

load_dotenv()
DATABASE_URL = os.environ.get("DATABASE_URL")


def get_connection():
    return psycopg2.connect(DATABASE_URL)


# ==============================================================================
# usuarios
# ==============================================================================

def obtener_o_crear_usuario_clerk(clerk_user_id: str, email: str, nombre: str | None = None) -> int:
    """
    Upsert por clerk_user_id (el claim `sub` del token OIDC que devuelve
    Clerk -- ver auth.py). Reemplaza el upsert por email sin verificación de
    la Fase 1 original (migración 004): email y nombre se sincronizan en
    cada login, pero ya no son la identidad -- esa es clerk_user_id.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO usuarios (clerk_user_id, email, nombre)
                VALUES (%s, %s, %s)
                ON CONFLICT (clerk_user_id) DO UPDATE
                    SET email = EXCLUDED.email,
                        nombre = COALESCE(EXCLUDED.nombre, usuarios.nombre)
                RETURNING id
                """,
                (clerk_user_id, email.strip().lower(), nombre),
            )
            usuario_id = cur.fetchone()[0]
        conn.commit()
        return usuario_id
    finally:
        conn.close()


# ==============================================================================
# proyectos
# ==============================================================================

def crear_proyecto(usuario_id: int, dominio: str, metodo: str, token: str) -> int:
    """
    Crea un proyecto en estado 'pendiente'. No verifica nada por sí solo.
    El token vence a las 48h — se calcula con `now()` del lado de la base
    (no en Python) para no depender de que el reloj del proceso y el de
    Neon coincidan.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO proyectos (usuario_id, dominio, verification_method, verification_token, verification_token_expires_at)
                VALUES (%s, %s, %s, %s, now() + interval '48 hours')
                RETURNING id
                """,
                (usuario_id, dominio, metodo, token),
            )
            proyecto_id = cur.fetchone()[0]
        conn.commit()
        return proyecto_id
    finally:
        conn.close()


def regenerar_token(proyecto_id: int) -> str:
    """
    Genera un token nuevo (con 48h de vida nueva) para un proyecto existente
    y lo vuelve a dejar en 'pendiente' — para cuando el token anterior
    venció o el usuario simplemente quiere reintentar desde cero.
    """
    nuevo_token = generar_token()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE proyectos
                SET verification_token = %s,
                    verification_token_expires_at = now() + interval '48 hours',
                    verification_status = 'pendiente',
                    verified_at = NULL
                WHERE id = %s
                """,
                (nuevo_token, proyecto_id),
            )
        conn.commit()
        return nuevo_token
    finally:
        conn.close()


def obtener_proyecto(proyecto_id: int) -> dict | None:
    """
    `token_vencido` se calcula en SQL (comparando contra el `now()` del
    servidor de Neon) en vez de en Python, para no arriesgar un desfase
    entre el reloj del proceso que corre la app y el de la base de datos.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, usuario_id, dominio, nombre, stack_detectado,
                       verification_method, verification_token,
                       verification_status, verified_at, creado_en,
                       verification_token_expires_at,
                       (verification_token_expires_at IS NOT NULL
                        AND verification_token_expires_at < now()) AS token_vencido
                FROM proyectos WHERE id = %s
                """,
                (proyecto_id,),
            )
            fila = cur.fetchone()
    finally:
        conn.close()

    if fila is None:
        return None

    campos = [
        "id", "usuario_id", "dominio", "nombre", "stack_detectado",
        "verification_method", "verification_token",
        "verification_status", "verified_at", "creado_en",
        "verification_token_expires_at", "token_vencido",
    ]
    return dict(zip(campos, fila))


# ==============================================================================
# consentimientos_escaneo -- Fase 3, POR CATEGORÍA (migrations/007)
# ==============================================================================
# Un booleano único habría hecho que aceptar la categoría de HOY (lectura
# activa) cubriera automáticamente cualquier categoría nueva que se agregue
# después (Fase 3 Parte B: escritura de RLS, invocación de RPC/Edge
# Functions -- ver docs/DISENO_FASE3_ESCRITURA_RPC.md) sin que el usuario la
# haya autorizado explícitamente. Cada categoría es su propia fila.

CATEGORIA_LECTURA_ACTIVA = "lectura_activa"


def tiene_consentimiento(proyecto_id: int, categoria: str) -> bool:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM consentimientos_escaneo WHERE proyecto_id = %s AND categoria = %s",
                (proyecto_id, categoria),
            )
            return cur.fetchone() is not None
    finally:
        conn.close()


def otorgar_consentimiento(proyecto_id: int, categoria: str) -> None:
    """
    Idempotente a propósito (ON CONFLICT DO NOTHING): otorgar de nuevo un
    consentimiento ya existente no debe fallar ni pisar `otorgado_en`
    original -- la fecha real de la primera autorización es la que importa.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO consentimientos_escaneo (proyecto_id, categoria)
                VALUES (%s, %s)
                ON CONFLICT (proyecto_id, categoria) DO NOTHING
                """,
                (proyecto_id, categoria),
            )
        conn.commit()
    finally:
        conn.close()


def listar_consentimientos(proyecto_id: int) -> list[dict]:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT categoria, otorgado_en FROM consentimientos_escaneo WHERE proyecto_id = %s ORDER BY otorgado_en",
                (proyecto_id,),
            )
            filas = cur.fetchall()
    finally:
        conn.close()
    return [{"categoria": f[0], "otorgado_en": f[1]} for f in filas]


def listar_proyectos(usuario_id: int) -> list[dict]:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, dominio, verification_method, verification_status, verified_at, creado_en
                FROM proyectos
                WHERE usuario_id = %s
                ORDER BY creado_en DESC
                """,
                (usuario_id,),
            )
            filas = cur.fetchall()
    finally:
        conn.close()

    campos = ["id", "dominio", "verification_method", "verification_status", "verified_at", "creado_en"]
    return [dict(zip(campos, fila)) for fila in filas]


def marcar_proyecto_verificado(proyecto_id: int) -> None:
    """
    Puede fallar con UniqueViolation si otro proyecto ya verificó el mismo
    dominio primero (índice único parcial en proyectos.dominio) — quien
    llame a esta función debe capturar esa excepción y mostrar un mensaje
    claro, no dejar que reviente como error genérico.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE proyectos
                SET verification_status = 'verificado', verified_at = now()
                WHERE id = %s
                """,
                (proyecto_id,),
            )
        conn.commit()
    finally:
        conn.close()


def marcar_proyecto_fallido(proyecto_id: int) -> None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE proyectos SET verification_status = 'fallido' WHERE id = %s",
                (proyecto_id,),
            )
        conn.commit()
    finally:
        conn.close()


# ==============================================================================
# escaneos
# ==============================================================================

class ProyectoNoVerificadoError(Exception):
    """El proyecto no está verificado — no se puede crear un escaneo."""


def crear_escaneo(proyecto_id: int, disparado_por: str = "manual") -> int:
    """
    Chequeo de aplicación ANTES del INSERT (evita gastar un round-trip para
    solo recibir la excepción del trigger de la base de datos, y da un
    mensaje de error específico). El trigger trg_bloquear_escaneo_no_verificado
    en la base sigue ahí como respaldo si alguna otra ruta de código llega a
    insertar sin pasar por esta función.
    """
    proyecto = obtener_proyecto(proyecto_id)
    if proyecto is None:
        raise ValueError(f"El proyecto {proyecto_id} no existe.")
    if proyecto["verification_status"] != "verificado":
        raise ProyectoNoVerificadoError(
            f"El proyecto {proyecto_id} ({proyecto['dominio']}) no está "
            f"verificado (estado: {proyecto['verification_status']}). No se "
            "puede crear un escaneo."
        )

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO escaneos (proyecto_id, disparado_por) VALUES (%s, %s) RETURNING id",
                (proyecto_id, disparado_por),
            )
            escaneo_id = cur.fetchone()[0]
        conn.commit()
        return escaneo_id
    finally:
        conn.close()


def marcar_escaneo_en_progreso(escaneo_id: int) -> None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE escaneos SET estado = 'en_progreso' WHERE id = %s", (escaneo_id,))
        conn.commit()
    finally:
        conn.close()


def marcar_escaneo_completado(escaneo_id: int) -> None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE escaneos SET estado = 'completado', finalizado_en = now() WHERE id = %s",
                (escaneo_id,),
            )
        conn.commit()
    finally:
        conn.close()


def marcar_escaneo_fallido(escaneo_id: int) -> None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE escaneos SET estado = 'fallido', finalizado_en = now() WHERE id = %s",
                (escaneo_id,),
            )
        conn.commit()
    finally:
        conn.close()


def marcar_escaneo_abortado(escaneo_id: int) -> None:
    """
    Distinto de 'fallido': 'fallido' es un error nuestro (excepción,
    timeout). 'abortado' es el circuit breaker frenando el escaneo a
    propósito porque el objetivo mostró latencia/tasa de error anómala --
    ver circuit_breaker.py y motor_escaneo_activo.py.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE escaneos SET estado = 'abortado', finalizado_en = now() WHERE id = %s",
                (escaneo_id,),
            )
        conn.commit()
    finally:
        conn.close()


def guardar_stack_detectado(proyecto_id: int, stack: str) -> None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE proyectos SET stack_detectado = %s WHERE id = %s", (stack, proyecto_id))
        conn.commit()
    finally:
        conn.close()


# ==============================================================================
# hallazgos
# ==============================================================================

def crear_hallazgo(
    escaneo_id: int,
    tipo_check: str,
    severidad: str,
    titulo: str,
    descripcion: str | None = None,
    impacto_potencial: str | None = None,
    sugerencia_tecnica: str | None = None,
    evidencia_metadata: dict | None = None,
) -> int:
    """
    evidencia_metadata pasa por el trigger trg_validar_evidencia_metadata
    (defensa en profundidad, ver migrations/002 y 005) -- si alguna clave no
    está en el allowlist, psycopg2 propaga la excepción de Postgres tal cual.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO hallazgos (
                    escaneo_id, tipo_check, severidad, titulo,
                    descripcion, impacto_potencial, sugerencia_tecnica, evidencia_metadata
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    escaneo_id, tipo_check, severidad, titulo,
                    descripcion, impacto_potencial, sugerencia_tecnica,
                    json.dumps(evidencia_metadata) if evidencia_metadata is not None else None,
                ),
            )
            hallazgo_id = cur.fetchone()[0]
        conn.commit()
        return hallazgo_id
    finally:
        conn.close()


def listar_hallazgos(escaneo_id: int) -> list[dict]:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, tipo_check, severidad, titulo, descripcion,
                       impacto_potencial, sugerencia_tecnica, evidencia_metadata, creado_en
                FROM hallazgos
                WHERE escaneo_id = %s
                ORDER BY
                    CASE severidad
                        WHEN 'CRITICA' THEN 0 WHEN 'ALTA' THEN 1 WHEN 'MEDIA' THEN 2
                        WHEN 'BAJA' THEN 3 ELSE 4
                    END
                """,
                (escaneo_id,),
            )
            filas = cur.fetchall()
    finally:
        conn.close()

    campos = [
        "id", "tipo_check", "severidad", "titulo", "descripcion",
        "impacto_potencial", "sugerencia_tecnica", "evidencia_metadata", "creado_en",
    ]
    return [dict(zip(campos, fila)) for fila in filas]


def listar_escaneos(proyecto_id: int) -> list[dict]:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, estado, disparado_por, iniciado_en, finalizado_en
                FROM escaneos
                WHERE proyecto_id = %s
                ORDER BY iniciado_en DESC
                """,
                (proyecto_id,),
            )
            filas = cur.fetchall()
    finally:
        conn.close()

    campos = ["id", "estado", "disparado_por", "iniciado_en", "finalizado_en"]
    return [dict(zip(campos, fila)) for fila in filas]
