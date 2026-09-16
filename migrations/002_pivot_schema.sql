-- ==============================================================================
-- 002_pivot_schema.sql
-- ==============================================================================
-- Esquema nuevo para el pivote a "escaneo de seguridad por URL". Convive con
-- codigos_acceso (001) sin tocarla — no hay ningún DROP ni ALTER sobre esa
-- tabla en este archivo. Es la Fase 1 (fundación): estas tablas existen para
-- soportar el flujo de verificación de dominio. Todavía NO hay lógica de
-- escaneo real (eso es Fase 2) — por eso `escaneos` y `hallazgos` están listas
-- para recibir datos, pero nada las escribe todavía salvo el flujo manual de
-- pruebas.
--
-- Decisiones de diseño relevantes (explicadas porque no son obvias del DDL):
--
-- 1. NO existe todavía un sistema de autenticación real. `usuarios` se
--    identifica hoy por email (upsert manual desde la UI de verificación de
--    dominio). Cuando haya login real, esta tabla es el punto de enganche.
--
-- 2. `proyectos.dominio` solo tiene UNICIDAD GARANTIZADA cuando el proyecto
--    está verificado (índice único parcial). Esto permite que dos personas
--    intenten verificar el mismo dominio en paralelo (ambos quedan en
--    'pendiente'), pero solo una puede llegar a 'verificado' — la segunda
--    verificación fallará por violar el índice único, lo cual es exactamente
--    el comportamiento correcto (evita que alguien reclame un dominio que
--    otro ya demostró controlar).
--
-- 3. Un escaneo NO puede crearse para un proyecto no verificado. Esto se
--    aplica en DOS capas (defensa en profundidad, coherente con lo que este
--    producto le exige a sus clientes):
--       a) capa de aplicación: db_pivot.crear_escaneo() valida el estado
--          antes de insertar.
--       b) capa de base de datos: un trigger BEFORE INSERT en `escaneos`
--          rechaza la fila si el proyecto asociado no está verificado, sin
--          importar qué código la esté insertando.
--
-- 4. `hallazgos.evidencia_metadata` es JSONB con un ALLOWLIST DE CLAVES
--    aplicado por trigger (no solo documentado en un comentario). Un
--    hallazgo que involucre datos reales de un tercero (ej. filas expuestas
--    por RLS abierta) debe guardar SOLO metadatos de la evidencia — nombre
--    de tabla, conteo de filas, endpoint, comando curl de reproducción —
--    NUNCA el contenido real de esas filas. El trigger rechaza cualquier
--    clave fuera del allowlist. Los campos de texto libre (descripcion,
--    impacto_potencial, sugerencia_tecnica) existen para la narrativa que
--    escribe el LLM; el schema no puede garantizar semánticamente que esa
--    narrativa nunca cite un dato real citado por error — esa garantía le
--    corresponde al prompt/código de Fase 2, que debe asegurarse de nunca
--    pasarle datos reales de terceros al LLM como contexto. Ver README de
--    esta carpeta.
-- ==============================================================================


-- ------------------------------------------------------------------------------
-- usuarios
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS usuarios (
    id           SERIAL PRIMARY KEY,
    email        VARCHAR NOT NULL UNIQUE,
    nombre       VARCHAR,
    creado_en    TIMESTAMP NOT NULL DEFAULT now()
);

COMMENT ON TABLE usuarios IS
    'Identidad mínima por email. No hay autenticación real todavía (sin '
    'password/OAuth) — se crea/reutiliza por email desde el flujo de '
    'verificación de dominio. Pendiente de decidir mecanismo de auth real '
    'antes de cobrar suscripciones.';


-- ------------------------------------------------------------------------------
-- proyectos (sitio/dominio que un usuario quiere escanear)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS proyectos (
    id                     SERIAL PRIMARY KEY,
    usuario_id             INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
    dominio                VARCHAR NOT NULL,
    nombre                 VARCHAR,
    stack_detectado        VARCHAR,
    verification_method    VARCHAR NOT NULL
                              CHECK (verification_method IN ('dns_txt', 'http_file')),
    verification_token     VARCHAR NOT NULL,
    verification_status    VARCHAR NOT NULL DEFAULT 'pendiente'
                              CHECK (verification_status IN ('pendiente', 'verificado', 'fallido')),
    verified_at            TIMESTAMP,
    creado_en              TIMESTAMP NOT NULL DEFAULT now()
);

COMMENT ON COLUMN proyectos.dominio IS
    'Dominio normalizado (sin protocolo, sin path, sin trailing slash, '
    'minúsculas) — ver verificacion_dominio.normalizar_dominio().';
COMMENT ON COLUMN proyectos.stack_detectado IS
    'supabase | firebase | desconocido — lo llena Fase 2 (fingerprinting del '
    'bundle). NULL hasta entonces.';
COMMENT ON COLUMN proyectos.verification_method IS
    'dns_txt: registro TXT en _auditoria-verificacion.<dominio>. '
    'http_file: archivo en https://<dominio>/.well-known/auditoria-verificacion.txt. '
    'El usuario elige uno de los dos según lo que pueda controlar (DNS propio '
    'vs. solo acceso al builder para agregar un archivo estático).';

CREATE INDEX IF NOT EXISTS idx_proyectos_usuario_id ON proyectos(usuario_id);

-- Un dominio solo puede tener UN proyecto verificado a la vez. Varios
-- intentos 'pendiente' o 'fallido' para el mismo dominio son válidos
-- (reintentos, o dos personas compitiendo por verificarlo primero).
CREATE UNIQUE INDEX IF NOT EXISTS proyectos_dominio_verificado_uidx
    ON proyectos (dominio)
    WHERE verification_status = 'verificado';


-- ------------------------------------------------------------------------------
-- escaneos (corridas de escaneo sobre un proyecto verificado)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS escaneos (
    id                SERIAL PRIMARY KEY,
    proyecto_id       INTEGER NOT NULL REFERENCES proyectos(id) ON DELETE CASCADE,
    estado            VARCHAR NOT NULL DEFAULT 'pendiente'
                        CHECK (estado IN ('pendiente', 'en_progreso', 'completado', 'fallido')),
    disparado_por     VARCHAR NOT NULL DEFAULT 'manual'
                        CHECK (disparado_por IN ('manual', 'programado')),
    iniciado_en       TIMESTAMP NOT NULL DEFAULT now(),
    finalizado_en     TIMESTAMP
);

COMMENT ON COLUMN escaneos.disparado_por IS
    '''manual'' hoy. ''programado'' queda listo para el tier de $39/mes '
    '(monitoreo semanal) cuando exista un scheduler — Fase 2/3, no ahora.';

CREATE INDEX IF NOT EXISTS idx_escaneos_proyecto_id ON escaneos(proyecto_id);


-- ------------------------------------------------------------------------------
-- hallazgos (resultado individual de un escaneo)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hallazgos (
    id                     SERIAL PRIMARY KEY,
    escaneo_id             INTEGER NOT NULL REFERENCES escaneos(id) ON DELETE CASCADE,
    tipo_check             VARCHAR NOT NULL
                              CHECK (tipo_check IN ('rls', 'secretos_bundle', 'idor', 'headers', 'dependencias', 'otro')),
    severidad              VARCHAR NOT NULL
                              CHECK (severidad IN ('CRITICA', 'ALTA', 'MEDIA', 'BAJA', 'INFORMATIVA')),
    titulo                 VARCHAR NOT NULL,
    descripcion            TEXT,
    impacto_potencial      TEXT,
    sugerencia_tecnica     TEXT,
    evidencia_metadata     JSONB,
    creado_en              TIMESTAMP NOT NULL DEFAULT now()
);

COMMENT ON COLUMN hallazgos.evidencia_metadata IS
    'SOLO metadatos de evidencia, nunca datos reales de terceros. Claves '
    'permitidas (aplicado por trigger, no solo por convención): tabla, '
    'endpoint, metodo_http, status_code, conteo_filas_expuestas, '
    'comando_reproduccion, headers_relevantes, nota.';

CREATE INDEX IF NOT EXISTS idx_hallazgos_escaneo_id ON hallazgos(escaneo_id);


-- ==============================================================================
-- Triggers de defensa en profundidad
-- ==============================================================================

-- Bloquea la creación de un escaneo si el proyecto no está verificado,
-- independientemente de qué código intente el INSERT.
CREATE OR REPLACE FUNCTION fn_bloquear_escaneo_no_verificado()
RETURNS trigger AS $$
DECLARE
    estado_proyecto VARCHAR;
BEGIN
    SELECT verification_status INTO estado_proyecto
    FROM proyectos
    WHERE id = NEW.proyecto_id;

    IF estado_proyecto IS DISTINCT FROM 'verificado' THEN
        RAISE EXCEPTION
            'No se puede crear un escaneo para el proyecto %: dominio no verificado (estado actual: %).',
            NEW.proyecto_id, COALESCE(estado_proyecto, 'proyecto inexistente');
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_bloquear_escaneo_no_verificado ON escaneos;
CREATE TRIGGER trg_bloquear_escaneo_no_verificado
    BEFORE INSERT ON escaneos
    FOR EACH ROW
    EXECUTE FUNCTION fn_bloquear_escaneo_no_verificado();


-- Rechaza cualquier clave en evidencia_metadata que no esté en el allowlist.
-- Esto es lo que convierte la regla de "nunca guardes datos reales de
-- terceros" en una restricción técnica real y no solo un comentario.
CREATE OR REPLACE FUNCTION fn_validar_evidencia_metadata()
RETURNS trigger AS $$
DECLARE
    claves_permitidas TEXT[] := ARRAY[
        'tabla', 'endpoint', 'metodo_http', 'status_code',
        'conteo_filas_expuestas', 'comando_reproduccion',
        'headers_relevantes', 'nota'
    ];
    clave TEXT;
BEGIN
    IF NEW.evidencia_metadata IS NOT NULL THEN
        FOR clave IN SELECT jsonb_object_keys(NEW.evidencia_metadata) LOOP
            IF NOT (clave = ANY(claves_permitidas)) THEN
                RAISE EXCEPTION
                    'evidencia_metadata contiene una clave no permitida: "%". '
                    'Este campo es SOLO para metadatos de evidencia (nombre de '
                    'tabla, conteo de filas, comando de reproducción), NUNCA '
                    'para el contenido real de datos de terceros. Claves '
                    'permitidas: %',
                    clave, array_to_string(claves_permitidas, ', ');
            END IF;
        END LOOP;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_validar_evidencia_metadata ON hallazgos;
CREATE TRIGGER trg_validar_evidencia_metadata
    BEFORE INSERT OR UPDATE ON hallazgos
    FOR EACH ROW
    EXECUTE FUNCTION fn_validar_evidencia_metadata();
