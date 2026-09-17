-- ==============================================================================
-- 006_fase3_lectura_activa.sql
-- ==============================================================================
-- Fase 3 Parte A: escaneo activo de LECTURA (RLS de Supabase, Storage
-- buckets, equivalentes de Firebase, detección estática de RPC/Edge
-- Functions). Nada de escritura ni invocación de funciones todavía -- eso
-- queda pendiente de un documento de diseño aparte, revisado antes de
-- implementarse.
--
-- Tres cambios:
--
-- 1. Consentimiento explícito para escaneo activo -- SEPARADO de la
--    verificación de propiedad de dominio (proyectos.verification_status).
--    Un proyecto puede estar verificado por DNS/archivo y aun así no tener
--    autorización para que le corramos checks activos -- son dos actos de
--    consentimiento distintos con distinto alcance (verificar que eres
--    dueño del dominio no es lo mismo que autorizar que probemos acceso a
--    tus tablas/buckets sin autenticación).
--
-- 2. hallazgos.tipo_check: agrega 'storage_expuesto' (Supabase Storage o
--    Firebase Storage accesibles sin auth) y 'rpc_deteccion' (función
--    invocable encontrada por análisis estático del bundle, sin invocar).
--    'rls' se reusa tal cual para Supabase RLS Y para los equivalentes de
--    lectura de Firestore/Realtime Database -- misma categoría conceptual
--    (acceso a datos sin control de autorización), aunque Firebase no le
--    llame "RLS" a su mecanismo.
--
-- 3. escaneos.estado: agrega 'abortado' -- distinto de 'fallido'. Un
--    escaneo 'fallido' murió por un error (excepción, timeout de red). Un
--    escaneo 'abortado' se DETUVO A SÍ MISMO on purpose porque el circuit
--    breaker detectó tasa de error o latencia anómala del objetivo -- la
--    distinción importa para el reporte: uno es "algo salió mal", el otro
--    es "nos frenamos nosotros para no seguir insistiendo".
--
-- 4. evidencia_metadata: nuevas claves para la evidencia que producen estos
--    checks -- bucket, conteo_archivos_expuestos, nombres_archivos,
--    nombre_funcion. Los nombres de archivo son evidencia legítima según lo
--    pedido explícitamente (nunca el contenido de esos archivos), aunque un
--    nombre de archivo en sí mismo ocasionalmente pueda ser sensible (ej.
--    "pasaporte_maria.jpg") -- se documenta como consideración residual,
--    no se bloquea, porque es exactamente la evidencia que se pidió.
-- ==============================================================================

ALTER TABLE proyectos
    ADD COLUMN IF NOT EXISTS consentimiento_escaneo_activo BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS consentimiento_otorgado_en TIMESTAMP;

COMMENT ON COLUMN proyectos.consentimiento_escaneo_activo IS
    'Consentimiento explícito y SEPARADO de verification_status -- un proyecto '
    'verificado por dominio puede seguir sin este consentimiento. Ningún check '
    'activo (Fase 3) puede correr si esto es false, sin importar el estado de '
    'verificación de dominio. Ver pages/2_Escanear.py.';


ALTER TABLE hallazgos DROP CONSTRAINT IF EXISTS hallazgos_tipo_check_check;
ALTER TABLE hallazgos ADD CONSTRAINT hallazgos_tipo_check_check
    CHECK (tipo_check IN ('rls', 'secretos_bundle', 'idor', 'headers', 'dependencias', 'storage_expuesto', 'rpc_deteccion', 'otro'));


ALTER TABLE escaneos DROP CONSTRAINT IF EXISTS escaneos_estado_check;
ALTER TABLE escaneos ADD CONSTRAINT escaneos_estado_check
    CHECK (estado IN ('pendiente', 'en_progreso', 'completado', 'fallido', 'abortado'));


CREATE OR REPLACE FUNCTION fn_validar_evidencia_metadata()
RETURNS trigger AS $$
DECLARE
    claves_permitidas TEXT[] := ARRAY[
        'tabla', 'endpoint', 'metodo_http', 'status_code',
        'conteo_filas_expuestas', 'comando_reproduccion',
        'headers_relevantes', 'nota',
        'archivo', 'patron_detectado', 'valor_parcial',
        'header', 'valor_header',
        'libreria', 'version_detectada', 'cve_ids',
        'bucket', 'conteo_archivos_expuestos', 'nombres_archivos', 'nombre_funcion'
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
