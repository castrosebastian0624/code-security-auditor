-- ==============================================================================
-- 005_evidencia_checks_pasivos.sql
-- ==============================================================================
-- Extiende el allowlist de claves de hallazgos.evidencia_metadata (trigger
-- fn_validar_evidencia_metadata, definido en 002_pivot_schema.sql) para
-- cubrir la evidencia que producen los 3 checks pasivos de Fase 2: headers
-- de seguridad, secretos en el bundle JS, y dependencias vulnerables.
--
-- Claves nuevas:
--   archivo            -- archivo JS del bundle donde se encontró algo
--   patron_detectado   -- nombre del patrón de secreto que matcheó (ej. "openai_api_key")
--   valor_parcial       -- el secreto encontrado, SIEMPRE enmascarado (ver
--                          checks_pasivos._enmascarar) -- nunca el valor completo
--   header              -- nombre de un header de seguridad ausente/presente
--   valor_header        -- valor crudo de un header (ej. Access-Control-Allow-Origin)
--   libreria             -- nombre de una librería JS vulnerable detectada
--   version_detectada   -- versión de esa librería
--   cve_ids              -- CVEs asociados, como string separado por comas
--
-- Se reemplaza fn_validar_evidencia_metadata completo (CREATE OR REPLACE)
-- en vez de solo documentar el cambio, porque el allowlist vive hardcodeado
-- dentro del cuerpo de la función -- no hay una tabla de configuración
-- separada que alterar.
-- ==============================================================================

CREATE OR REPLACE FUNCTION fn_validar_evidencia_metadata()
RETURNS trigger AS $$
DECLARE
    claves_permitidas TEXT[] := ARRAY[
        'tabla', 'endpoint', 'metodo_http', 'status_code',
        'conteo_filas_expuestas', 'comando_reproduccion',
        'headers_relevantes', 'nota',
        'archivo', 'patron_detectado', 'valor_parcial',
        'header', 'valor_header',
        'libreria', 'version_detectada', 'cve_ids'
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

-- El trigger ya existe (creado en 002) y apunta a esta función por nombre;
-- CREATE OR REPLACE arriba ya actualiza su comportamiento sin necesidad de
-- recrear el trigger en sí.
