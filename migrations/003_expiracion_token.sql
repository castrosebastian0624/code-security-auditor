-- ==============================================================================
-- 003_expiracion_token.sql
-- ==============================================================================
-- Un token de verificación de dominio generado hoy y nunca reclamado no
-- debería servir para siempre — entre otras cosas, porque un registro TXT
-- o archivo de verificación que alguien deja publicado indefinidamente es
-- una superficie de reutilización innecesaria. Los tokens vencen 48h
-- después de generados.
--
-- Igual que en 002_pivot_schema.sql, la regla se aplica en DOS capas:
--   a) capa de aplicación: db_pivot.py chequea el vencimiento antes de
--      intentar la verificación en vivo (evita gastar una consulta DNS/HTTP
--      en un token que ya sabemos vencido).
--   b) capa de base de datos: un trigger BEFORE UPDATE en `proyectos`
--      rechaza la transición a verification_status='verificado' si el
--      token ya venció, sin importar qué código lo intente.
-- ==============================================================================

ALTER TABLE proyectos
    ADD COLUMN IF NOT EXISTS verification_token_expires_at TIMESTAMP;

COMMENT ON COLUMN proyectos.verification_token_expires_at IS
    'El token vence 48h después de generarse (ver crear_proyecto / '
    'regenerar_token en db_pivot.py). NULL solo debería darse en proyectos '
    'creados antes de esta migración; todo proyecto nuevo siempre trae '
    'expiración. Un token vencido no puede verificar el dominio — hay que '
    'generar uno nuevo (botón "Generar nuevo token" en la UI).';

CREATE OR REPLACE FUNCTION fn_bloquear_verificacion_token_vencido()
RETURNS trigger AS $$
BEGIN
    IF NEW.verification_status = 'verificado'
       AND (OLD.verification_status IS DISTINCT FROM 'verificado')
       AND NEW.verification_token_expires_at IS NOT NULL
       AND NEW.verification_token_expires_at < now()
    THEN
        RAISE EXCEPTION
            'No se puede verificar el proyecto %: el token venció el % (ahora: %). Genera un token nuevo.',
            NEW.id, NEW.verification_token_expires_at, now();
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_bloquear_verificacion_token_vencido ON proyectos;
CREATE TRIGGER trg_bloquear_verificacion_token_vencido
    BEFORE UPDATE ON proyectos
    FOR EACH ROW
    EXECUTE FUNCTION fn_bloquear_verificacion_token_vencido();
