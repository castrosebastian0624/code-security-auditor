-- ==============================================================================
-- 004_clerk_identity.sql
-- ==============================================================================
-- Reemplaza la identificación por email sin verificación (ver comentario en
-- 002_pivot_schema.sql) por una identidad real respaldada por Clerk (OIDC,
-- vía st.login() nativo de Streamlit -- ver auth.py).
--
-- `usuarios` tiene 0 filas en producción a la fecha de esta migración: no hay
-- ningún dato real que migrar, por eso clerk_user_id puede agregarse
-- directamente como NOT NULL UNIQUE sin una transición de columna nullable.
-- Si esto llegara a correr contra una base con usuarios ya creados por el
-- flujo viejo (email), la migración fallará al intentar poner NOT NULL sobre
-- filas existentes sin valor -- es intencional: obliga a decidir a mano cómo
-- mapear esos usuarios viejos a un clerk_user_id real, en vez de inventar uno.
-- ==============================================================================

ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS clerk_user_id VARCHAR;

-- UNIQUE como índice separado (no inline en el ALTER) para que sea seguro
-- re-correr esta migración: CREATE UNIQUE INDEX IF NOT EXISTS es idempotente,
-- un ALTER TABLE ... ADD CONSTRAINT no lo es.
CREATE UNIQUE INDEX IF NOT EXISTS usuarios_clerk_user_id_uidx ON usuarios (clerk_user_id);

ALTER TABLE usuarios ALTER COLUMN clerk_user_id SET NOT NULL;

COMMENT ON COLUMN usuarios.clerk_user_id IS
    'Subject (sub) claim del token OIDC de Clerk. Identidad real desde esta '
    'migración -- reemplaza el upsert por email sin verificación. email sigue '
    'existiendo como dato informativo (se sincroniza en cada login), pero ya '
    'no es la clave de identidad.';
