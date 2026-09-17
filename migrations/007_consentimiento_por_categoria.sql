-- ==============================================================================
-- 007_consentimiento_por_categoria.sql
-- ==============================================================================
-- Reemplaza proyectos.consentimiento_escaneo_activo (booleano único, 006) por
-- una tabla de consentimientos POR CATEGORÍA. Razón: Fase 3 Parte A (lectura:
-- RLS, Storage, Firebase, detección de RPC) y Fase 3 Parte B (pendiente:
-- escritura de RLS, invocación de RPC/Edge Functions -- ver
-- docs/DISENO_FASE3_ESCRITURA_RPC.md) son autorizaciones de alcance y riesgo
-- MUY distintos. Un booleano único habría hecho que aceptar Parte A hoy
-- cubriera automáticamente Parte B el día que exista -- exactamente lo que no
-- queremos. Cada categoría nueva se autoriza por separado, explícitamente.
--
-- 0 filas de producción tenían consentimiento_escaneo_activo=true al momento
-- de esta migración (verificado antes de escribirla) -- no hay nada real que
-- migrar, por eso se puede DROPear la columna vieja directamente en el mismo
-- archivo en vez de dejar una columna muerta o un shim de compatibilidad.
-- ==============================================================================

CREATE TABLE IF NOT EXISTS consentimientos_escaneo (
    id            SERIAL PRIMARY KEY,
    proyecto_id   INTEGER NOT NULL REFERENCES proyectos(id) ON DELETE CASCADE,
    categoria     VARCHAR NOT NULL
                    CHECK (categoria IN ('lectura_activa')),
    otorgado_en   TIMESTAMP NOT NULL DEFAULT now(),
    UNIQUE (proyecto_id, categoria)
);

COMMENT ON TABLE consentimientos_escaneo IS
    'Un proyecto puede tener 0, 1 o varias filas -- una por categoría de '
    'escaneo activo autorizada. "lectura_activa" cubre HOY: RLS de Supabase '
    '(conteo de filas vía anon key), listado de Storage buckets, lectura de '
    'Firestore/Realtime Database/Firebase Storage, y detección estática de '
    'RPC/Edge Functions (sin invocar). Cuando exista Fase 3 Parte B '
    '(escritura de RLS, invocación real de RPC/Edge Functions -- ver '
    'docs/DISENO_FASE3_ESCRITURA_RPC.md), se agrega como categoría(s) nueva(s) '
    'al CHECK de arriba -- nunca queda cubierta por una fila ya existente de '
    'otra categoría.';

CREATE INDEX IF NOT EXISTS idx_consentimientos_escaneo_proyecto_id ON consentimientos_escaneo(proyecto_id);

ALTER TABLE proyectos DROP COLUMN IF EXISTS consentimiento_escaneo_activo;
ALTER TABLE proyectos DROP COLUMN IF EXISTS consentimiento_otorgado_en;
