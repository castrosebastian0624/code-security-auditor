-- ==============================================================================
-- 001_codigos_acceso.sql
-- ==============================================================================
-- Reproduce el schema de la tabla `codigos_acceso` tal como existe hoy en el
-- proyecto de Neon en producción. Esta tabla YA EXISTE — este archivo es un
-- documento de recuperación ante desastre, no algo que necesites correr en la
-- base actual. Se escribió leyendo directamente el schema en vivo (via
-- information_schema y pg_constraint), no de memoria.
--
-- Si alguna vez pierdes el proyecto de Neon, correr este archivo contra una
-- base nueva reproduce la tabla y permite seguir usando generar_codigo.py y
-- app.py sin cambios.
--
-- Es idempotente (CREATE TABLE IF NOT EXISTS): correrlo contra la base real
-- no rompe nada, simplemente no hace nada si la tabla ya existe.
-- ==============================================================================

CREATE TABLE IF NOT EXISTS codigos_acceso (
    codigo             VARCHAR NOT NULL PRIMARY KEY,
    prospecto_nombre   VARCHAR,
    usos_permitidos    INTEGER DEFAULT 2,
    usos_realizados    INTEGER DEFAULT 0,
    creado_en          TIMESTAMP DEFAULT now()
);

COMMENT ON TABLE codigos_acceso IS
    'Códigos de acceso de un solo uso por prospecto (v1: auditoría de código '
    'por archivo). El código es la clave primaria. usos_realizados se '
    'incrementa solo cuando una auditoría termina con éxito (ver '
    'incrementar_uso() en app.py) — un error de conexión o de parseo de JSON '
    'no consume un uso.';
