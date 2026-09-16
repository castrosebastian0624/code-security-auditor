# Migraciones

No hay una herramienta de migraciones (Alembic, etc.) todavía — son archivos
SQL planos, numerados en el orden en que deben aplicarse, pensados para
correrse a mano con `psql` contra el proyecto de Neon:

```bash
psql "$DATABASE_URL" -f migrations/001_codigos_acceso.sql
psql "$DATABASE_URL" -f migrations/002_pivot_schema.sql
```

Todas usan `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`, así
que son seguras de correr más de una vez.

| Archivo | Qué hace |
|---|---|
| `001_codigos_acceso.sql` | Reproduce el schema de `codigos_acceso` (v1, ya existe en producción). Es un documento de recuperación ante desastre, no un cambio nuevo. |
| `002_pivot_schema.sql` | Tablas nuevas para el pivote: `usuarios`, `proyectos`, `escaneos`, `hallazgos`. No toca `codigos_acceso`. Incluye dos triggers de defensa en profundidad: bloquear escaneos sobre proyectos no verificados, y validar que `hallazgos.evidencia_metadata` nunca contenga datos reales de terceros (solo metadatos de evidencia). |
| `003_expiracion_token.sql` | Agrega `verification_token_expires_at` a `proyectos` (48h desde la creación) y un trigger que bloquea marcar un proyecto como `verificado` si el token ya venció. |

Cuando el pivote esté más maduro y el equipo crezca, vale la pena migrar a
Alembic o similar — por ahora, con un solo desarrollador y una base de datos,
el costo de esa herramienta no se justifica.
