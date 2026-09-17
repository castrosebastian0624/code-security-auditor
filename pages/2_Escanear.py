"""
================================================================================
 ESCANEAR (Fase 2 pasivo + Fase 3 Parte A activo, con consentimiento)
================================================================================
Solo lista proyectos YA VERIFICADOS (ver 1_Verificar_Dominio.py) -- disparar
un escaneo sobre un proyecto no verificado está bloqueado en dos capas
(motor_escaneo.py -> db_pivot.crear_escaneo -> trigger de base de datos),
así que ni siquiera se ofrece el botón acá para no invitar al intento.

El escaneo ACTIVO (Fase 3: RLS de Supabase, Storage buckets, equivalentes de
Firebase, detección de RPC) exige un consentimiento SEPARADO del de
verificación de dominio -- tabla `consentimientos_escaneo`, por CATEGORÍA
(migrations/007; ver db_pivot.CATEGORIA_LECTURA_ACTIVA). Un dominio
verificado por DNS puede seguir sin este consentimiento, y el botón de
escaneo activo queda oculto/bloqueado hasta que se otorgue explícitamente
acá, con su propio checkbox. Cuando exista Fase 3 Parte B (escritura/RPC --
ver docs/DISENO_FASE3_ESCRITURA_RPC.md), va a ser una categoría nueva con su
propio checkbox, no algo cubierto por esta autorización.
================================================================================
"""

import streamlit as st

import db_pivot
import motor_escaneo
import motor_escaneo_activo
from auth import boton_logout, requerir_login

st.set_page_config(page_title="Escanear — Auditor IA", page_icon="🛡️", layout="wide")

st.markdown("## 🛡️ Escanear")
st.caption(
    "Fase 2 (pasivo): headers de seguridad, secretos expuestos en el bundle JS, "
    "y dependencias con vulnerabilidades conocidas -- no requiere permiso adicional. "
    "Fase 3 (activo): prueba acceso real a tus tablas/buckets sin autenticación -- "
    "requiere que autorices explícitamente cada proyecto."
)
st.divider()

usuario_id, email = requerir_login()
col_sesion, col_logout = st.columns([4, 1])
with col_sesion:
    st.caption(f"Sesión iniciada como **{email}**.")
with col_logout:
    boton_logout()
st.divider()

ICONO_ESTADO_ESCANEO = {
    "completado": "🟢",
    "en_progreso": "🟡",
    "pendiente": "⚪",
    "fallido": "🔴",
    "abortado": "🟠",
}
ICONO_SEVERIDAD = {
    "CRITICA": "🔴",
    "ALTA": "🟠",
    "MEDIA": "🟡",
    "BAJA": "🔵",
    "INFORMATIVA": "⚪",
}

proyectos = [p for p in db_pivot.listar_proyectos(usuario_id) if p["verification_status"] == "verificado"]

if not proyectos:
    st.info(
        "Todavía no tienes ningún dominio verificado. Ve a **Verificar Dominio** "
        "primero -- un escaneo solo puede correr sobre un dominio del que ya "
        "demostraste ser dueño."
    )
else:
    for p in proyectos:
        with st.expander(f"🟢 {p['dominio']}", expanded=True):
            escaneos = db_pivot.listar_escaneos(p["id"])

            # ------------------------------------------------------------------
            # Fase 2: escaneo pasivo -- sin consentimiento adicional
            # ------------------------------------------------------------------
            if st.button("🔍 Escanear (pasivo)", key=f"escanear_{p['id']}", type="primary"):
                with st.spinner(
                    "Renderizando el sitio, extrayendo el bundle JS, y corriendo los "
                    "3 checks pasivos... esto puede tardar 20-40 segundos."
                ):
                    try:
                        escaneo_id = motor_escaneo.ejecutar_escaneo(p["id"])
                        st.success(f"✅ Escaneo #{escaneo_id} completado.")
                        st.rerun()
                    except motor_escaneo.EscaneoError as e:
                        st.error(f"❌ {e}")

            st.divider()

            # ------------------------------------------------------------------
            # Fase 3 Parte A: escaneo activo de LECTURA -- consentimiento
            # explícito, separado, y por CATEGORÍA (ver db_pivot.py y
            # migrations/007) -- esta autorización cubre SOLO lo enumerado acá.
            # Si algún día se agrega Parte B (escritura de RLS, invocación de
            # RPC/Edge Functions -- ver docs/DISENO_FASE3_ESCRITURA_RPC.md),
            # va a ser una categoría NUEVA con su propio checkbox, nunca algo
            # que quede cubierto automáticamente por esto.
            # ------------------------------------------------------------------
            st.markdown("#### 🔓 Escaneo activo de lectura (Fase 3 Parte A)")

            tiene_consentimiento_lectura = db_pivot.tiene_consentimiento(
                p["id"], db_pivot.CATEGORIA_LECTURA_ACTIVA
            )

            if not tiene_consentimiento_lectura:
                st.warning(
                    "El escaneo activo va más allá de leer lo que tu sitio ya expone "
                    "públicamente: usa las mismas credenciales públicas que tu app ya "
                    "expone (la anon key de Supabase, o el config de Firebase) para "
                    "intentar leer datos reales, sin ninguna cuenta ni autenticación -- "
                    "exactamente lo que cualquier visitante sin cuenta podría hacer. "
                    "Esta autorización cubre específicamente estas 4 cosas, todas de "
                    "**solo lectura**, nunca escritura ni borrado:\n\n"
                    "1. **Tablas de Supabase**: probar si se puede leer/contar filas vía "
                    "RLS y la anon key, sin token de usuario.\n"
                    "2. **Storage buckets de Supabase**: listar qué buckets y qué "
                    "nombres de archivo son accesibles sin autenticación.\n"
                    "3. **Firebase**: lectura de Firestore, Realtime Database, y "
                    "listado de Firebase Storage sin autenticación.\n"
                    "4. **Detección de funciones RPC/Edge Functions**: solo se "
                    "detecta su nombre en el código -- nunca se invocan.\n\n"
                    "En ningún caso se guarda el contenido real de una fila, documento "
                    "o archivo -- solo conteos y nombres, como evidencia."
                )
                consiente = st.checkbox(
                    "Entiendo y autorizo las 4 pruebas de lectura sin autenticación "
                    "descritas arriba (tablas, buckets, Firebase, detección de RPC) "
                    "para este dominio.",
                    key=f"consentimiento_{p['id']}",
                )
                if st.button(
                    "Autorizar escaneo activo de lectura para este dominio",
                    key=f"autorizar_{p['id']}",
                    disabled=not consiente,
                ):
                    db_pivot.otorgar_consentimiento(p["id"], db_pivot.CATEGORIA_LECTURA_ACTIVA)
                    st.rerun()
            else:
                consentimientos = db_pivot.listar_consentimientos(p["id"])
                for c in consentimientos:
                    st.caption(f"✅ Categoría **{c['categoria']}** autorizada el {c['otorgado_en']}.")
                if st.button("🔓 Escanear ahora (activo)", key=f"escanear_activo_{p['id']}"):
                    with st.spinner(
                        "Probando acceso sin autenticación a tablas, buckets y reglas de "
                        "Firebase... con límites de velocidad y un circuit breaker que "
                        "detiene todo si tu sitio empieza a responder lento o con errores."
                    ):
                        try:
                            escaneo_id, abortado, razon = motor_escaneo_activo.ejecutar_escaneo_activo(p["id"])
                            if abortado:
                                st.warning(
                                    f"🟠 Escaneo #{escaneo_id} se detuvo solo (circuit breaker): {razon} "
                                    "Los hallazgos encontrados antes de detenerse sí se guardaron."
                                )
                            else:
                                st.success(f"✅ Escaneo activo #{escaneo_id} completado.")
                            st.rerun()
                        except motor_escaneo_activo.ConsentimientoRequeridoError as e:
                            st.error(f"❌ {e}")
                        except motor_escaneo.EscaneoError as e:
                            st.error(f"❌ {e}")

            if not escaneos:
                st.caption("Todavía no se ha corrido ningún escaneo sobre este dominio.")
                continue

            st.divider()
            st.markdown("**Escaneos anteriores:**")
            for e in escaneos:
                icono_estado = ICONO_ESTADO_ESCANEO.get(e["estado"], "⚪")

                with st.container(border=True):
                    st.markdown(f"{icono_estado} **Escaneo #{e['id']}** — {e['estado']} · {e['iniciado_en']}")

                    if e["estado"] not in ("completado", "abortado"):
                        continue

                    hallazgos = db_pivot.listar_hallazgos(e["id"])
                    if not hallazgos:
                        st.caption("Sin hallazgos.")
                        continue

                    for h in hallazgos:
                        icono = ICONO_SEVERIDAD.get(h["severidad"], "⚪")
                        with st.expander(f"{icono} [{h['severidad']}] {h['titulo']}"):
                            if h["descripcion"]:
                                st.markdown(f"**Descripción:** {h['descripcion']}")
                            if h["impacto_potencial"]:
                                st.markdown(f"**Impacto potencial:** {h['impacto_potencial']}")
                            if h["sugerencia_tecnica"]:
                                st.markdown(f"**Sugerencia técnica:** {h['sugerencia_tecnica']}")
                            if h["evidencia_metadata"]:
                                st.caption(f"Evidencia: `{h['evidencia_metadata']}`")
