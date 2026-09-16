"""
================================================================================
 ESCANEAR (Fase 2 del pivote)
================================================================================
Solo lista proyectos YA VERIFICADOS (ver 1_Verificar_Dominio.py) -- disparar
un escaneo sobre un proyecto no verificado está bloqueado en dos capas
(motor_escaneo.py -> db_pivot.crear_escaneo -> trigger de base de datos),
así que ni siquiera se ofrece el botón acá para no invitar al intento.

Solo corre los 3 checks pasivos de Fase 2 (headers, secretos en el bundle,
dependencias vulnerables) -- ver motor_escaneo.py. RLS e IDOR quedan para
Fase 3.
================================================================================
"""

import streamlit as st

import db_pivot
import motor_escaneo
from auth import boton_logout, requerir_login

st.set_page_config(page_title="Escanear — Auditor IA", page_icon="🛡️", layout="wide")

st.markdown("## 🛡️ Escanear")
st.caption(
    "Fase 2 del pivote: headers de seguridad, secretos expuestos en el bundle "
    "JS, y dependencias con vulnerabilidades conocidas. Solo sobre dominios "
    "ya verificados."
)
st.divider()

usuario_id, email = requerir_login()
col_sesion, col_logout = st.columns([4, 1])
with col_sesion:
    st.caption(f"Sesión iniciada como **{email}**.")
with col_logout:
    boton_logout()
st.divider()

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

            if st.button("🔍 Escanear ahora", key=f"escanear_{p['id']}", type="primary"):
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

            if not escaneos:
                st.caption("Todavía no se ha corrido ningún escaneo sobre este dominio.")
                continue

            st.markdown("**Escaneos anteriores:**")
            for e in escaneos:
                icono_estado = {
                    "completado": "🟢",
                    "en_progreso": "🟡",
                    "pendiente": "⚪",
                    "fallido": "🔴",
                }.get(e["estado"], "⚪")

                with st.container(border=True):
                    st.markdown(f"{icono_estado} **Escaneo #{e['id']}** — {e['estado']} · {e['iniciado_en']}")

                    if e["estado"] != "completado":
                        continue

                    hallazgos = db_pivot.listar_hallazgos(e["id"])
                    if not hallazgos:
                        st.caption("Sin hallazgos -- el sitio pasó los 3 checks pasivos limpio.")
                        continue

                    icono_severidad = {
                        "CRITICA": "🔴",
                        "ALTA": "🟠",
                        "MEDIA": "🟡",
                        "BAJA": "🔵",
                        "INFORMATIVA": "⚪",
                    }
                    for h in hallazgos:
                        icono = icono_severidad.get(h["severidad"], "⚪")
                        with st.expander(f"{icono} [{h['severidad']}] {h['titulo']}"):
                            if h["descripcion"]:
                                st.markdown(f"**Descripción:** {h['descripcion']}")
                            if h["impacto_potencial"]:
                                st.markdown(f"**Impacto potencial:** {h['impacto_potencial']}")
                            if h["sugerencia_tecnica"]:
                                st.markdown(f"**Sugerencia técnica:** {h['sugerencia_tecnica']}")
                            if h["evidencia_metadata"]:
                                st.caption(f"Evidencia: `{h['evidencia_metadata']}`")
