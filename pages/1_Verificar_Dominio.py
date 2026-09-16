"""
================================================================================
 VERIFICAR PROPIEDAD DE DOMINIO (Fase 1 del pivote)
================================================================================
Página nueva y separada de app.py a propósito: el flujo v1 (subir código)
sigue funcionando exactamente igual en app.py, sin tocarlo. Esta página es la
fundación del flujo v2 (escaneo por URL) — registra un proyecto y verifica
que quien lo pide controla el dominio, ANTES de que exista ningún check de
escaneo real (eso es Fase 2).

La identidad del usuario viene de Clerk (OIDC vía st.login() nativo de
Streamlit — ver auth.py), no de un email sin verificar. Ver auth.py para el
detalle de por qué se eligió esa opción sobre librerías de terceros.
================================================================================
"""

import psycopg2
import streamlit as st

import db_pivot
from auth import boton_logout, requerir_login
from verificacion_dominio import (
    DominioInvalidoError,
    generar_token,
    normalizar_dominio,
    verificar,
)

st.set_page_config(page_title="Verificar Dominio — Auditor IA", page_icon="🔗", layout="wide")

st.markdown("## 🔗 Verificar propiedad de dominio")
st.caption(
    "Fundación del escaneo por URL (Fase 1 del pivote). Ningún escaneo real "
    "corre todavía — esto solo registra tu dominio y confirma que lo "
    "controlas, para que en la fase siguiente el sistema pueda escanearlo."
)
st.divider()

# ==============================================================================
# 1. Login (Clerk)
# ==============================================================================
usuario_id, email = requerir_login()

col_sesion, col_logout = st.columns([4, 1])
with col_sesion:
    st.caption(f"Sesión iniciada como **{email}**.")
with col_logout:
    boton_logout()

st.divider()

# ==============================================================================
# 2. Registrar un dominio nuevo
# ==============================================================================
st.markdown("### 2. Registrar un dominio nuevo")

col_dominio, col_metodo = st.columns([2, 1])
with col_dominio:
    dominio_input = st.text_input(
        "Dominio a verificar",
        placeholder="miapp.com",
        help="El dominio o subdominio donde está desplegada tu app en producción.",
    )
with col_metodo:
    metodo_label = st.radio(
        "Método de verificación",
        ["Registro DNS (TXT)", "Archivo en el sitio"],
        help=(
            "DNS: si tienes un dominio propio y acceso a su configuración DNS. "
            "Archivo: si todavía usas el subdominio que te dio tu builder "
            "(ej. *.lovable.app) y no controlas su DNS, pero sí puedes agregar "
            "un archivo estático."
        ),
    )
metodo = "dns_txt" if metodo_label.startswith("Registro DNS") else "http_file"

if st.button("Generar instrucciones de verificación", type="primary"):
    try:
        dominio_normalizado = normalizar_dominio(dominio_input)
        token = generar_token()
        proyecto_id = db_pivot.crear_proyecto(usuario_id, dominio_normalizado, metodo, token)
        st.session_state["ultimo_proyecto_id"] = proyecto_id
        st.success(f"✅ Proyecto creado para **{dominio_normalizado}**. Sigue las instrucciones abajo.")
    except DominioInvalidoError as e:
        st.error(f"⚠️ {e}")
    except psycopg2.errors.UniqueViolation:
        st.error(
            "⚠️ Ya existe un intento de verificación reciente para ese dominio. "
            "Si es tuyo, revisa la lista de proyectos más abajo."
        )
    except Exception as e:
        st.error(f"❌ No se pudo crear el proyecto: {e}")

st.divider()

# ==============================================================================
# 3. Mis proyectos: instrucciones, verificación, estado
# ==============================================================================
st.markdown("### 3. Mis proyectos")
proyectos = db_pivot.listar_proyectos(usuario_id)

if not proyectos:
    st.info("Todavía no has registrado ningún dominio.")
else:
    for p in proyectos:
        estado = p["verification_status"]
        icono = {"verificado": "🟢", "pendiente": "🟡", "fallido": "🔴"}.get(estado, "⚪")

        with st.expander(f"{icono} {p['dominio']} — {estado}", expanded=(estado == "pendiente")):
            st.caption(f"Método: {p['verification_method']} · Registrado: {p['creado_en']}")

            if estado == "verificado":
                st.success(f"Verificado el {p['verified_at']}. Listo para escanear (Fase 2, aún no disponible).")
                continue

            proyecto_completo = db_pivot.obtener_proyecto(p["id"])
            token = proyecto_completo["verification_token"]
            token_vencido = proyecto_completo["token_vencido"]

            if token_vencido:
                st.error(
                    f"⏰ Este token venció el {proyecto_completo['verification_token_expires_at']} "
                    "(los tokens duran 48h). Genera uno nuevo para poder verificar — "
                    "el que tenías ya no sirve, aunque lo hayas publicado."
                )
                if st.button("🔄 Generar nuevo token", key=f"regenerar_{p['id']}"):
                    db_pivot.regenerar_token(p["id"])
                    st.rerun()
                continue

            st.caption(f"Este token vence el {proyecto_completo['verification_token_expires_at']}.")

            if p["verification_method"] == "dns_txt":
                st.markdown("**Agrega este registro TXT en tu proveedor de DNS:**")
                st.code(
                    f"Nombre/Host: _auditoria-verificacion.{p['dominio']}\n"
                    f"Tipo:        TXT\n"
                    f"Valor:       {token}",
                    language="text",
                )
                st.caption(
                    "Los cambios de DNS pueden tardar unos minutos en propagarse. "
                    "Si la verificación falla, espera un poco e intenta de nuevo."
                )
            else:
                st.markdown("**Publica un archivo en esta ruta exacta de tu sitio:**")
                st.code(f"https://{p['dominio']}/.well-known/auditoria-verificacion.txt", language="text")
                st.markdown("**Contenido exacto del archivo (sin nada más):**")
                st.code(token, language="text")
                st.caption(
                    "Si usas un builder como Lovable o Bolt.new, pídele a la IA que "
                    "agregue un archivo estático en esa ruta con ese contenido exacto."
                )

            col_verificar, col_cancelar = st.columns([1, 1])
            with col_verificar:
                if st.button("🔍 Verificar ahora", key=f"verificar_{p['id']}"):
                    with st.spinner("Comprobando..."):
                        ok, detalle = verificar(p["dominio"], p["verification_method"], token)
                    if ok:
                        try:
                            db_pivot.marcar_proyecto_verificado(p["id"])
                            st.success(f"✅ {detalle} Dominio verificado.")
                            st.rerun()
                        except psycopg2.errors.UniqueViolation:
                            st.error(
                                "⚠️ Este dominio ya fue verificado por otra cuenta antes que tú. "
                                "Si crees que es un error, contacta a soporte."
                            )
                    else:
                        st.warning(f"⏳ Todavía no verificado: {detalle}")

            with col_cancelar:
                if st.button("Cancelar este intento", key=f"cancelar_{p['id']}"):
                    db_pivot.marcar_proyecto_fallido(p["id"])
                    st.rerun()
