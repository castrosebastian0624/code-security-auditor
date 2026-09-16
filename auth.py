"""
================================================================================
 AUTENTICACIÓN — Clerk como proveedor OIDC, vía st.login() nativo de Streamlit
================================================================================
Reemplaza la identificación por email sin verificación de la Fase 1 original.

Antes de construir nada a mano se evaluaron dos alternativas:

- rootelement/python-clerk-auth: implementación manual de OIDC contra Clerk.
  0 estrellas, 1 fork, 3 commits, un solo autor, sin tests, el propio README
  dice "provided as-is for educational and development purposes" -- es
  exactamente el ejemplo de un solo archivo que se quería evitar. Descartada.
- streamlit-oauth (dnplus, 214 estrellas, mantenida, con tests y CI): sí es
  una librería seria, pero solo maneja el intercambio del código OAuth --
  devuelve el token crudo sin validar firma/iss/aud/exp, y no resuelve la
  persistencia de sesión entre reruns de Streamlit. Usarla igual habría
  significado construir a mano la validación del ID token y el manejo de
  sesión -- las dos partes más sensibles en seguridad de todo el flujo.

En vez de cualquiera de las dos: st.login()/st.logout()/st.user, nativos de
Streamlit desde la versión 1.42 (sobre Authlib). Cubren exactamente lo que
streamlit-oauth no cubre:
  - Validación completa del ID token (firma contra el JWKS del proveedor,
    iss, aud, exp) -- la hace Authlib, no este código.
  - Persistencia de sesión entre reruns vía cookie firmada
    (`cookie_secret` en secrets.toml) -- tampoco la maneja este código.

Lo único que SÍ construimos a mano en este archivo es el mapeo de la
identidad de Clerk (el claim `sub` del ID token) a una fila de nuestra tabla
`usuarios` -- ninguna librería puede resolver eso porque es específico de
nuestro esquema.

Requiere un bloque [auth] en `.streamlit/secrets.toml` (no se comitea -- ver
`.streamlit/secrets.toml.example` para el detalle de cada clave y dónde
conseguirla en el dashboard de Clerk: Config > OAuth applications).
================================================================================
"""

import streamlit as st

import db_pivot


def requerir_login() -> tuple[int, str]:
    """
    Exige una sesión válida de Clerk. Si no hay sesión, muestra un botón de
    login y detiene la ejecución de la página (st.stop()) -- todo el código
    que llama a esta función después de su retorno solo corre para un
    usuario ya autenticado.

    Devuelve (usuario_id, email) de la fila en nuestra tabla `usuarios`,
    creándola si es el primer login de ese usuario de Clerk.
    """
    if not st.user.is_logged_in:
        st.info("Inicia sesión con tu cuenta para continuar.")
        st.button("🔐 Iniciar sesión", on_click=st.login, type="primary")
        st.stop()

    usuario_id = db_pivot.obtener_o_crear_usuario_clerk(
        clerk_user_id=st.user.sub,
        email=st.user.email,
        nombre=st.user.get("name"),
    )
    return usuario_id, st.user.email


def boton_logout() -> None:
    st.button("Cerrar sesión", on_click=st.logout)
