# PoC de hosting — Render + Playwright + Nuclei

Prueba de infraestructura, no de producto: confirma si Render puede correr
Chromium headless (Playwright) y un binario externo de escaneo (Nuclei)
dentro de un contenedor, con los permisos y recursos que eso requiere.
Nada de lo que hay acá es lógica de negocio del auditor — ver `test_app.py`.

## Qué hace

`GET /test` corre dos pruebas y devuelve el resultado en JSON:

1. Lanza Chromium headless, navega a `example.com`, lee el `<title>`.
2. Corre `nuclei -version` como subproceso.

Si ambas dan `"ok": true`, el hosting sostiene el tipo de carga que necesita
Fase 2 (ingesta de URL con navegador real + motor de escaneo externo).

## Cómo desplegarlo en Render (dashboard, sin CLI)

1. Entra a [render.com](https://render.com) con tu cuenta (o créala si no
   tienes una — eso es algo que tienes que hacer tú, no algo que un asistente
   deba hacer en tu nombre).
2. **New +** → **Web Service** → conecta este repositorio de GitHub.
3. Render debería detectar el `Dockerfile` automáticamente si le indicas
   que el **Root Directory** es `render-poc`. Si te pregunta:
   - **Environment**: Docker
   - **Root Directory**: `render-poc`
   - **Instance Type**: el más barato disponible (Starter, ~$7/mes en el
     momento de escribir esto — Render dejó de tener un tier 100% gratuito
     para Web Services hace tiempo; confirma el precio actual en su
     dashboard antes de confirmar el deploy, por si cambió).
4. Deploy. La primera build tarda varios minutos (descarga a Chromium +
   sus dependencias de sistema + el binario de Nuclei).
5. Una vez que el servicio esté "Live", visita
   `https://<tu-servicio>.onrender.com/test` y pega el JSON de vuelta.

## Qué borrar después

Este servicio es desechable. Una vez que confirmes el resultado, bórralo
desde el dashboard de Render (Settings → Delete Web Service) para no seguir
pagando por él — no tiene ninguna lógica que valga la pena dejar corriendo.
