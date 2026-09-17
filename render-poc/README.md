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

## Nota (Fase 2, actualizada): el Dockerfile real ya existe

El Dockerfile de producción real vive en la raíz del repo (`/Dockerfile`),
no acá -- ver ese archivo y `.github/workflows/docker-build.yml`. Este PoC
queda solo como referencia histórica. Dos cosas que se verificaron en vivo
durante Fase 2 y ya están reflejadas en el Dockerfile real:

1. `playwright install --with-deps chromium` (sin flags extra) ya descarga
   TANTO el Chrome completo COMO el "Chrome Headless Shell" -- el que usa
   Playwright por defecto en `launch()`. No hace falta un paso separado.
2. El downloader de Playwright puede fallar con timeout por una falla de
   red transitoria (visto varias veces en desarrollo local, nunca todavía
   dentro de un build de Render) -- vale la pena mantener el retry de 3
   intentos que ya tiene el Dockerfile real.

## ⚠️ Bug real y repetido de la API de Render: `dockerfilePath`/`dockerContext`

Encontrado DOS VECES en sesiones distintas (Fase 2 y Fase 3), con `rootDir`
distinto cada vez -- confirmado que es un problema real y consistente de la
API de Render (`POST /v1/services`), no un caso aislado. Documentado acá
para no perder tiempo re-descubriéndolo la próxima vez.

**El bug**: pasar `dockerfilePath` y `dockerContext` directamente dentro de
`serviceDetails` (nivel superior) **se ignora en silencio, sin error** --
Render no valida ni rechaza esos campos, simplemente no los usa. El
resultado: el build usa el default (`./Dockerfile` + contexto `.`, es decir,
**el Dockerfile de la raíz del repo**), sin ningún mensaje que indique que
tu configuración fue ignorada. Si el repo tiene un Dockerfile real en la
raíz (como este), el síntoma es MUY confuso: el deploy "funciona" pero
corre la app equivocada -- no un error obvio de build.

**La corrección**: esos dos campos van anidados un nivel más adentro, bajo
`serviceDetails.envSpecificDetails`:

```json
{
  "serviceDetails": {
    "env": "docker",
    "plan": "free",
    "envSpecificDetails": {
      "dockerfilePath": "ruta/relativa/al/repo/Dockerfile",
      "dockerContext": "ruta/relativa/al/repo"
    }
  }
}
```

Ambas rutas (`dockerfilePath` y `dockerContext`) son **relativas a la raíz
del repo**, no relativas a un `rootDir` que se haya configurado por
separado -- no hace falta (ni ayuda) pasar `rootDir` a la vez que se pasan
estos dos campos completos.

**Cómo confirmar que quedó bien configurado** antes de esperar a que termine
el build: `GET /v1/services/<id>` y revisar que
`serviceDetails.envSpecificDetails.dockerfilePath`/`dockerContext` reflejen
lo que se quería, no el default `./Dockerfile` / `.`.
