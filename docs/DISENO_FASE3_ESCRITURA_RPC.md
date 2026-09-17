# Diseño (no implementado): prueba de escritura RLS + invocación de RPC/Edge Functions

Documento de diseño solicitado explícitamente antes de escribir cualquier código para
estas dos capacidades. **Nada de lo descrito acá está implementado.** Se revisa junto
al usuario antes de construir una sola línea.

Ambas comparten el mismo problema de fondo: a diferencia de los checks de lectura de
Fase 3 Parte A (un `HEAD`/conteo es intrínsecamente no-destructivo por naturaleza),
cualquier prueba de escritura o invocación, por definición, **hace algo real** del
lado del objetivo. El diseño tiene que asumir eso de frente, no esconderlo.

---

## A) Prueba de escritura de RLS (INSERT/UPDATE/DELETE sin autenticación)

### Mecanismo propuesto

1. **Solo INSERT de una fila nueva, nunca UPDATE de una fila existente.** Un test de
   UPDATE necesitaría localizar y modificar una fila real -- si algo falla a mitad de
   camino, se corrompe un dato ajeno de verdad. INSERT+DELETE de una fila **propia**
   es el único patrón que se considera: el peor caso posible es dejar una fila de
   prueba, nunca perder o alterar un dato real del cliente.
2. La fila se marca con un valor imposible de confundir con datos reales: un prefijo
   fijo + UUID v4 (ej. `__auditoria_ia_test_3f9a1c2e-...__`) en cada campo de texto
   disponible, dejando todo lo demás en NULL/default.
3. El INSERT se hace con `Prefer: return=representation` para recibir de vuelta el
   `id` real generado por Postgres -- necesario para el paso 4.
4. **Inmediatamente después**, en la misma ejecución (sin pausa, sin depender de un
   segundo request programado más tarde), DELETE de esa fila exacta por su `id`.
5. Se verifica que el DELETE de verdad la eliminó (un GET/HEAD de ese `id` específico
   debe devolver 0 filas).
6. **Si el DELETE falla por lo que sea** (la tabla podría tener una política de
   escritura distinta para INSERT que para DELETE): el hallazgo de "escritura sin
   auth posible" se reporta IGUAL -- ya se confirmó en el paso 3 -- pero con un
   aviso explícito y visible: *"Puede haber quedado un registro de prueba en la
   tabla `<tabla>` con el marcador `<uuid>` -- bórralo manualmente."* Nunca se oculta
   este caso ni se reintenta el DELETE de forma agresiva.
7. **Si el INSERT falla por validación de schema** (400/422 por una columna
   `NOT NULL` que no podemos adivinar, una foreign key, un constraint, etc.): esto
   NO se interpreta como "protegido" -- se reporta como **inconcluso**, no como
   hallazgo negativo. Solo un 401/403 explícito de autorización cuenta como
   "correctamente protegido". Confundir un fallo de schema con protección real
   sería un falso negativo que le da falsa confianza al dueño del proyecto.

### Consentimiento

Un tercer nivel, **separado y más explícito** que el de lectura de Fase 3 Parte A --
no se hereda. Lenguaje propuesto: *"Autorizo que se intente insertar y luego borrar
un registro de prueba (marcado como tal) en mis tablas, para confirmar si acepta
escrituras sin autenticación."*

Solo corre sobre tablas que **ya pasaron el check de lectura** (Fase 3 Parte A) --
no tiene sentido probar escritura en una tabla donde ni siquiera la lectura funcionó,
y minimiza cuántas tablas se tocan.

### Circuit breaker

Mismo mecanismo de `circuit_breaker.py`, pero **más estricto**: máximo un intento de
escritura por tabla, nunca un reintento si falla (a diferencia de lectura, donde un
fallo transitorio es más aceptable, un fallo de escritura a medias -- INSERT sin
DELETE confirmado -- ya deja el sistema en un estado que hay que resolver, no seguir
insistiendo sobre él).

### Pruebas que correrían antes de dar esto por bueno

1. Fixture propio con RLS de insert abierto: confirmar que INSERT+DELETE ocurre y
   la fila NO queda al final.
2. Simular un fallo del DELETE (ej. cortar el fixture entre el INSERT y el DELETE) y
   confirmar que el sistema avisa explícitamente al usuario con el `id`/marcador
   exacto de lo que pudo haber quedado.
3. Confirmar que el código es estructuralmente incapaz de emitir un UPDATE sobre un
   `id` que no fue el que el propio proceso generó en ese mismo request.
4. Prueba de concurrencia: dos escaneos de escritura sobre el mismo proyecto en
   paralelo (no debería poder pasar por diseño de UI, pero se prueba iguel) --
   confirmar que no hay condiciones de carrera.
5. Cada intento queda registrado de forma auditable (tabla, UUID, resultado del
   INSERT, resultado del DELETE) incluso si algo salió mal a mitad de camino.

---

## B) Invocación real de RPC / Edge Functions / Callable Functions

### Por qué es un problema fundamentalmente distinto

Leer una tabla tiene una semántica universal ("devuelve datos"). Una función
arbitraria puede hacer **literalmente cualquier cosa** -- calcular un precio, pero
también transferir dinero, enviar un email, borrar una cuenta. No existe una forma
genérica de "invocar con seguridad" algo cuyo comportamiento no conocemos de
antemano. El diseño tiene que ser mucho más conservador que el de escritura de RLS.

### Mecanismo propuesto

1. **Nunca invocar todas las funciones detectadas automáticamente con argumentos
   reales.** En cambio, invocar únicamente con argumentos vacíos o deliberadamente
   inválidos (`{}`, tipos incorrectos) -- el objetivo no es ejecutar la lógica de
   negocio, es observar solo el código de autorización:
   - **401/403** → protegida correctamente. Es la única señal que de verdad interesa.
   - **400/422** → la función SÍ aceptó la invocación (llegó a validar argumentos)
     sin rechazar por falta de autenticación -- ya es evidencia de "no protegida",
     sin necesidad de reintentar con argumentos válidos para "confirmar más".
   - **200/2xx** → la función se ejecutó. Es el escenario que más se quiere evitar
     activar sin querer.
2. Ante **cualquier** señal de que pudo haber un efecto real (2xx, o incluso un 500
   que podría llegar después de un efecto parcial), se detiene esa invocación y ese
   check completo de inmediato, marcado explícitamente como *"no se pudo determinar
   de forma segura -- posible efecto secundario real, revisar manualmente ya"* --
   nunca se asume "no pasó nada" solo porque no hubo un error visible.
3. Consentimiento de un nivel todavía más explícito que el de escritura de RLS,
   con lenguaje tipo: *"Entiendo que esto puede ejecutar código real de mi
   aplicación con efectos que no puedo predecir (envío de emails, cobros, cambios de
   datos), y asumo la responsabilidad de revisar el resultado manualmente."*

### Alternativa que recomendaría en la práctica, en vez de automatizar esto

En lugar de que el escáner invoque la función, **generar un reporte con
instrucciones para que el propio dueño la pruebe manualmente** (ej. "abre las
DevTools de tu navegador, ejecuta este `fetch(...)` exacto, revisa si el resultado
te pide iniciar sesión"). Deja la decisión y el riesgo en manos de quien realmente
puede evaluar el efecto real de su propia función -- nosotros no podemos.

### Pruebas que correrían antes de dar esto por bueno (si se construyera la versión automática)

1. Fixture propio con 3 funciones de prueba:
   a. Requiere auth → debe detectarse como protegida sin ejecutar nada.
   b. No requiere auth, cálculo puro sin efectos secundarios → debe reportarse como
      vulnerable, confirmando que efectivamente no causó daño.
   c. No requiere auth y tiene un efecto secundario deliberado y medible (ej.
      incrementa un contador) → confirmar que el patrón de "argumentos vacíos" no lo
      dispara, o que si lo dispara, el sistema lo detecta y avisa explícitamente.
2. Circuit breaker: confirmar que se detiene igual que los demás checks activos ante
   latencia/error anómalos.
3. Revisión manual (una persona, no solo pruebas automatizadas) contra 5-10 nombres
   de función reales de proyectos de prueba distintos, para calibrar qué tan bien
   distingue "protegida" de "no protegida" el patrón de argumentos vacíos, antes de
   confiar en él como señal única.

---

## Recomendación

El riesgo entre las dos partes es asimétrico: una tabla mal leída es baja severidad
comparado con una función que transfiere dinero ejecutada sin querer. Sugerencia:

1. Implementar primero la prueba de escritura de RLS (A) -- el mecanismo de
   INSERT+DELETE inmediato es contenible y verificable de forma determinística.
2. Para RPC/Edge Functions (B), considerar seriamente quedarse con la alternativa de
   "generar instrucciones para prueba manual" como primera versión del producto, y
   solo evaluar automatizarlo más adelante, con más historial e información real de
   cómo se comportan las funciones de los clientes en la práctica.
