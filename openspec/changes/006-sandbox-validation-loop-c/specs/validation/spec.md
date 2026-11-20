# Delta — validation (change 006)

Tests: tests/validation/test_sandbox.py, tests/validation/test_loop_c.py, tests/validation/test_review_cli.py, tests/validation/test_evidence.py

## MODIFIED Requirement: Gate humano por hallazgo
La validación DEBE requerir una aprobación vigente del Reviewer para **ese** hallazgo. Aprobar un hallazgo NO DEBE habilitar otro hallazgo del mismo host. Un hallazgo sin decisión NO DEBE aprobarse por defecto.

### Scenario: sin aprobación
- GIVEN un hallazgo sin aprobación del Reviewer
- WHEN se invoca la validación
- THEN el resultado es PENDING_HITL y el `Sender` no se invoca

### Scenario: aprobación de otro hallazgo del mismo host
- GIVEN dos hallazgos sobre `dvwa.lab.test` y solo el primero aprobado
- WHEN el loop C procesa el segundo
- THEN el resultado es PENDING_HITL y el `Sender` no se invoca

### Scenario: aprobación vencida
- GIVEN una aprobación con más de `approval_ttl_minutes`
- WHEN el loop C procesa el hallazgo
- THEN se trata como sin aprobación y no se envía tráfico

### Scenario: Reviewer que no responde
- GIVEN un hallazgo en cola sin decisión por más de `validation_timeout_minutes`
- WHEN el loop C lo procesa
- THEN queda `not_validated` con motivo `reviewer_timeout` y no se envía tráfico

### Scenario: hallazgo rechazado
- GIVEN un hallazgo rechazado por el Reviewer
- WHEN el loop C lo procesa
- THEN queda `not_validated` con motivo `reviewer_rejected` y no se envía tráfico

## MODIFIED Requirement: Sandbox efímero
Cada envío de validación DEBE ejecutarse en un contenedor propio, en la red interna del laboratorio, sin volúmenes, sin capacidades y con usuario sin privilegios. El contenedor DEBE destruirse al terminar, aunque la verificación falle. El sandbox NO DEBE alcanzar hosts fuera del laboratorio.

### Scenario: fin de la validación
- GIVEN una validación finalizada
- WHEN el sandbox termina
- THEN el contenedor no existe y solo queda la evidencia en la bitácora

### Scenario: falla la verificación
- GIVEN un contenedor que termina con error a mitad del envío
- WHEN el adaptador procesa el fallo
- THEN el contenedor se destruye y el intento queda ABORTED con motivo `sandbox_error`

### Scenario: opciones del contenedor
- GIVEN cualquier envío
- WHEN se arma el comando del sandbox
- THEN incluye `--rm`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, usuario sin privilegios y la red del laboratorio, y no incluye `--network host`, `bridge` ni volúmenes

### Scenario: red del laboratorio no interna
- GIVEN la red del laboratorio sin `Internal: true`
- WHEN se intenta un envío
- THEN no se lanza el contenedor y el resultado es `sandbox_error`

### Scenario: destino fuera del laboratorio
- GIVEN el sandbox real en la red del laboratorio
- WHEN intenta conectarse a `1.1.1.1:80` o a la red `tools`
- THEN la conexión falla

### Scenario: contenedor que no se puede destruir
- GIVEN un `docker rm -f` que falla
- WHEN termina el envío
- THEN se registra `sandbox.cleanup_failed` y el loop C se detiene para todo el engagement

### Scenario: huérfanos de una corrida anterior
- GIVEN un contenedor con la etiqueta del engagement que quedó vivo
- WHEN arranca el loop C
- THEN se destruye antes del primer envío

## ADDED Requirement: Límites del sandbox
El sandbox DEBE respetar `sandbox.limits` de la política: tiempo por solicitud, tiempo por contenedor, tamaño de respuesta y cantidad de solicitudes por hallazgo y por engagement. Superar un límite NO DEBE producir un resultado positivo.

### Scenario: respuesta más grande que el límite
- GIVEN una respuesta mayor que `max_response_bytes` con el canario después del límite
- WHEN se evalúa
- THEN la evidencia queda `truncated: true` y el resultado no es `validated`

### Scenario: contenedor que no termina
- GIVEN un envío que supera `container_timeout_s`
- WHEN vence el tiempo
- THEN el contenedor se destruye y el intento queda ABORTED con motivo `timeout`

### Scenario: presupuesto del engagement agotado
- GIVEN un engagement con `max_requests_per_engagement` envíos registrados en la bitácora
- WHEN el loop C procesa otro hallazgo aprobado
- THEN se detiene con `request_budget_exhausted` sin invocar el `Sender`

## ADDED Requirement: Loop C por hallazgo
El loop C DEBE procesar solo hallazgos `confirmed` o `inconclusive`, elegir la entrada del catálogo por CWE y `lab_targets`, tomar los parámetros del grafo de activos y detenerse según `decide_validation`. Un intento positivo DEBE detener el loop.

### Scenario: hallazgo descartado
- GIVEN un hallazgo `discarded` aprobado
- WHEN corre el loop C
- THEN no se invoca el `Sender`

### Scenario: verificación inexistente en el catálogo
- GIVEN un hallazgo aprobado cuyo CWE no tiene entrada en el catálogo
- WHEN corre el loop C
- THEN queda `not_validated` con motivo `no_catalog_entry` sin invocar el `Sender`

### Scenario: positivo en el primer intento
- GIVEN un hallazgo aprobado cuya verificación da positivo
- WHEN corre el loop C
- THEN queda `validated` tras un solo envío

### Scenario: dos intentos negativos
- GIVEN un hallazgo aprobado cuya verificación da negativo dos veces
- WHEN corre el loop C
- THEN queda `not_validated` tras dos envíos, cada uno con un canario distinto

### Scenario: engagement fuera de VALIDATE
- GIVEN un engagement en ANALYZE
- WHEN se corre el loop C
- THEN no se invoca nada y se registra el motivo

## ADDED Requirement: Evidencia de validación
Cada intento DEBE dejar un archivo de evidencia referenciado en la bitácora como `ruta#sha256=<hex>`, con la verificación, su versión, la versión del catálogo, los parámetros, el `sandbox_id` y el resultado. La evidencia NO DEBE contener valores de cookies ni de `Authorization`, ni el cuerpo completo de la respuesta.

### Scenario: cookie en la respuesta
- GIVEN una respuesta con `Set-Cookie: PHPSESSID=abc123; HttpOnly`
- WHEN se escribe la evidencia
- THEN contiene el nombre y los atributos de la cookie y no contiene `abc123`

### Scenario: cuerpo grande
- GIVEN una respuesta de 60 KB
- WHEN se escribe la evidencia
- THEN contiene el SHA-256 del cuerpo y un extracto de a lo sumo 512 bytes

### Scenario: evidencia alterada
- GIVEN un archivo de evidencia modificado después de registrarse
- WHEN se verifica contra la bitácora
- THEN el SHA-256 no coincide

## ADDED Requirement: CLI del Reviewer
La CLI DEBE listar los hallazgos en cola y registrar aprobaciones y rechazos con reviewer y motivo obligatorios, en el registro de aprobaciones y en la bitácora. La CLI NO DEBE enviar tráfico.

### Scenario: aprobar sin motivo
- GIVEN un hallazgo en cola
- WHEN se ejecuta `approve` con motivo vacío
- THEN falla y no escribe nada

### Scenario: aprobar un hallazgo que no está en cola
- GIVEN un `finding_id` inexistente
- WHEN se ejecuta `approve`
- THEN falla y no escribe nada

### Scenario: decisión registrada
- GIVEN un hallazgo en cola
- WHEN se ejecuta `reject` con reviewer y motivo
- THEN el registro de aprobaciones y la bitácora tienen la decisión, y el registro rechaza UPDATE y DELETE
