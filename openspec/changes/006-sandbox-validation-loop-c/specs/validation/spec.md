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

### Scenario: aprobación revocada
- GIVEN una aprobación vigente y después un rechazo del mismo hallazgo
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
El sandbox DEBE respetar `sandbox.limits` de la política: tiempo por solicitud, tiempo por contenedor, tamaño de respuesta y cantidad de solicitudes por hallazgo y por engagement. Superar un límite NO DEBE producir un resultado positivo: una respuesta truncada DEBE quedar `not_validated` aunque el evaluador dé positivo sobre lo leído.

### Scenario: respuesta más grande que el límite
- GIVEN una respuesta mayor que `max_response_bytes` con el canario después del límite
- WHEN se evalúa
- THEN la evidencia queda `truncated: true` y el resultado no es `validated`

### Scenario: respuesta truncada con un evaluador de encabezados o cookies
- GIVEN una respuesta truncada con una cookie de sesión sin `Secure`, `HttpOnly` ni `SameSite`
- WHEN el loop C la evalúa con `POC-COOKIE-001`
- THEN el hallazgo queda `not_validated` y la evidencia de cada intento tiene `truncated: true` y resultado `not_validated`

### Scenario: contenedor que no termina
- GIVEN un envío que supera `container_timeout_s`
- WHEN vence el tiempo
- THEN el contenedor se destruye y el intento queda ABORTED con motivo `timeout`

### Scenario: presupuesto del engagement agotado
- GIVEN un engagement con `max_requests_per_engagement` envíos registrados en la bitácora
- WHEN el loop C procesa otro hallazgo aprobado
- THEN se detiene con `request_budget_exhausted` sin invocar el `Sender`

## ADDED Requirement: Loop C por hallazgo
El loop C DEBE procesar solo hallazgos `confirmed` o `inconclusive`, elegir la entrada del catálogo por CWE y `lab_targets`, tomar los parámetros del grafo de activos y detenerse según `decide_validation`. Un intento positivo DEBE detener el loop. Un bloqueo no fatal del Guard DEBE terminar como `not_validated` con su motivo, y todo error de un intento, también `adapter_error`, DEBE quedar en la bitácora como intento.

### Scenario: hallazgo descartado
- GIVEN un hallazgo `discarded` aprobado
- WHEN corre el loop C
- THEN no se invoca el `Sender`

### Scenario: verificación inexistente en el catálogo
- GIVEN un hallazgo aprobado cuyo CWE no tiene entrada en el catálogo
- WHEN corre el loop C
- THEN queda `not_validated` con motivo `no_catalog_entry` sin invocar el `Sender`

### Scenario: host parecido a un objetivo del laboratorio
- GIVEN un hallazgo aprobado sobre `dvwa.evil.example` o `d-v-w-a.lab.test`
- WHEN corre el loop C
- THEN queda `not_validated` con motivo `no_catalog_entry` sin lanzar ningún contenedor

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

### Scenario: bloqueo no fatal del Guard
- GIVEN un hallazgo, aprobado o no, cuyo host resuelve fuera del alcance
- WHEN corre el loop C
- THEN queda `not_validated` con motivo `dns_out_of_scope` (no `pending_hitl`), hay un registro BLOCKED con ese motivo y no se lanza ningún contenedor

### Scenario: error del adaptador después de enviar
- GIVEN un intento cuyo archivo de evidencia ya existe y no se puede escribir
- WHEN el adaptador falla después del envío
- THEN queda un `validation.attempt` ABORTED con motivo `adapter_error` y `subject` del hallazgo, y cuenta como intento también después de un reinicio

## ADDED Requirement: Aprobación atada a la solicitud revisada
Cada versión de lo que se enviaría por hallazgo (host, entrada del catálogo y parámetros) DEBE ser una revisión propia de la cola, con un hash corto de la solicitud. Una aprobación DEBE habilitar solo su revisión y su hash. El loop C DEBE enviar exactamente la revisión aprobada; si la elección cambia, NO DEBE enviar nada hasta una decisión nueva.

### Scenario: parámetros cambiados después de aprobar
- GIVEN un hallazgo aprobado y, después, una observación nueva del loop B que cambia el endpoint elegido
- WHEN corre el loop C
- THEN el resultado es PENDING_HITL, el `Sender` no se invoca y el hallazgo queda `pending` hasta una decisión nueva; con esa decisión se envía la solicitud nueva

### Scenario: se envía la solicitud aprobada
- GIVEN una aprobación de la revisión con `base_url` `http://dvwa.lab.test:8080` y ruta `/login.php`
- WHEN corre el loop C
- THEN el envío va al puerto 8080 con la ruta `/login.php`

### Scenario: aprobación con el hash de otra solicitud
- GIVEN una fila de aprobación con un hash distinto del de la revisión, aunque tenga su control en la bitácora
- WHEN corre el loop C
- THEN el resultado es PENDING_HITL y el `Sender` no se invoca

### Scenario: volver a una solicitud anterior
- GIVEN un hallazgo en cola con la solicitud A y después la solicitud B
- WHEN se vuelve a encolar A
- THEN se agrega como una revisión nueva, posterior a B (una aprobación vale para una sola revisión); encolar A otra vez no agrega nada

## ADDED Requirement: La bitácora define la decisión vigente
La decisión vigente de un hallazgo DEBE salir del control `hitl.*` más nuevo de la bitácora para ese `subject`, y DEBE corresponder a una única fila del registro de aprobaciones (la referencia incluye el número de fila). Una fila del registro sin su control, o una copia de una fila, NO DEBE habilitar tráfico.

### Scenario: aprobación insertada sin la CLI
- GIVEN una fila de aprobación escrita en el registro sin control en la bitácora
- WHEN corre el loop C
- THEN el resultado es PENDING_HITL y el `Sender` no se invoca

### Scenario: control de otro hallazgo
- GIVEN un hallazgo aprobado por la CLI y otro con una fila de aprobación sin control propio
- WHEN corre el loop C
- THEN solo se envía el primero

### Scenario: aprobación revocada y fila copiada
- GIVEN una aprobación, un rechazo posterior y una copia de la fila aprobada insertada al final del registro
- WHEN corre el loop C
- THEN queda `not_validated` con motivo `reviewer_rejected` y no se envía tráfico

## ADDED Requirement: Aprobación verificada antes de cada intento
Antes de cada intento, el loop C DEBE volver a verificar que la aprobación siga vigente, no revocada, en la bitácora y para el mismo hash.

### Scenario: aprobación que vence entre intentos
- GIVEN un hallazgo aprobado cuya aprobación vence durante el primer intento
- WHEN el loop C decide el segundo
- THEN no lo envía, el hallazgo queda `pending_hitl` con un intento y no se cierra

### Scenario: aprobación revocada entre intentos
- GIVEN un hallazgo aprobado que se rechaza durante el primer intento
- WHEN el loop C decide el segundo
- THEN no lo envía y el hallazgo queda `not_validated` con motivo `reviewer_rejected`

## ADDED Requirement: Evidencia de validación
Cada intento DEBE dejar un archivo de evidencia referenciado en la bitácora como `ruta#sha256=<hex>`, con la verificación, su versión, la versión del catálogo, los parámetros, el `sandbox_id` y el resultado. La evidencia NO DEBE contener valores de cookies ni de `Authorization`, ni el cuerpo completo de la respuesta, ni la query o el fragmento de `Location`.

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

### Scenario: Location con query o fragmento
- GIVEN una respuesta con `Location: http://dvwa.lab.test/login.php?token=s3cret#frag`
- WHEN se escribe la evidencia
- THEN guarda `http://dvwa.lab.test/login.php` y no contiene `s3cret`

## ADDED Requirement: CLI del Reviewer
La CLI DEBE listar los hallazgos en cola con el hash corto de su solicitud y registrar aprobaciones y rechazos con reviewer y motivo obligatorios, en el registro de aprobaciones y en la bitácora (con `subject` = `finding_id`). `approve` DEBE exigir `--request` con el hash que mostró `list`. Un `reject` sobre una aprobación vigente DEBE revocarla. La fila del registro y el control de la bitácora DEBEN escribirse juntos o ninguno. La CLI NO DEBE enviar tráfico.

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

### Scenario: aprobar con un hash distinto
- GIVEN un hallazgo en cola
- WHEN se ejecuta `approve` con un `--request` que no es el de la solicitud en cola
- THEN falla indicando que la solicitud no es la revisada y no escribe nada

### Scenario: la cola cambia entre `list` y `approve`
- GIVEN el hash que mostró `list` y, después, una revisión nueva de la solicitud
- WHEN se ejecuta `approve` con el hash mostrado
- THEN falla y no escribe nada

### Scenario: rechazo que revoca
- GIVEN una aprobación vigente
- WHEN se ejecuta `reject`
- THEN el estado pasa a `rejected` y la bitácora tiene `hitl.approve` y después `hitl.reject`

### Scenario: la bitácora falla
- GIVEN una bitácora que no acepta escrituras
- WHEN se ejecuta `approve`
- THEN la CLI sale con error indicando que la decisión NO quedó registrada, y no hay fila en el registro ni control en la bitácora
