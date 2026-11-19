# Delta — tool-adapters (change 005)

Tests: tests/tool_adapters/test_nuclei.py, tests/tool_adapters/test_zap.py, tests/tool_adapters/test_template_allowlist.py, tests/tool_adapters/test_feed_adapters.py

## ADDED Requirement: nuclei con host, IP fijada y sin redirecciones
`nuclei.safe_templates` DEBE recibir un host canónico (nunca una URL armada por el agente), DEBE sondear `http://<ip>:<puerto>` con `Host: <nombre>` usando las IP que validó el Harness y el puerto de los `http_service` del grafo, DEBE llevar `-dr`, `-pt http`, `-nh`, `-ni` y el rate limit de `policy.yaml`, y DEBE rechazar los flags prohibidos del perfil.

### Scenario: perfil de nuclei
- GIVEN el objetivo `dvwa.lab.test` con `addresses = ("10.99.0.2",)` y un servicio en el puerto 80
- WHEN se construye el comando
- THEN lleva `-u http://10.99.0.2:80`, `-H "Host: dvwa.lab.test"`, `-dr`, `-ni`, `-rl 5` y no lleva `-fr`, `-code`, `-headless` ni `-dast`

### Scenario: URL como objetivo (red team 4.1)
- GIVEN el objetivo `http://dvwa.lab.test/../`
- WHEN se invoca `nuclei.safe_templates`
- THEN se rechaza como objetivo inválido

### Scenario: resultado de otra IP
- GIVEN una línea de salida con `ip` 203.0.113.7
- WHEN se parsea
- THEN se descarta y cuenta como inválida

## ADDED Requirement: Solo templates registrados e intactos
El adaptador DEBE pasar a nuclei solo los templates del manifiesto cuyo SHA-256 coincide, uno por uno. Un template de la carpeta que no está en el manifiesto, o cuyo hash no coincide, NO DEBE ejecutarse. Cada template registrado DEBE usar solo protocolo `http`, métodos GET o HEAD y redirecciones apagadas, sin `payloads`, `fuzzing`, `code`, `headless`, `dns` ni OAST, y sin tags de `exclude_tags`.

### Scenario: template sin registrar
- GIVEN un archivo nuevo en `templates/allowlist/` que no está en `MANIFEST.md`
- WHEN se construye el comando de nuclei
- THEN ese archivo no aparece en el comando y el test de la allow-list falla

### Scenario: template modificado
- GIVEN un template registrado cuyo contenido cambió después de registrarlo
- WHEN se invoca `nuclei.safe_templates`
- THEN ese template no se ejecuta

### Scenario: template con POST
- GIVEN un template con `method: POST`
- WHEN corre el test de la allow-list
- THEN falla

## ADDED Requirement: ZAP por API, en modo protegido y sin escaneo activo
`zap.baseline_scan` DEBE hablar con el servicio ZAP del laboratorio usando solo un conjunto fijo de endpoints, que NO DEBE incluir ningún endpoint de escaneo activo. Por cada invocación DEBE:
- usar el modo `protect`;
- limitar el contexto a `http://<ip>(:<puerto>)?/`;
- fijar `Host: <nombre>`;
- aplicar el rate limit de `policy.yaml`;
- limitar el spider en hilos, profundidad y duración.

La clave de la API DEBE leerse del entorno y NO DEBE tener valor por defecto.

### Scenario: endpoints permitidos
- GIVEN el conjunto de endpoints del adaptador
- WHEN corre el test
- THEN ninguno contiene `/ascan/`

### Scenario: enlace a otro host
- GIVEN una página del objetivo con un enlace a `http://203.0.113.7/`
- WHEN corre el spider
- THEN ese enlace queda fuera de alcance y no se visita

### Scenario: alerta de otra URL
- GIVEN una alerta de ZAP cuya `url` no es de la IP y el puerto analizados
- WHEN se parsea
- THEN se descarta y cuenta como inválida

### Scenario: sin clave de API
- GIVEN `PTAAS_ZAP_API_KEY` sin definir
- WHEN se invoca `zap.baseline_scan`
- THEN devuelve un error tipado y no se manda nada

## ADDED Requirement: Capabilities de datos sin red
`cve.lookup`, `epss.lookup` y `cwe.map` DEBEN leer solo los snapshots locales y el grafo, y NO DEBEN abrir conexiones de red.

### Scenario: consulta con la red bloqueada
- GIVEN un test que hace fallar cualquier apertura de socket
- WHEN se invocan las tres capabilities de datos
- THEN devuelven su resultado sin error
