# Spec — tool-adapters

Tests: `tests/test_adapters.py`, `tests/test_audit_and_policy.py`, `tests/tool_adapters/test_subfinder.py`, `tests/tool_adapters/test_httpx.py`, `tests/tool_adapters/test_tool_errors.py`, `tests/tool_adapters/test_nmap_output.py`, `tests/tool_adapters/test_nuclei.py`, `tests/tool_adapters/test_zap.py`, `tests/tool_adapters/test_template_allowlist.py`, `tests/tool_adapters/test_feed_adapters.py`
Configuración: `harness/profiles.yaml`, `harness/tools.yaml`, `harness/policy.yaml`

## Requirement: Declaración de capability
Todo adaptador DEBE declarar nombre, fases permitidas y si es destructivo; el harness NO DEBE ejecutar capabilities sin adaptador registrado.

### Scenario: capability sin adaptador
- GIVEN una capability habilitada en la fase pero sin adaptador
- WHEN se invoca
- THEN la acción es bloqueada y registrada

### Scenario: adaptador fuera de su fase
- GIVEN un adaptador declarado solo para ANALYZE
- WHEN se invoca con un token de RECON
- THEN la acción es bloqueada

## Requirement: Ejecución sin shell
Los adaptadores DEBEN construir argv fijo y ejecutar sin shell, con timeout; NO DEBEN interpolar entrada sin validar.

### Scenario: target con metacaracteres
- GIVEN un target como `; rm -rf /` o `10.0.0.5 -A`
- WHEN el adaptador valida el target
- THEN lo rechaza antes de construir el comando

## Requirement: Argumentos prohibidos
El perfil de cada herramienta DEBE listar argumentos prohibidos y el adaptador DEBE rechazarlos.

### Scenario: nmap con scripts
- GIVEN un perfil de nmap que agrega `--script=vuln`
- WHEN se construye el comando
- THEN se rechaza por argumento prohibido

## Requirement: Nuclei acotado
El adaptador de Nuclei DEBE usar solo el directorio de templates curado, excluir etiquetas intrusivas y desactivar OAST.

### Scenario: perfil de Nuclei
- GIVEN el perfil vigente
- WHEN se construye el comando
- THEN incluye el directorio curado, excluye `intrusive`, `dos`, `fuzz`, `bruteforce` y desactiva OAST

## Requirement: Coherencia de configuración
Toda capability habilitada en `policy.yaml` DEBE existir en `tools.yaml` y viceversa.

### Scenario: capability huérfana
- GIVEN una capability presente en un solo archivo
- WHEN corre la verificación de coherencia
- THEN el test falla

<!-- Archivado desde el change 008-spec-hardening -->

## Requirement: Red del laboratorio coherente con la política
La subred de `lab/docker-compose.yml` DEBE estar fijada y contenida en `targets.lab_only_cidrs` de `harness/profiles.yaml`, y la red DEBE ser `internal: true`.

### Scenario: subred no fijada o distinta
- GIVEN un `docker-compose.yml` sin subred, o con una subred fuera de `lab_only_cidrs`
- WHEN corre el test de coherencia
- THEN el test falla indicando la diferencia

### Scenario: red con salida a internet
- GIVEN la red del laboratorio sin `internal: true`
- WHEN corre el test de coherencia
- THEN el test falla

<!-- Archivado desde el change 004-recon-loop-a -->

## Requirement: subfinder pasivo y acotado
`subfinder.enum` DEBE aceptar solo un dominio (nunca una IP ni un CIDR), DEBE correr con los argumentos fijos del perfil y DEBE rechazar los argumentos que amplían las fuentes o lo vuelven activo.

### Scenario: perfil de subfinder
- GIVEN el perfil vigente
- WHEN se construye el comando para `dvwa.lab.test`
- THEN lleva `-d dvwa.lab.test`, salida JSON y sin color, y no lleva `-all`, `-recursive`, `-active` ni `-ip`

### Scenario: subfinder sobre una IP
- GIVEN el objetivo 10.99.0.3
- WHEN se construye el comando de subfinder
- THEN se rechaza como objetivo inválido

## Requirement: httpx sin redirecciones y con IP fijada
`httpx.probe` DEBE sondear la IP validada con el nombre en el encabezado `Host`, NO DEBE seguir redirecciones y DEBE llevar el rate limit de `policy.yaml`.

### Scenario: perfil de httpx
- GIVEN el objetivo `dvwa.lab.test` con `addresses = ("10.99.0.3",)`
- WHEN se construye el comando
- THEN sondea `10.99.0.3` con `Host: dvwa.lab.test`, lleva `-rl 5` y no lleva `-fr`, `-follow-redirects` ni `-fhr`

### Scenario: redirección a otro host (A5)
- GIVEN una respuesta 302 con `Location: http://203.0.113.7/`
- WHEN se procesa la salida de httpx
- THEN `203.0.113.7` entra como descubrimiento, pasa por el filtro de alcance y nunca se sondea

## Requirement: Salida de herramienta validada por schema
Cada adaptador DEBE validar cada registro de salida contra su schema. Los registros inválidos DEBEN descartarse y contarse. Si hay al menos uno válido, el resultado DEBE ser `partial` o `ok`. Si ninguno es válido y la salida no estaba vacía, DEBE ser `invalid_output`.

### Scenario: salida parcialmente inválida
- GIVEN una salida de httpx con 3 líneas válidas y 1 que no es JSON
- WHEN se parsea
- THEN se usan las 3 válidas, `invalid_lines = 1` y el estado es `partial`

### Scenario: salida totalmente inválida
- GIVEN una salida de subfinder sin ninguna línea válida
- WHEN se parsea
- THEN el estado es `invalid_output` y no entra ningún activo al grafo

### Scenario: nombre malicioso en la salida
- GIVEN una línea de subfinder con `host: "-oN /tmp/x"` o con caracteres de control
- WHEN se parsea
- THEN se descarta porque no normaliza como objetivo

## Requirement: Errores de herramienta sin excepción
Ante timeout, binario ausente, binario que no se puede ejecutar o código de salida distinto de 0, el adaptador DEBE devolver un resultado de error tipado (`timeout`, `binary_missing`, `exec_error`, `exit_code`) en lugar de lanzar. Una salida con bytes que no son UTF-8 NO DEBE romper la ejecución.

### Scenario: binario ausente
- GIVEN un runner que no encuentra el binario de httpx
- WHEN se invoca `httpx.probe`
- THEN el resultado es `{"status": "error", "error": "binary_missing"}`

### Scenario: timeout
- GIVEN una herramienta que excede `timeout_s`
- WHEN se invoca
- THEN el resultado es `{"status": "error", "error": "timeout"}`

## Requirement: Sin proxy hacia el laboratorio
El entorno con el que corren las herramientas NO DEBE incluir variables de proxy (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` y sus minúsculas).

### Scenario: proxy en el entorno del harness
- GIVEN un harness corriendo con `HTTPS_PROXY` definido
- WHEN se arma el entorno de una herramienta
- THEN la variable no está

## Requirement: Un flag prohibido se detecta en cualquier forma
nmap y las herramientas escritas en Go aceptan un flag con uno o dos guiones y con la forma `flag=valor`. El control de argumentos prohibidos DEBE reconocer todas esas formas.

### Scenario: el mismo flag escrito distinto
- GIVEN `--script` prohibido en el perfil de nmap
- WHEN el comando lleva `-script`, `--script=vuln` o `-script=vuln`
- THEN se rechaza

### Scenario: perfiles de httpx y subfinder
- GIVEN los perfiles vigentes
- WHEN se agrega `-csp-probe`, `-tls-probe`, `-ss`, `-p` u `-o` a httpx, o `-o`, `-oD`, `-r` o `-rL` a subfinder
- THEN se rechaza

## Requirement: La salida solo describe lo que se escaneó
`nmap.service_scan` DEBE descartar los hosts de la salida que no sean una de las IP escaneadas, y `httpx.probe` los que no sean una de las IP sondeadas. Una respuesta hostil NO DEBE poder inflar el grafo: la lista de tecnologías de un servicio DEBE acotarse.

### Scenario: nmap reporta otra IP
- GIVEN una salida de nmap con un host 10.99.0.3 y un escaneo sobre 10.99.0.200
- WHEN se parsea
- THEN no entra ningún servicio y el estado es `invalid_output`

### Scenario: lista de tecnologías enorme
- GIVEN una línea de httpx con 500 tecnologías
- WHEN se parsea
- THEN el servicio queda con 20

<!-- Archivado desde el change 005-correlation-analysis-loop-b -->

## Requirement: nuclei con host, IP fijada y sin redirecciones
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

## Requirement: Solo templates registrados e intactos
El adaptador DEBE pasar a nuclei solo los templates del manifiesto cuyo SHA-256 coincide, uno por uno. Un template de la carpeta que no está en el manifiesto, o cuyo hash no coincide, NO DEBE ejecutarse. Cada template registrado DEBE usar solo protocolo `http`, métodos GET o HEAD y redirecciones apagadas, sin `payloads`, `fuzzing`, `code`, `headless`, `dns` ni OAST, sin tags de `exclude_tags` (escritas como texto o como lista) y sin un encabezado `Host` propio.

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

### Scenario: template que fija su propio Host
- GIVEN un template con `headers: {Host: 203.0.113.7}`
- WHEN corre el control estático
- THEN no pasa y no se ejecuta

## Requirement: ZAP por API, en modo protegido y sin escaneo activo
`zap.baseline_scan` DEBE hablar con el servicio ZAP del laboratorio usando solo un conjunto fijo de endpoints, que NO DEBE incluir ningún endpoint de escaneo activo. Por cada invocación DEBE:
- usar el modo `protect`;
- limitar el contexto a `http://<ip>(:<puerto>)?/`;
- fijar `Host: <nombre>`;
- aplicar el rate limit de `policy.yaml`;
- limitar el spider en hilos, profundidad y duración;
- NO enviar formularios (`processForm` y `postForm` apagados antes de arrancar el spider);
- empezar y terminar con una sesión nueva de ZAP, para no atribuir alertas de otra corrida y no retener datos del objetivo.

La clave de la API DEBE leerse del entorno, NO DEBE tener valor por defecto y DEBE viajar en el encabezado `X-ZAP-API-Key`, nunca en la URL.

### Scenario: spider sin formularios
- GIVEN una invocación de `zap.baseline_scan`
- WHEN se arma la secuencia de llamadas
- THEN `setOptionProcessForm` y `setOptionPostForm` con `false` van antes de `spider/action/scan`, y en el laboratorio el objetivo recibe solo GET de ZAP

### Scenario: alertas de una corrida anterior
- GIVEN un ZAP que ya analizó la misma IP para otro engagement
- WHEN se invoca `zap.baseline_scan`
- THEN la primera llamada abre una sesión nueva y la última la vuelve a abrir

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

## Requirement: Capabilities de datos sin red
`cve.lookup`, `epss.lookup` y `cwe.map` DEBEN leer solo los snapshots locales y el grafo, y NO DEBEN abrir conexiones de red.

### Scenario: consulta con la red bloqueada
- GIVEN un test que hace fallar cualquier apertura de socket
- WHEN se invocan las tres capabilities de datos
- THEN devuelven su resultado sin error
