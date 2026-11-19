# Delta — tool-adapters (change 004)

Tests: tests/tool_adapters/test_subfinder.py, tests/tool_adapters/test_httpx.py,
tests/tool_adapters/test_tool_errors.py, tests/tool_adapters/test_nmap_output.py

## ADDED Requirement: subfinder pasivo y acotado
`subfinder.enum` DEBE aceptar solo un dominio (nunca una IP ni un CIDR), DEBE correr con los argumentos fijos del perfil y DEBE rechazar los argumentos que amplían las fuentes o lo vuelven activo.

### Scenario: perfil de subfinder
- GIVEN el perfil vigente
- WHEN se construye el comando para `dvwa.lab.test`
- THEN lleva `-d dvwa.lab.test`, salida JSON y sin color, y no lleva `-all`, `-recursive`, `-active` ni `-ip`

### Scenario: subfinder sobre una IP
- GIVEN el objetivo 10.99.0.3
- WHEN se construye el comando de subfinder
- THEN se rechaza como objetivo inválido

## ADDED Requirement: httpx sin redirecciones y con IP fijada
`httpx.probe` DEBE sondear la IP validada con el nombre en el encabezado `Host`, NO DEBE seguir redirecciones y DEBE llevar el rate limit de `policy.yaml`.

### Scenario: perfil de httpx
- GIVEN el objetivo `dvwa.lab.test` con `addresses = ("10.99.0.3",)`
- WHEN se construye el comando
- THEN sondea `10.99.0.3` con `Host: dvwa.lab.test`, lleva `-rl 5` y no lleva `-fr`, `-follow-redirects` ni `-fhr`

### Scenario: redirección a otro host (A5)
- GIVEN una respuesta 302 con `Location: http://203.0.113.7/`
- WHEN se procesa la salida de httpx
- THEN `203.0.113.7` entra como descubrimiento, pasa por el filtro de alcance y nunca se sondea

## ADDED Requirement: Salida de herramienta validada por schema
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

## ADDED Requirement: Errores de herramienta sin excepción
Ante timeout, binario ausente, binario que no se puede ejecutar o código de salida distinto de 0, el adaptador DEBE devolver un resultado de error tipado (`timeout`, `binary_missing`, `exec_error`, `exit_code`) en lugar de lanzar. Una salida con bytes que no son UTF-8 NO DEBE romper la ejecución.

### Scenario: binario ausente
- GIVEN un runner que no encuentra el binario de httpx
- WHEN se invoca `httpx.probe`
- THEN el resultado es `{"status": "error", "error": "binary_missing"}`

### Scenario: timeout
- GIVEN una herramienta que excede `timeout_s`
- WHEN se invoca
- THEN el resultado es `{"status": "error", "error": "timeout"}`

## ADDED Requirement: Sin proxy hacia el laboratorio
El entorno con el que corren las herramientas NO DEBE incluir variables de proxy (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` y sus minúsculas).

### Scenario: proxy en el entorno del harness
- GIVEN un harness corriendo con `HTTPS_PROXY` definido
- WHEN se arma el entorno de una herramienta
- THEN la variable no está

## ADDED Requirement: Un flag prohibido se detecta en cualquier forma
nmap y las herramientas escritas en Go aceptan un flag con uno o dos guiones y con la forma `flag=valor`. El control de argumentos prohibidos DEBE reconocer todas esas formas.

### Scenario: el mismo flag escrito distinto
- GIVEN `--script` prohibido en el perfil de nmap
- WHEN el comando lleva `-script`, `--script=vuln` o `-script=vuln`
- THEN se rechaza

### Scenario: perfiles de httpx y subfinder
- GIVEN los perfiles vigentes
- WHEN se agrega `-csp-probe`, `-tls-probe`, `-ss`, `-p` u `-o` a httpx, o `-o`, `-oD`, `-r` o `-rL` a subfinder
- THEN se rechaza

## ADDED Requirement: La salida solo describe lo que se escaneó
`nmap.service_scan` DEBE descartar los hosts de la salida que no sean una de las IP escaneadas, y `httpx.probe` los que no sean una de las IP sondeadas. Una respuesta hostil NO DEBE poder inflar el grafo: la lista de tecnologías de un servicio DEBE acotarse.

### Scenario: nmap reporta otra IP
- GIVEN una salida de nmap con un host 10.99.0.3 y un escaneo sobre 10.99.0.200
- WHEN se parsea
- THEN no entra ningún servicio y el estado es `invalid_output`

### Scenario: lista de tecnologías enorme
- GIVEN una línea de httpx con 500 tecnologías
- WHEN se parsea
- THEN el servicio queda con 20
