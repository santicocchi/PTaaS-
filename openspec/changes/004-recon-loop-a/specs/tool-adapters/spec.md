# Delta — tool-adapters (change 004)

Tests: tests/tool_adapters/test_subfinder.py, tests/tool_adapters/test_httpx.py,
tests/tool_adapters/test_tool_errors.py

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
Ante timeout, binario ausente o código de salida distinto de 0, el adaptador DEBE devolver un resultado de error tipado (`timeout`, `binary_missing`, `exit_code`) en lugar de lanzar.

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
