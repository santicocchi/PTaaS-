# Delta — tool-adapters (change 007)

Tests: tests/tool_adapters/test_defectdojo.py

## ADDED Requirement: DefectDojo por API, con una sola llamada fija
`defectdojo.export` DEBE declarar `allowed_phases = (REPORT,)` y `destructive = False`, y DEBE ejecutarse solo por `Harness.invoke`. Por invocación DEBE hacer una única llamada `POST /api/v2/import-scan/` con `scan_type=Generic Findings Import` y `close_old_findings=false`, a la IP que validó el Harness con `Host: <nombre>`, sin seguir redirecciones, con el timeout y el tamaño máximo de respuesta de `policy.yaml` y sin variables de proxy. Antes de enviar DEBE verificar que el SHA-256 del archivo del informe coincida con el aprobado; si no, NO DEBE enviar nada.

### Scenario: llamada armada
- GIVEN el destino `defectdojo.tools.test` con `addresses = ("10.97.0.20",)` y `report-v1` aprobado
- WHEN se arma la solicitud
- THEN va a `10.97.0.20` con `Host: defectdojo.tools.test`, método POST, ruta `/api/v2/import-scan/`, `scan_type` `Generic Findings Import` y sin seguir redirecciones

### Scenario: redirección de DefectDojo
- GIVEN un servidor falso que responde 302 a `http://203.0.113.7/`
- WHEN se exporta
- THEN no se sigue la redirección y el resultado es `{"status": "error", "error": "invalid_output"}`

### Scenario: informe cambiado entre aprobar y enviar
- GIVEN `report-v1` aprobado y su archivo modificado antes del envío
- WHEN el adaptador se ejecuta
- THEN no abre ninguna conexión y devuelve un error tipado

## ADDED Requirement: Clave de DefectDojo
La clave DEBE leerse de `PTAAS_DEFECTDOJO_API_KEY`, NO DEBE tener valor por defecto, DEBE viajar solo en el encabezado `Authorization: Token <clave>` y NO DEBE aparecer en la URL, la bitácora, la evidencia ni los errores.

### Scenario: sin clave
- GIVEN `PTAAS_DEFECTDOJO_API_KEY` sin definir
- WHEN se invoca `defectdojo.export`
- THEN devuelve un error tipado y no abre ninguna conexión

### Scenario: clave fuera de los registros
- GIVEN una exportación que falla con la clave `k-123456`
- WHEN se leen la bitácora, la evidencia y el mensaje de error
- THEN ninguno contiene `k-123456`

## ADDED Requirement: Errores de DefectDojo sin excepción
Ante timeout, conexión rechazada, respuesta no 2xx o respuesta que no es JSON, el adaptador DEBE devolver `timeout`, `exec_error` o `invalid_output` en lugar de lanzar. Con un envío exitoso DEBE devolver la referencia de una evidencia con el SHA-256 del documento enviado, el código HTTP, el id de test y los conteos, sin el cuerpo completo de la respuesta.

### Scenario: DefectDojo caído
- GIVEN un destino que rechaza la conexión
- WHEN se invoca `defectdojo.export`
- THEN el resultado es `{"status": "error", "error": "exec_error"}`

### Scenario: respuesta de error
- GIVEN un servidor falso que responde 500
- WHEN se invoca `defectdojo.export`
- THEN el resultado es `{"status": "error", "error": "invalid_output"}`

### Scenario: envío exitoso
- GIVEN un servidor falso que responde 201 con `{"test": 7}`
- WHEN se invoca `defectdojo.export`
- THEN el resultado es OK con una evidencia `reports/<engagement>/export-report-v1.json#sha256=<hex>` que tiene el código 201, el test 7 y el SHA-256 del documento enviado
