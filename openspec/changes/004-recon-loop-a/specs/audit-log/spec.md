# Delta — audit-log (change 004)

Tests: tests/audit_log/test_tool_error_reasons.py, tests/authorization/test_review_004.py

## ADDED Requirement: Motivo de un error de herramienta
Un registro no BLOCKED PUEDE llevar motivo solo si pertenece al conjunto cerrado de errores de herramienta: `timeout`, `binary_missing`, `exec_error`, `exit_code`, `invalid_output` y `adapter_error`. Además, solo los resultados ABORTED y PENDING_HITL PUEDEN llevarlo. Cualquier otro motivo DEBE rechazarse al escribir.

### Scenario: herramienta que excede su timeout
- GIVEN httpx que excede su timeout durante el loop A
- WHEN el orquestador lo registra
- THEN queda `tool.error` con resultado ABORTED y `reason = timeout`, y la cadena sigue íntegra

### Scenario: motivo inventado
- GIVEN un registro ABORTED con motivo "lo que sea"
- WHEN se intenta escribir
- THEN se rechaza

## ADDED Requirement: Un adaptador que lanza después del OK queda abortado
El write-ahead ya dejó un OK que dice que la acción se iba a ejecutar. Si el adaptador lanza una excepción, `Harness.invoke` DEBE registrar la misma acción como ABORTED con motivo `adapter_error` y DEBE devolver un error tipado, sin propagar la excepción.

### Scenario: adaptador con un bug
- GIVEN un adaptador que lanza `RuntimeError` dentro de `run`
- WHEN `Harness.invoke` lo ejecuta
- THEN la bitácora tiene el OK seguido de un ABORTED con `reason = adapter_error`, `invoke` devuelve `{"status": "error", "error": "adapter_error"}` y la cadena sigue íntegra
