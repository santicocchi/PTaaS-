# Delta — audit-log (change 004)

Tests: tests/audit_log/test_tool_error_reasons.py

## ADDED Requirement: Motivo de un error de herramienta
Un registro no BLOCKED PUEDE llevar motivo solo si pertenece al conjunto cerrado de errores de herramienta: `timeout`, `binary_missing`, `exit_code`, `invalid_output`. Cualquier otro motivo DEBE rechazarse al escribir.

### Scenario: herramienta que excede su timeout
- GIVEN httpx que excede su timeout durante el loop A
- WHEN el orquestador lo registra
- THEN queda `tool.error` con resultado ABORTED y `reason = timeout`, y la cadena sigue íntegra

### Scenario: motivo inventado
- GIVEN un registro ABORTED con motivo "lo que sea"
- WHEN se intenta escribir
- THEN se rechaza
