# Delta — audit-log (change 006)

Tests: tests/audit_log/test_validation_reasons.py

## ADDED Requirement: Motivos de la validación
La bitácora DEBE aceptar `sandbox_error` como motivo de error de herramienta y `missing_subject` como motivo de bloqueo. Los registros de control `hitl.approve`, `hitl.reject`, `sandbox.cleanup_failed` y `validation.closed` (con motivo `no_catalog_entry`, `reviewer_rejected`, `reviewer_timeout` o `request_budget_exhausted`) DEBEN quedar en la cadena. Un motivo fuera de esas listas DEBE rechazarse.

### Scenario: motivo de sandbox
- GIVEN un envío que falla en el contenedor
- WHEN se registra
- THEN el registro tiene resultado ABORTED y motivo `sandbox_error`

### Scenario: motivo inventado
- GIVEN un registro de error con motivo `sandbox_broke`
- WHEN se intenta escribir
- THEN se rechaza
