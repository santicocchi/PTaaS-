# Delta — audit-log (change 006)

Tests: tests/audit_log/test_validation_reasons.py

## ADDED Requirement: Motivos de la validación
La bitácora DEBE aceptar `sandbox_error` como motivo de error de herramienta y `missing_subject` e `invalid_subject` como motivos de bloqueo. Los registros de control `hitl.approve`, `hitl.reject`, `sandbox.cleanup_failed` y `validation.closed` (con motivo `no_catalog_entry`, `reviewer_rejected`, `reviewer_timeout` o `request_budget_exhausted`) DEBEN quedar en la cadena. Un motivo fuera de esas listas DEBE rechazarse.

### Scenario: motivo de sandbox
- GIVEN un envío que falla en el contenedor
- WHEN se registra
- THEN el registro tiene resultado ABORTED y motivo `sandbox_error`

### Scenario: motivo inventado
- GIVEN un registro de error con motivo `sandbox_broke`
- WHEN se intenta escribir
- THEN se rechaza

### Scenario: sujeto malformado
- GIVEN una invocación con `subject` que no es un `finding_id` válido (por ejemplo `F-1
X` o un texto de 500 caracteres)
- WHEN se invoca, en cualquier fase y aun con el kill switch activo
- THEN queda exactamente un registro BLOCKED con motivo `invalid_subject`, sin `subject`, y el adaptador no se ejecuta
