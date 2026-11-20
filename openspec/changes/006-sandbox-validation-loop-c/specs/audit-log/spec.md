# Delta — audit-log (change 006)

Tests: tests/audit_log/test_validation_reasons.py, tests/authorization/test_hitl_subject.py

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
- GIVEN una invocación con `subject` que no es un `finding_id` válido (por ejemplo `F-1` seguido de un salto de línea, o un texto de 500 caracteres)
- WHEN se invoca, en cualquier fase y aun con el kill switch activo
- THEN queda exactamente un registro BLOCKED con motivo `invalid_subject`, sin `subject`, y el adaptador no se ejecuta

## ADDED Requirement: Hallazgo en la cadena
Un registro PUEDE llevar `subject` (el `finding_id`). Si lo lleva, DEBE ser un `finding_id` válido y DEBE entrar en el hash del registro. Los registros de `Harness.invoke` con sujeto (OK, PENDING_HITL) y los controles `hitl.*` y `validation.*` DEBEN llevarlo. Una bitácora creada antes de este change DEBE poder leerse y verificarse.

### Scenario: sujeto en registros y controles
- GIVEN un PENDING_HITL de `invoke` y un `hitl.approve` del hallazgo `F-1`
- WHEN se registran
- THEN los dos tienen `subject` `F-1` y la cadena verifica

### Scenario: sujeto alterado
- GIVEN un registro con `subject` `F-1`
- WHEN se cambia a `F-2`
- THEN la verificación de la cadena falla

### Scenario: bitácora anterior a 006
- GIVEN una bitácora SQLite sin la columna `subject`
- WHEN se verifica y después se abre
- THEN verifica igual, al abrirse gana la columna y los registros viejos no tienen `subject`

## ADDED Requirement: Expresiones ancladas al final
Las validaciones de `subject` y de la referencia de evidencia NO DEBEN aceptar un salto de línea final.

### Scenario: evidencia con salto de línea final
- GIVEN una referencia `ruta#sha256=<hex>` seguida de un salto de línea
- WHEN se intenta registrar
- THEN se rechaza
