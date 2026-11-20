# Spec — engagement-lifecycle

Estados: CREATED → AUTHORIZED → RECON → CORRELATE → ANALYZE → VALIDATE → REPORT → DELIVERED; ABORTED desde cualquier estado no terminal.
Tests: `tests/test_engagement_and_loops.py`, `tests/engagement_lifecycle/test_report_to_delivered.py`, `tests/reporting/test_delivery_failures.py`

## Requirement: Sin RoE no hay autorización
El sistema NO DEBE pasar de CREATED a AUTHORIZED sin un RoE válido.

### Scenario: RoE inválido
- GIVEN un engagement sin RoE válido
- WHEN se intenta avanzar
- THEN la transición es rechazada

## Requirement: Gates humanos en transiciones de riesgo
El sistema DEBE exigir aprobación del Reviewer para entrar a RECON (primera acción activa), a VALIDATE y a DELIVERED.

### Scenario: avanzar sin aprobación
- GIVEN un engagement en AUTHORIZED sin la aprobación `first_active_action`
- WHEN se intenta avanzar
- THEN la transición es rechazada indicando la aprobación faltante

### Scenario: validar sin aprobación
- GIVEN un engagement en ANALYZE sin la aprobación `before_validate`
- WHEN se intenta avanzar
- THEN la transición es rechazada

## Requirement: Kill switch
El sistema DEBE permitir abortar el engagement desde cualquier estado no entregado, y un engagement abortado NO DEBE avanzar.

### Scenario: aborto
- GIVEN un engagement en curso
- WHEN se activa el kill switch
- THEN el estado es ABORTED y todo intento de avanzar es rechazado

## Requirement: Estados terminales
Un engagement DELIVERED o ABORTED NO DEBE aceptar más transiciones.

### Scenario: avanzar tras entregar
- GIVEN un engagement en DELIVERED
- WHEN se intenta avanzar
- THEN la transición es rechazada

<!-- Archivado desde el change 008-spec-hardening -->

## Requirement: Kill switch irreversible por engagement
El kill switch DEBE estar asociado a un engagement y, una vez activado, NO DEBE poder desactivarse: continuar exige un engagement nuevo con RoE vigente.

### Scenario: intento de desactivar el kill switch
- GIVEN un engagement con el kill switch activado
- WHEN se intenta desactivarlo y luego se invoca una acción
- THEN el intento de desactivar falla, la acción se registra ABORTED y no se ejecuta

### Scenario: kill switch de otro engagement
- GIVEN dos engagements `eng-1` y `eng-2`, con el kill switch activado solo en `eng-1`
- WHEN un agente de `eng-2` invoca una acción en alcance
- THEN la acción de `eng-2` se ejecuta y la de `eng-1` se registra ABORTED

<!-- Archivado desde el change 007-reporting-defectdojo -->

## Requirement: REPORT → DELIVERED solo con entrega registrada
El engagement DEBE pasar de REPORT a DELIVERED solo después de que la entrega verifique la cadena, confirme que el kill switch no está activo, confirme la aprobación auditada de la última versión del informe con su SHA-256 y registre `report.delivered`. El permiso `before_deliver` NO DEBE poder otorgarse sin esa aprobación auditada. Si cualquier paso falla, el engagement DEBE quedar en REPORT, salvo con el kill switch activo o la cadena rota, donde DEBE pasar a ABORTED. En DELIVERED NO DEBE generarse una versión nueva del informe.

### Scenario: entrega aprobada
- GIVEN un engagement en REPORT con `report-v1` aprobado y vigente
- WHEN se entrega
- THEN la bitácora tiene `report.delivered` y el estado es DELIVERED

### Scenario: avanzar sin entrega
- GIVEN un engagement en REPORT sin aprobación de entrega
- WHEN se intenta avanzar
- THEN la transición es rechazada indicando `before_deliver` y el estado sigue en REPORT

### Scenario: falla la exportación
- GIVEN un engagement en REPORT con `report-v1` aprobado y un DefectDojo que devuelve error
- WHEN se entrega
- THEN no hay `report.delivered`, la bitácora tiene `report.delivery` ABORTED con el error tipado y el estado sigue en REPORT

### Scenario: kill switch durante REPORT
- GIVEN un engagement en REPORT con `report-v1` aprobado y el kill switch activado
- WHEN se entrega
- THEN se registra `report.delivery` ABORTED con motivo `killswitch`, no se exporta nada y el estado es ABORTED

### Scenario: cadena rota al entregar
- GIVEN un engagement en REPORT con `report-v1` aprobado y un registro intermedio de la bitácora alterado
- WHEN se entrega
- THEN se lanza `AuditIntegrityError`, no hay `report.delivered` y el estado es ABORTED

### Scenario: informe nuevo después de entregar
- GIVEN un engagement en DELIVERED
- WHEN se genera un informe
- THEN falla con `engagement_delivered` y no se escribe nada

### Scenario: entrega ya registrada con el estado recién armado
- GIVEN una bitácora con `report.delivered` de `report-v1`, su aprobación todavía vigente y un `Engagement` recién armado en REPORT
- WHEN se entrega
- THEN falla con `already_delivered`, no se envía nada a DefectDojo y la bitácora sigue con un solo `report.delivered`

### Scenario: kill switch durante el envío
- GIVEN un engagement en REPORT con `report-v1` aprobado y un destino en el RoE
- WHEN el kill switch se activa mientras el POST está en curso
- THEN se registra `report.delivery` ABORTED con motivo `killswitch`, no hay `report.delivered` y el estado es ABORTED
