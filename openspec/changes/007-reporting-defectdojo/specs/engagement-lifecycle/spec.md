# Delta — engagement-lifecycle (change 007)

Tests: tests/engagement_lifecycle/test_report_to_delivered.py

## ADDED Requirement: REPORT → DELIVERED solo con entrega registrada
El engagement DEBE pasar de REPORT a DELIVERED solo después de que la entrega verifique la cadena, confirme que el kill switch no está activo, confirme la aprobación auditada de la última versión del informe con su SHA-256 y registre `report.delivered`. El permiso `before_deliver` NO DEBE poder otorgarse sin esa aprobación auditada. Si cualquier paso falla, el engagement DEBE quedar en REPORT. En DELIVERED NO DEBE generarse una versión nueva del informe.

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
- THEN no hay `report.delivered`, la bitácora tiene el error y el estado sigue en REPORT

### Scenario: kill switch durante REPORT
- GIVEN un engagement en REPORT con `report-v1` aprobado y el kill switch activado
- WHEN se entrega
- THEN se registra `report.delivery` ABORTED, no se exporta nada y el estado es ABORTED

### Scenario: informe nuevo después de entregar
- GIVEN un engagement en DELIVERED
- WHEN se genera un informe
- THEN falla con `engagement_delivered` y no se escribe nada
