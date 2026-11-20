# Delta — audit-log (change 007)

Tests: tests/audit_log/test_report_records.py

## ADDED Requirement: Registros del informe
La bitácora DEBE aceptar estos registros de control, todos con `subject`. Sus motivos amplían los conjuntos cerrados de los requisitos de motivos del 004 y del 006; cualquier motivo fuera de la unión de esos conjuntos DEBE seguir rechazándose:
- `report.generated`: resultado OK, evidencia `reports/<engagement>/report-v<N>.json#sha256=<hex>` y `subject` `report-v<N>`, con el mismo `N` en los dos;
- `report.generation_failed`: resultado ABORTED, `subject` = `finding_id` o `report_id`, y motivo del conjunto cerrado `missing_cwe`, `invalid_cvss_vector`, `missing_remediation`, `invalid_catalog_entry`, `evidence_mismatch`, `validation_mismatch`, `finding_mismatch`, `sensitive_data`, `summary_jargon`, `not_lab_target`, `out_of_scope`, `engagement_not_in_report`, `engagement_delivered`, `version_conflict`, `internal_error`;
- `hitl.approve_delivery` y `hitl.reject_delivery`: resultado OK, agente `reviewer:<nombre>`, evidencia = referencia hasheada de la fila del registro con su número (`approvals/<engagement>/<report_id>#sha256=`) y `subject` = `report_id`;
- `report.delivery`: resultado PENDING_HITL sin motivo (sin aprobación) o ABORTED con motivo del conjunto cerrado `killswitch`, `sensitive_data`, `evidence_mismatch`, `timeout`, `exec_error`, `invalid_output`, `adapter_error`, `out_of_scope`, con `subject` = `report_id` (`report-v<N>`);
- `report.delivered`: resultado OK, objetivo = modo (`api` u `offline`), evidencia = resumen de la entrega `reports/<engagement>/delivered-<report_id>.json` (con el SHA-256 del informe, el modo y la referencia de la exportación) y `subject` = `report_id`.

Un motivo fuera de esos conjuntos, un `report.generated` o `report.delivered` sin evidencia, un `report.generated` cuya evidencia no es el archivo de su `subject` en su engagement, o un `report.generated`, `report.delivery` o `report.delivered` cuyo `subject` no es `report-v<N>`, DEBE rechazarse al escribir. Los registros del informe NO DEBEN contener el contenido del informe, la clave de DefectDojo ni valores redactados.

### Scenario: informe generado
- GIVEN un `report-v1` escrito
- WHEN se registra
- THEN hay un `report.generated` OK con la referencia del archivo, `subject` `report-v1` y la cadena verifica

### Scenario: motivo de fallo inventado
- GIVEN un `report.generation_failed` con motivo `campo_raro`
- WHEN se intenta escribir
- THEN se rechaza

### Scenario: informe generado con otra forma
- GIVEN un `report.generated` con `subject` `f-1`, o con `subject` `report-v2` y evidencia `reports/eng-1/report-v1.json`, o con evidencia de otro engagement
- WHEN se intenta escribir
- THEN se rechaza

### Scenario: entrega abortada sin motivo
- GIVEN un `report.delivery` ABORTED sin motivo o con motivo `campo_raro`
- WHEN se intenta escribir
- THEN se rechaza

### Scenario: decisión de entrega mal formada
- GIVEN un `hitl.approve_delivery` de un agente que no es `reviewer:<nombre>`, sin evidencia o con `subject` `f-1`
- WHEN se intenta escribir
- THEN se rechaza

### Scenario: informe generado sin evidencia
- GIVEN un `report.generated` sin referencia de evidencia
- WHEN se intenta escribir
- THEN se rechaza

### Scenario: fallo por dato sensible
- GIVEN un informe que falla con `sensitive_data` por un correo
- WHEN se registra el fallo
- THEN el registro tiene motivo `sensitive_data` y ningún campo del registro contiene el correo

## ADDED Requirement: La bitácora define la decisión de entrega vigente
La decisión vigente de entrega de un informe DEBE salir del control `hitl.*_delivery` más nuevo de la bitácora para ese `report_id`, y DEBE corresponder a una única fila del registro de aprobaciones. Un control `hitl.approve` o `hitl.reject` de un hallazgo NO DEBE contar como decisión de entrega, y una decisión de entrega NO DEBE contar como decisión de validación.

### Scenario: control de validación con sujeto de informe
- GIVEN un `hitl.approve` (de validación) con `subject` `report-v1`
- WHEN se busca la decisión de entrega de `report-v1`
- THEN no hay ninguna

### Scenario: fila copiada después de un rechazo
- GIVEN una aprobación de entrega, un rechazo posterior y una copia de la fila aprobada insertada al final del registro
- WHEN se busca la decisión vigente
- THEN es el rechazo
