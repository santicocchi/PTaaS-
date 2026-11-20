# Spec — audit-log

Tests: `tests/test_audit_and_policy.py`, `tests/test_authorization.py`, `tests/test_audit_persistence.py`, `tests/audit_log/test_tool_error_reasons.py`, `tests/audit_log/test_anchor_race.py`, `tests/authorization/test_review_004.py`, `tests/audit_log/test_validation_reasons.py`, `tests/authorization/test_hitl_subject.py`, `tests/audit_log/test_report_records.py`

## Requirement: Registro total
El sistema DEBE registrar toda decisión del harness: OK, BLOCKED, PENDING_HITL y ABORTED, con agente, acción, objetivo, fase, token/engagement y marca de tiempo.

### Scenario: intento bloqueado
- GIVEN una acción fuera de alcance
- WHEN el harness la rechaza
- THEN existe un registro BLOCKED con el objetivo intentado

## Requirement: Append-only con integridad verificable
Cada registro DEBE incluir el hash del anterior (cadena); el sistema DEBE poder detectar alteración o borrado.

### Scenario: registro alterado
- GIVEN una bitácora íntegra
- WHEN se modifica un campo de un registro intermedio
- THEN la verificación de la cadena falla

### Scenario: registro borrado
- GIVEN una bitácora íntegra
- WHEN se elimina un registro intermedio
- THEN la verificación de la cadena falla

## Requirement: Sin datos sensibles en claro
La bitácora NO DEBE almacenar credenciales ni contenido de datos del cliente; solo referencias a evidencia.

### Scenario: evidencia grande
- GIVEN una evidencia con contenido del objetivo
- WHEN se registra la acción
- THEN la bitácora guarda una referencia, no el contenido

<!-- Archivado desde el change 002-audit-persistence -->

## Requirement: Persistencia por engagement
La bitácora DEBE persistir en un almacenamiento propio de cada engagement y recuperarse completa tras reiniciar el proceso.

### Scenario: recuperación tras reinicio
- GIVEN un engagement con 3 registros escritos
- WHEN se cierra el proceso y se vuelve a abrir la bitácora
- THEN se leen los 3 registros, en orden, con la cadena íntegra

### Scenario: dos engagements no comparten registros
- GIVEN los engagements `eng-1` y `eng-2` con registros propios
- WHEN se lee la bitácora de `eng-2`
- THEN no contiene ningún registro de `eng-1`

### Scenario: identificador de engagement usado como ruta
- GIVEN un `engagement_id` igual a `../otro`
- WHEN se intenta abrir su bitácora
- THEN se rechaza sin crear ni leer ningún archivo

## Requirement: Append-only sin API de modificación
El almacenamiento NO DEBE permitir actualizar ni borrar registros, y la capa de acceso NO DEBE exponer operaciones para hacerlo.

### Scenario: UPDATE directo sobre la tabla
- GIVEN una bitácora con registros
- WHEN se ejecuta un UPDATE o un DELETE por SQL
- THEN la base lo rechaza y los registros quedan iguales

## Requirement: Verificación al abrir y bajo demanda
El sistema DEBE verificar la cadena al abrir la bitácora y DEBE ofrecer `python -m harness.audit verify <archivo>`, que sale con código distinto de 0 si la cadena está rota.

### Scenario: fila alterada en el archivo
- GIVEN una bitácora íntegra
- WHEN se cambia el `target` de un registro intermedio editando el archivo (sin triggers)
- THEN `verify` sale con código 1 e indica el `seq` del registro roto, y abrir la bitácora falla

### Scenario: fila intermedia borrada en el archivo
- GIVEN una bitácora íntegra de 4 registros
- WHEN se borra el registro 2 editando el archivo
- THEN `verify` sale con código 1

### Scenario: inicio de cadena trasplantado
- GIVEN los registros de `eng-1` copiados dentro del archivo de `eng-2`
- WHEN se verifica la bitácora de `eng-2`
- THEN la verificación falla (el GENESIS es por engagement)

## Requirement: Cadena rota detiene el engagement
Con la cadena rota, el engagement NO DEBE ejecutar más acciones.

### Scenario: manipulación durante el engagement
- GIVEN un harness con bitácora persistente y un registro alterado después de abrirla
- WHEN un agente invoca una acción en alcance
- THEN la herramienta no se ejecuta y se lanza `AuditIntegrityError`

## Requirement: Escrituras concurrentes
Escrituras simultáneas DEBEN producir una cadena válida sin registros perdidos.

### Scenario: 4 hilos escribiendo 50 registros cada uno
- GIVEN una bitácora vacía
- WHEN 4 hilos escriben 50 registros cada uno al mismo tiempo
- THEN hay 200 registros y la cadena verifica

## Requirement: Kill switch persistente
Un kill switch activado DEBE seguir activado después de reiniciar.

### Scenario: reinicio después de abortar
- GIVEN un engagement con el kill switch activado
- WHEN se reinicia el proceso y se reabre la bitácora
- THEN cualquier acción se registra ABORTED y no se ejecuta

## Requirement: Evidencia por referencia
El campo de evidencia DEBE ser una referencia con hash (`<ruta>#sha256=<hex>`) y NO DEBE contener el contenido.

### Scenario: evidencia con contenido
- GIVEN un intento de registrar evidencia que no tiene la forma `<ruta>#sha256=<hex>`
- WHEN se llama a `record`
- THEN se rechaza

<!-- Archivado desde el change 008-spec-hardening -->

## Requirement: Cadena verificada antes de actuar
El harness DEBE verificar la integridad de la bitácora del engagement antes de ejecutar una acción activa. Con la cadena rota, el engagement NO DEBE continuar. (Implementación: change 002.)

### Scenario: bitácora manipulada
- GIVEN una bitácora con un registro intermedio alterado
- WHEN un agente invoca una acción en alcance
- THEN la herramienta no se ejecuta y el engagement pasa a ABORTED

## Requirement: Motivo del bloqueo
Todo registro BLOCKED DEBE incluir un motivo de un conjunto cerrado: `out_of_scope`, `token_expired`, `token_invalid`, `wrong_phase`, `not_allowlisted`, `destructive`, `no_adapter`, `adapter_phase`.

### Scenario: motivo de un bloqueo por alcance
- GIVEN una acción sobre un objetivo fuera del RoE
- WHEN el harness la rechaza
- THEN el registro BLOCKED tiene `reason = out_of_scope`

### Scenario: motivo de un bloqueo por token vencido
- GIVEN un token cuya ventana terminó
- WHEN se invoca una acción en alcance
- THEN el registro BLOCKED tiene `reason = token_expired`

<!-- Archivado desde el change 004-recon-loop-a -->

## Requirement: Motivo de un error de herramienta
Un registro no BLOCKED PUEDE llevar motivo solo si pertenece al conjunto cerrado de errores de herramienta: `timeout`, `binary_missing`, `exec_error`, `exit_code`, `invalid_output` y `adapter_error`. Además, solo los resultados ABORTED y PENDING_HITL PUEDEN llevarlo. Cualquier otro motivo DEBE rechazarse al escribir.

### Scenario: herramienta que excede su timeout
- GIVEN httpx que excede su timeout durante el loop A
- WHEN el orquestador lo registra
- THEN queda `tool.error` con resultado ABORTED y `reason = timeout`, y la cadena sigue íntegra

### Scenario: motivo inventado
- GIVEN un registro ABORTED con motivo "lo que sea"
- WHEN se intenta escribir
- THEN se rechaza

## Requirement: Un adaptador que lanza después del OK queda abortado
El write-ahead ya dejó un OK que dice que la acción se iba a ejecutar. Si el adaptador lanza una excepción, `Harness.invoke` DEBE registrar la misma acción como ABORTED con motivo `adapter_error` y DEBE devolver un error tipado, sin propagar la excepción.

### Scenario: adaptador con un bug
- GIVEN un adaptador que lanza `RuntimeError` dentro de `run`
- WHEN `Harness.invoke` lo ejecuta
- THEN la bitácora tiene el OK seguido de un ABORTED con `reason = adapter_error`, `invoke` devuelve `{"status": "error", "error": "adapter_error"}` y la cadena sigue íntegra

<!-- Archivado desde el change 006-sandbox-validation-loop-c -->

## Requirement: Motivos de la validación
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

## Requirement: Hallazgo en la cadena
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

## Requirement: Expresiones ancladas al final
Las validaciones de `subject` y de la referencia de evidencia NO DEBEN aceptar un salto de línea final.

### Scenario: evidencia con salto de línea final
- GIVEN una referencia `ruta#sha256=<hex>` seguida de un salto de línea
- WHEN se intenta registrar
- THEN se rechaza

<!-- Archivado desde el change 007-reporting-defectdojo -->

## Requirement: Registros del informe
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

## Requirement: La bitácora define la decisión de entrega vigente
La decisión vigente de entrega de un informe DEBE salir del control `hitl.*_delivery` más nuevo de la bitácora para ese `report_id`, y DEBE corresponder a una única fila del registro de aprobaciones. Un control `hitl.approve` o `hitl.reject` de un hallazgo NO DEBE contar como decisión de entrega, y una decisión de entrega NO DEBE contar como decisión de validación.

### Scenario: control de validación con sujeto de informe
- GIVEN un `hitl.approve` (de validación) con `subject` `report-v1`
- WHEN se busca la decisión de entrega de `report-v1`
- THEN no hay ninguna

### Scenario: fila copiada después de un rechazo
- GIVEN una aprobación de entrega, un rechazo posterior y una copia de la fila aprobada insertada al final del registro
- WHEN se busca la decisión vigente
- THEN es el rechazo
