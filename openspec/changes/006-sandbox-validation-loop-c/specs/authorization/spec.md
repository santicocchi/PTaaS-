# Delta — authorization (change 006)

Tests: tests/authorization/test_hitl_subject.py

## ADDED Requirement: Aprobación HITL con sujeto
Una aprobación humana DEBE quedar atada a `(engagement, fase, acción, target canónico, subject)`. Una acción con gate humano invocada sin `subject` DEBE bloquearse con motivo `missing_subject` y quedar en bitácora. Una aprobación retirada NO DEBE habilitar nada, y un `subject` que no es un `finding_id` válido NO DEBE poder aprobarse.

### Scenario: validación sin sujeto
- GIVEN un token de VALIDATE y la acción `poc_catalog.run_parametrized`
- WHEN se invoca sin `subject`
- THEN el resultado es BLOCKED con `missing_subject` y el adaptador no se ejecuta

### Scenario: sujeto distinto
- GIVEN una aprobación para el hallazgo `F-1` en `dvwa.lab.test`
- WHEN se invoca con `subject="F-2"` sobre el mismo host
- THEN el resultado es PENDING_HITL y el adaptador no se ejecuta

### Scenario: sujeto aprobado
- GIVEN una aprobación para `F-1` en `dvwa.lab.test`
- WHEN se invoca con `subject="F-1"` sobre ese host
- THEN el adaptador se ejecuta

### Scenario: aprobación del sujeto en otro host
- GIVEN una aprobación para `F-1` en `10.0.0.5`
- WHEN se invoca con `subject="F-1"` sobre `dvwa.lab.test`
- THEN el resultado es PENDING_HITL y el adaptador no se ejecuta

### Scenario: aprobación retirada
- GIVEN una aprobación para `F-1` que el orquestador retiró
- WHEN se invoca con `subject="F-1"`
- THEN el resultado es PENDING_HITL y el adaptador no se ejecuta

### Scenario: sujeto inválido
- GIVEN un `subject` vacío, con espacios, con `/` o de más de 128 caracteres
- WHEN se intenta aprobar
- THEN se rechaza
