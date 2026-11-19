# Delta — audit-log (change 008)

Tests: tests/test_audit_and_policy.py

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
