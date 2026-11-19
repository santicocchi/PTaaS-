# Delta — authorization (change 009, red team)

Tests: tests/test_red_team_guard.py

## Requirement: El gate humano lo decide la política
Toda acción en una fase listada en `gates_hitl` de `policy.yaml` DEBE exigir aprobación humana, sin importar lo que declare la Action.

### Scenario: validación declarada sin aprobación (R13)
- GIVEN un token de VALIDATE y una Action con `requires_human_approval=False`
- WHEN un agente la invoca sin aprobación registrada
- THEN el resultado es PENDING_HITL y la herramienta no se ejecuta

## Requirement: Lo destructivo lo declara el adaptador
El Harness DEBE bloquear toda acción cuyo adaptador sea destructivo o no lo declare, aunque la Action diga lo contrario.

### Scenario: adaptador destructivo con Action no destructiva (R14)
- GIVEN un adaptador con `destructive=True`
- WHEN se invoca con una Action `destructive=False`
- THEN se bloquea con `reason = destructive`

## Requirement: Un nombre autorizado debe resolver dentro del alcance
Antes de actuar sobre un nombre, el Harness DEBE resolverlo y exigir que todas sus IP estén en los CIDR del token y no estén excluidas. Si no resuelve, DEBE bloquear.

### Scenario: nombre que resuelve fuera de alcance (A4)
- GIVEN un token que autoriza `lab.example.test` y 10.0.0.0/24
- WHEN `app.lab.example.test` resuelve a 8.8.8.8, o a 10.0.0.7 y 10.0.1.7
- THEN se bloquea con `dns_out_of_scope`

### Scenario: nombre que resuelve a un host excluido
- GIVEN una exclusión 10.0.0.1
- WHEN el nombre resuelve a 10.0.0.1
- THEN se bloquea con `excluded`

### Scenario: nombre que no resuelve
- GIVEN un nombre sin registros DNS
- WHEN se invoca una acción sobre él
- THEN se bloquea con `dns_unresolved`
