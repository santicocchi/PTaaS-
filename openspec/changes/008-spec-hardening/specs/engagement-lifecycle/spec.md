# Delta — engagement-lifecycle (change 008)

Tests: tests/test_engagement_and_loops.py

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
