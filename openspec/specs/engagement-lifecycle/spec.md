# Spec — engagement-lifecycle

Estados: CREATED → AUTHORIZED → RECON → CORRELATE → ANALYZE → VALIDATE → REPORT → DELIVERED; ABORTED desde cualquier estado no terminal.
Tests: `tests/test_engagement_and_loops.py`

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
