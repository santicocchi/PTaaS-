# Delta — poc-catalog (change 006)

Tests: tests/test_poc_catalog.py

## MODIFIED Requirement: Aprobación registrada
Toda entrada DEBE tener `proposed_by`, `approved_by` y `approved_at`. `approved_by` NO DEBE ser igual a `proposed_by`: nadie aprueba su propia verificación.

### Scenario: entrada sin aprobación
- GIVEN una entrada sin `approved_at`
- WHEN se carga el catálogo
- THEN se rechaza

### Scenario: autoaprobación
- GIVEN una entrada con `approved_by` igual a `proposed_by`
- WHEN se carga el catálogo
- THEN se rechaza indicando la entrada

## ADDED Requirement: Evaluador conocido
El `evaluator` de toda entrada DEBE existir en `EVALUATORS`. Un evaluador nuevo es código del harness y DEBE entrar por un change con revisión del `security-reviewer`.

### Scenario: evaluador inexistente
- GIVEN una entrada con `evaluator: run_shell`
- WHEN se carga el catálogo
- THEN se rechaza

## ADDED Requirement: Canario por intento
Cada intento de una verificación con canario DEBE usar un canario nuevo. Un canario de un intento anterior NO DEBE contar como positivo.

### Scenario: canario de una corrida anterior
- GIVEN una respuesta que refleja el canario del intento 1
- WHEN se evalúa el intento 2
- THEN el resultado no es positivo
