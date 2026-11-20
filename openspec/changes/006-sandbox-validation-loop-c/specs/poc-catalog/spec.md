# Delta — poc-catalog (change 006)

Tests: tests/test_poc_catalog.py, tests/validation/test_loop_c.py

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

## ADDED Requirement: Objetivos del laboratorio explícitos
Cada nombre de `lab_targets` DEBE estar en un mapa explícito a FQDN del laboratorio (`dvwa` → `dvwa.lab.test`, `juice-shop` → `juiceshop.lab.test`). Un host DEBE coincidir solo si su forma canónica completa (minúsculas, sin punto final, sin quitar caracteres) es uno de esos FQDN.

### Scenario: host parecido
- GIVEN los `lab_targets` `dvwa` y `juice-shop`
- WHEN se evalúan `dvwa.evil.example`, `d-v-w-a.lab.test`, `dvwa`, `xdvwa.lab.test` o `juice-shop.lab.test`
- THEN ninguno coincide, y sí coinciden `dvwa.lab.test`, `DVWA.lab.test.` y `juiceshop.lab.test`

### Scenario: objetivo desconocido en el catálogo
- GIVEN una entrada con `lab_targets: [dvwa, evil]`
- WHEN se carga el catálogo
- THEN se rechaza indicando `evil`
