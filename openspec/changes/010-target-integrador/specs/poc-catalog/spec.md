# Delta — poc-catalog (change 010)

Tests: tests/poc_catalog/test_integrador_targets.py

## MODIFIED Requirement: Solo laboratorio
Toda entrada DEBE ser `lab_only`. `lab_targets` PUEDE incluir `phantomcorp`, que DEBE mapear solo al FQDN `phantomcorp.lab.test`. Las entradas siguen siendo inertes: este change no agrega ni cambia evaluadores.

### Scenario: verificación inerte sobre el target del integrador
- GIVEN una entrada con `lab_targets: [dvwa, juice-shop, phantomcorp]` aprobada
- WHEN se parametriza sobre `phantomcorp.lab.test`
- THEN se acepta

### Scenario: entrada sin `phantomcorp`
- GIVEN una entrada con `lab_targets: [dvwa]`
- WHEN se parametriza sobre `phantomcorp.lab.test`
- THEN se rechaza y no se ejecuta

### Scenario: host parecido
- GIVEN una entrada con `lab_targets: [phantomcorp]`
- WHEN se parametriza sobre `phantomcorp`, `phantomcorp.lab.test.evil.test` o `PHANTOMCORP.lab.test.`
- THEN solo se acepta el que normaliza exactamente a `phantomcorp.lab.test`

### Scenario: cambio de catálogo sin aprobación
- GIVEN el catálogo `0.3.0` con una entrada cuyo `approved_by` es igual a `proposed_by`
- WHEN se carga
- THEN se rechaza
