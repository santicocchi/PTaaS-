# Delta — authorization (change 007)

Tests: tests/authorization/test_report_token.py, tests/authorization/test_delivery_gate.py

## ADDED Requirement: Destinos del informe en el RoE
El RoE PUEDE tener `report_destinations`: cada destino con host, IP en un CIDR /32, puerto e id de engagement en DefectDojo. Cada host DEBE ser igual o subdominio de `targets.report_destination_domains` y cada IP DEBE estar en `targets.report_destination_cidrs` de `profiles.yaml`. Un destino fuera de esas listas DEBE rechazar el RoE. Los destinos DEBEN entrar en el `roe_sha256`.

### Scenario: destino fuera de la red de herramientas
- GIVEN un RoE con el destino `defectdojo.example.com` o con la IP `203.0.113.7`
- WHEN se parsea
- THEN se rechaza indicando el destino

### Scenario: destino agregado después de aprobar
- GIVEN un RoE aprobado al que luego se le agrega un destino
- WHEN se parsea
- THEN se rechaza como `roe_tampered`

## ADDED Requirement: El token de REPORT solo alcanza los destinos del informe
El token de fase REPORT DEBE tener como alcance solo los `report_destinations` del RoE y NO DEBE incluir los CIDR ni los dominios de los objetivos. Sin destinos, el alcance del token DEBE quedar vacío.

### Scenario: exportar hacia un objetivo del laboratorio
- GIVEN un token de REPORT y la acción `defectdojo.export`
- WHEN se invoca sobre `dvwa.lab.test` o `10.99.0.2`
- THEN el resultado es BLOCKED con `out_of_scope`, queda en bitácora y el adaptador no se ejecuta

### Scenario: RoE sin destinos
- GIVEN un RoE sin `report_destinations`
- WHEN se emite un token de REPORT y se invoca `defectdojo.export` sobre cualquier host
- THEN el resultado es BLOCKED con `out_of_scope`

### Scenario: destino autorizado que resuelve fuera
- GIVEN un destino `defectdojo.tools.test` con IP autorizada `10.97.0.20/32` que resuelve a `10.97.0.30`
- WHEN se invoca `defectdojo.export` sobre ese host
- THEN el resultado es BLOCKED con `dns_out_of_scope`

## ADDED Requirement: Gate de entrega por política
Toda invocación de `defectdojo.export` DEBE exigir aprobación humana con `subject` igual al `report_id`, porque así lo declara `gates_hitl` (`before: deliver`, `capabilities`) en `policy.yaml`, sin importar lo que declare la Action. Sin `subject` DEBE bloquearse con `missing_subject`. Una aprobación de entrega DEBE quedar atada a `(engagement, fase REPORT, acción, destino canónico, report_id)` y NO DEBE habilitar otro `report_id`.

### Scenario: exportación declarada sin aprobación
- GIVEN un token de REPORT y una Action `defectdojo.export` con `requires_human_approval=False`
- WHEN se invoca sobre el destino autorizado con `subject="report-v1"` y sin aprobación cargada
- THEN el resultado es PENDING_HITL y el adaptador no se ejecuta

### Scenario: exportación sin sujeto
- GIVEN un token de REPORT
- WHEN se invoca `defectdojo.export` sobre el destino autorizado sin `subject`
- THEN el resultado es BLOCKED con `missing_subject` y el adaptador no se ejecuta

### Scenario: aprobación de otra versión
- GIVEN una aprobación cargada para `report-v1`
- WHEN se invoca `defectdojo.export` con `subject="report-v2"`
- THEN el resultado es PENDING_HITL y el adaptador no se ejecuta

### Scenario: exportación aprobada
- GIVEN una aprobación cargada para `report-v1` sobre el destino autorizado
- WHEN se invoca `defectdojo.export` con `subject="report-v1"`
- THEN se registra OK antes de ejecutar y el adaptador se ejecuta
