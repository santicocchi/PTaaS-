# Delta — authorization (change 005)

Tests: tests/test_roe_and_tokens.py

## ADDED Requirement: Criticidad de activos en el RoE
El RoE PUEDE incluir `criticality`, un mapa de dominio o IP del alcance a un entero de 1 a 5. Una entrada fuera del alcance o con un valor fuera de rango DEBE rechazar el RoE. Un activo sin entrada tiene criticidad 3.

### Scenario: criticidad fuera de rango
- GIVEN un RoE con `criticality: {dvwa.lab.test: 9}`
- WHEN se parsea
- THEN se rechaza indicando el campo

### Scenario: criticidad de un host fuera del alcance
- GIVEN un RoE con `criticality: {otro.lab.test: 4}` y `otro.lab.test` fuera del alcance
- WHEN se parsea
- THEN se rechaza
