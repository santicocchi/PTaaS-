# Delta — tool-adapters (change 008)

Tests: tests/test_audit_and_policy.py

## Requirement: Red del laboratorio coherente con la política
La subred de `lab/docker-compose.yml` DEBE estar fijada y contenida en `targets.lab_only_cidrs` de `harness/profiles.yaml`, y la red DEBE ser `internal: true`.

### Scenario: subred no fijada o distinta
- GIVEN un `docker-compose.yml` sin subred, o con una subred fuera de `lab_only_cidrs`
- WHEN corre el test de coherencia
- THEN el test falla indicando la diferencia

### Scenario: red con salida a internet
- GIVEN la red del laboratorio sin `internal: true`
- WHEN corre el test de coherencia
- THEN el test falla
