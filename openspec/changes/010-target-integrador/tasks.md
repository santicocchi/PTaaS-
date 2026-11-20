# Tasks — Change 010

## Spec y diseño
- [x] 1.1 `proposal.md` y `design.md`
- [x] 1.2 Deltas de `authorization` y `poc-catalog`
- [x] 1.3 Revisión de Santi (PR de spec)

## Implementación (test primero por Scenario)
- [x] 2.1 `lab/docker-compose.yml`: servicio `phantomcorp` (perfil `integrador`, red `lab`, 10.99.0.12, alias) y `PTAAS_INTEGRADOR_CONTEXT` en el README del lab
- [x] 2.2 `profiles.yaml` y `LAB_TARGET_HOSTS`: `phantomcorp.lab.test`
- [x] 2.3 Catálogo `0.3.0`: `lab_targets` con `phantomcorp` (propuesto por claude, aprobado por santiago el 2026-11-20)
- [x] 2.4 `demo/roe-integrador.yaml`
- [x] 2.5 ZAP: `setOptionParseRobotsTxt` fijo en `true` (delta de `tool-adapters`)
- [ ] 2.6 Demos (`pipeline`, `validation`, `report`): elegir la RoE entre las del repo (`roe-pipeline` o `roe-integrador`) sin aflojar el control de la entrega del loop C
- [ ] 2.7 Trazabilidad: commit del repo del curso e `Id` de la imagen `ptaas-phantomcorp` en la bitácora de la corrida

## Verificación
- [x] 3.1 Tests de los Scenarios de los deltas
- [x] 3.2 `security-reviewer` sobre el change (B1 = firma pendiente; I1–I3 y M1, M3, M4, M8 corregidos; I4 → 2.7)
- [ ] 3.3 Corrida real: loop A, B y C sobre `phantomcorp.lab.test` con `audit verify`
