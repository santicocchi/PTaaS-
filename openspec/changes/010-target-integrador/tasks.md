# Tasks — Change 010

## Spec y diseño
- [ ] 1.1 `proposal.md` y `design.md`
- [ ] 1.2 Deltas de `authorization` y `poc-catalog`
- [ ] 1.3 Revisión de Santi (PR de spec)

## Implementación (test primero por Scenario)
- [ ] 2.1 `lab/docker-compose.yml`: servicio `phantomcorp` (perfil `integrador`, red `lab`, 10.99.0.12, alias) y `PTAAS_INTEGRADOR_CONTEXT` en el README del lab
- [ ] 2.2 `profiles.yaml` y `LAB_TARGET_HOSTS`: `phantomcorp.lab.test`
- [ ] 2.3 Catálogo `0.3.0`: `lab_targets` con `phantomcorp` (aprobación de Santi registrada)
- [ ] 2.4 `demo/roe-integrador.yaml`
- [ ] 2.5 ZAP: verificar `robots.txt` en el spider; si no lo lee, sumar `setOptionParseRobotsTxt` con valor fijo

## Verificación
- [ ] 3.1 Tests de los Scenarios de los deltas
- [ ] 3.2 `security-reviewer` sobre el change
- [ ] 3.3 Corrida real: loop A, B y C sobre `phantomcorp.lab.test` con `audit verify`
