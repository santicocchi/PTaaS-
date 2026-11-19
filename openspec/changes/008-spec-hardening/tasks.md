# Tasks — Change 008

## Spec
- [x] 1.1 Leer las 11 specs y `Harness.invoke`; listar huecos
- [x] 1.2 Escribir deltas (7 Requirements, ≥ 3 con Scenario negativo)
- [x] 1.3 Cerrar las preguntas abiertas de `001` en su `design.md`
- [ ] 1.4 Revisión humana del delta (PR)

## Implementación (test primero)
- [ ] 2.1 authorization: aprobación atada a engagement y fase
- [ ] 2.2 authorization: normalización del objetivo
- [ ] 2.3 engagement-lifecycle: kill switch irreversible por engagement
- [ ] 2.4 audit-log: motivo del bloqueo en el registro
- [ ] 2.5 tool-adapters: subred fija en `lab/docker-compose.yml` + test de coherencia

## Verificación
- [ ] 3.1 Mutation check de cada Requirement nuevo (romper → test rojo)
- [ ] 3.2 Archivar los deltas en `openspec/specs/`
