# Change 008 — Endurecimiento de specs (spec sprint, día 2)

## Por qué
La lectura de `Harness.invoke` y de las 11 specs dejó huecos donde el control depende de una convención y no de una regla verificable:

- Las aprobaciones humanas se guardan como `acción@objetivo`, sin engagement ni fase: una aprobación vieja podría reutilizarse.
- Cualquier módulo puede construir un `ScopeToken`; nada prueba que lo emitió el harness.
- El objetivo no se normaliza de forma explícita (mayúsculas, punto final, IPv4 mapeada a IPv6).
- El kill switch puede volver a `False` y no está atado a un engagement.
- La bitácora no se verifica antes de actuar, y un BLOCKED no dice *por qué* se bloqueó.
- `harness/profiles.yaml` autoriza `10.99.0.0/24`, pero `lab/docker-compose.yml` no fija subred (Docker asignó `172.18.0.0/16`).

## Qué cambia
7 Requirements nuevos, 5 de ellos con Scenario negativo de seguridad, en 4 capabilities:

| Capability | Requirement | Negativo |
|---|---|---|
| authorization | Aprobación humana atada a engagement y fase | Sí |
| authorization | Normalización del objetivo | Sí |
| authorization | Token emitido por el harness | Sí |
| engagement-lifecycle | Kill switch irreversible por engagement | Sí |
| audit-log | Cadena verificada antes de actuar | Sí |
| audit-log | Motivo del bloqueo | No |
| tool-adapters | Red del laboratorio coherente con la política | No |

## Fuera de este change
La implementación de los Requirements que ya tienen change propio se hace allí:
"Token emitido por el harness" → `003-roe-and-tokens`; "Cadena verificada antes de actuar" → `002-audit-persistence`.
Este change solo los especifica para que esos changes arranquen con criterios de aceptación claros.

## Criterios de aceptación
1. Cada Scenario nuevo tiene un test que falla antes de implementar y pasa después.
2. `python -m pytest -q` y `python tools/progress.py` en verde.
3. Delta revisado por otro integrante (o por el `spec-author`) antes de codear.
