# Checkpoint 1 — Sprint 1 (núcleo de autorización)

Lo que pide el plan para este checkpoint: specs, changes 002 y 003, lista de bypass
encontrados y corregidos, y la demo de 5 minutos (ver [`demo/README.md`](../demo/README.md)).

## Specs

Todas en `openspec/specs/`, con los deltas de los changes 008, 002, 003 y 009 ya archivados.

| Capability | Requirements | Scenarios |
|---|---:|---:|
| authorization | 17 | 33 |
| audit-log | 12 | 18 |
| tool-adapters | 6 | 8 |
| vuln-analysis | 6 | 6 |
| poc-catalog | 6 | 7 |
| engagement-lifecycle | 5 | 7 |
| agent-contracts | 5 | 6 |
| asset-discovery | 5 | 6 |
| correlation | 5 | 5 |
| validation | 3 | 3 |
| reporting | 2 | 2 |
| **Total** | **72** | **101** |

Cada Scenario es un test (`tests/`): 226 tests en verde.

## Changes cerrados en el sprint

| Change | Qué resolvió | Revisión de seguridad |
|---|---|---|
| 008 spec-hardening | Normalización de objetivos (mayúsculas, punto final, IPv6, IPv4 mapeada), motivos de bloqueo cerrados | Hallazgos corregidos con test |
| 002 audit-persistence | Bitácora SQLite append-only por engagement, hash encadenado, triggers contra UPDATE/DELETE, `verify` por CLI, kill switch persistente | Write-ahead, cadena rota deja rastro, ancla contra truncado, triggers verificados al abrir |
| 003 roe-and-tokens | RoE validado y aprobado por hash, tokens por fase con HMAC y TTL, exclusiones, revocación | El emisor re-parsea el RoE, la clave no llega a las herramientas, revocación leída de la bitácora |
| 009 red-team-guard | 16 ataques contra el guard, 3 bypass reales corregidos | Resolver que falla, gate con fase mal escrita, kill switch re-chequeado antes de ejecutar |

## Bypass encontrados y corregidos (red team, change 009)

| # | Ataque | Antes | Ahora |
|---|---|---|---|
| **A4** | Hostname autorizado que resuelve a una IP fuera de alcance | **Pasaba** | `dns_out_of_scope` / `dns_unresolved` / `excluded` |
| **R13** | Acción de VALIDATE con `requires_human_approval=False` | **Pasaba sin aprobación humana** | El gate lo decide la política: toda acción de VALIDATE espera aprobación |
| **R14** | Adaptador destructivo invocado con una Action "no destructiva" | **Pasaba** | El Harness consulta `adapter.destructive` |

Los otros 13 ataques (sufijos engañosos, IPv6, IPv4 en octal o decimal, homoglifos, tokens
fabricados o de otra fase, zonas horarias, CIDR amplio, argumentos inyectados, concurrencia en
la bitácora, kill switch evadido) ya estaban bloqueados y quedaron como tests de regresión.
Tabla completa: `openspec/changes/009-red-team-guard/proposal.md`.

## Limitaciones conocidas (documentadas en cada design.md)

- **Truncado de la bitácora con el proceso apagado:** necesita un ancla externa (publicar el
  último hash en cada checkpoint o informe).
- **Aprobación no autenticada:** cualquiera puede recalcular `roe_sha256`. Mejora: firma Ed25519
  del aprobador.
- **DNS rebinding:** entre validar la IP y que la herramienta resuelva de nuevo. Se ataca en el
  004 pasándole a la herramienta la IP validada (task 4.2).
- **Mismo proceso:** el código que corre dentro del harness puede leer atributos privados. Por
  eso los agentes solo llegan por `Harness.invoke`.

## Próximo sprint

Change 004 (recon con subfinder/httpx y loop A, más redirecciones y rebinding) y después 005
(correlación y análisis, loop B).
