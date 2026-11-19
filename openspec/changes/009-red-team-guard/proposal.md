# Change 009 — Red team del guard (día 5)

## Por qué
El plan pide, al cierre del Sprint 1, atacar el control a propósito y convertir cada evasión en test y corrección. Se probaron los 10 ataques de `docs/desafios-extension.md` (A1–A10) y 6 propios (R11–R16): en total 45 casos en `tests/test_red_team_guard.py`.

## Resultado del red team
| # | Ataque | Resultado antes de este change | Ahora |
|---|---|---|---|
| A1 | Hostname con mayúsculas, punto final o espacios | Bloqueado/normalizado (008) | Igual |
| A2 | Sufijo engañoso | Bloqueado | Igual |
| A3 | IPv6, IPv4 mapeada, `%zona` | Bloqueado (008) | Igual |
| **A4** | **Hostname autorizado que resuelve a una IP fuera de alcance** | **PASABA** | Bloqueado: `dns_out_of_scope` / `dns_unresolved` / `excluded` |
| A5 | Redirecciones HTTP | No aplica todavía (sin adaptador HTTP) | Requirement agregado al 004 |
| A6 | Token reutilizado en otra fase o engagement | Bloqueado (003, 002) | Igual |
| A7 | Zonas horarias | Bloqueado (003) | Igual |
| A8 | CIDR amplio en el RoE | Bloqueado (003) | Igual |
| A9 | Argumentos inyectados por el target | Bloqueado (008) | Igual |
| A10 | Concurrencia en la bitácora | Cadena íntegra (002) | Igual |
| R11 | IPv4 en octal, hex o decimal (`167772165` = 10.0.0.5 para curl) | Bloqueado | Igual |
| R12 | Homoglifos y caracteres invisibles | Bloqueado | Igual |
| **R13** | **Acción de VALIDATE con `requires_human_approval=False`** | **PASABA: se ejecutaba sin aprobación humana** | Gate por política: toda acción de VALIDATE exige aprobación |
| **R14** | **Adaptador destructivo invocado con una Action "no destructiva"** | **PASABA** | El Harness consulta `adapter.destructive` |
| R15 | Token fabricado con `0.0.0.0/0` | Bloqueado (003) | Igual |
| R16 | Kill switch evadido cambiando el `engagement_id` | Bloqueado (003) | Igual |

**3 bypass reales encontrados y corregidos (A4, R13, R14).** Los tres tienen la misma causa de fondo: el harness confiaba en un dato que no controla. En A4 era el nombre de host (sin mirar a qué IP apunta); en R13 y R14, un flag que arma el agente.

## Hallazgo funcional (no es de seguridad)
El adaptador de Nuclei espera una URL, pero el Guard (008) solo acepta host o IP. Por eso hoy `nuclei.safe_templates` no puede correr a través de `Harness.invoke`. Se agrega al change 005: el adaptador debe armar la URL a partir del host autorizado.
