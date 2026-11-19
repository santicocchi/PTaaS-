# Design — Change 003: RoE y emisión de scope tokens

## Contexto
Hoy cualquier módulo puede escribir `ScopeToken(...)` con el alcance que quiera, y el Harness lo acepta. Es la limitación L1 del change 008: con un token fabricado se evaden el alcance, el kill switch y las aprobaciones. Este change hace que **la única fuente de autoridad sea un RoE aprobado**, convertido por un emisor en tokens cortos, por fase y verificables.

```
roe.yaml ──parse+validar──▶ RoE ──issue(fase)──▶ ScopeToken + MAC ──▶ Harness.invoke
              │ rechazo                │ rechazo                      │ verify(token)
              ▼                        ▼                              ▼
          bitácora                 bitácora                   token_invalid / revoked
```

## Decisiones

### D1. Formato del RoE (YAML)
```yaml
engagement_id: lab-2026-001
client: Laboratorio propio UTN
scope:
  cidrs: [10.99.0.0/24]
  domains: [dvwa.lab.test, juiceshop.lab.test]
exclusions:
  hosts: [10.99.0.1]            # el gateway de Docker no se toca
  domains: []
window:
  start: 2026-11-20T09:00:00-03:00   # zona horaria obligatoria
  end:   2026-11-20T18:00:00-03:00
phases: [recon, correlate, analyze, validate, report]
emergency_contacts:
  - {name: Santi, channel: "tel:+54..."}
approval:
  approver: Docente
  approved_at: 2026-11-19T12:00:00-03:00
  roe_sha256: <hash del RoE sin el bloque approval>
```
El parser valida con modelos tipados y devuelve **todos** los errores juntos, cada uno con el campo y el motivo. Así quien carga el RoE corrige todo de una vez.

### D2. Validaciones
| Regla | Por qué |
|---|---|
| Campos obligatorios: `engagement_id`, `scope`, `window`, `phases`, `emergency_contacts` (≥ 1) y `approval` | Un RoE incompleto no autoriza nada |
| `engagement_id` con la misma regex que la bitácora (002) | Se usa como nombre de archivo |
| Alcance no vacío: al menos un CIDR o un dominio | Sin alcance no hay qué autorizar |
| Cada CIDR contenido en `targets.lab_only_cidrs` y cada dominio igual o subdominio de `lab_only_domains` | Tope duro del laboratorio. `0.0.0.0/0`, `/8` o una IP pública se rechazan (A8) |
| Ventana con zona horaria explícita; se convierte a UTC; `start < end`; duración ≤ 7 días | Evita ambigüedad de zona (A7) y ventanas eternas |
| `phases` ⊆ fases conocidas | No se inventan fases |
| Exclusiones que cubren todo el alcance → rechazo | Un RoE que no autoriza nada es un error, no un RoE |

### D3. Aprobación del RoE (respuesta a "¿firma, hash, aprobador?")
`approval.roe_sha256` es el SHA-256 del RoE canónico **sin** el bloque `approval`. El parser lo recalcula: si alguien cambia una coma después de aprobado, el RoE se rechaza (`roe_tampered`). La firma criptográfica del aprobador (por ejemplo Ed25519) queda fuera del MVP: el hash ata la aprobación al contenido y el nombre del aprobador queda en bitácora. Es una mejora explícita, no un olvido.

### D4. Integridad del token: HMAC-SHA256 del emisor
`ScopeToken` suma `excluded` (exclusiones) y `mac`. El `TokenIssuer` calcula `mac = HMAC(clave, campos canónicos)`. La clave:
- se lee de `PTAAS_TOKEN_KEY` (≥ 32 bytes) o, si no existe, se genera al azar al arrancar el proceso (`secrets.token_bytes(32)`);
- **nunca** se escribe en código, logs ni bitácora;
- no la ve ningún agente: el Harness recibe el emisor y le pregunta `verify(token)`.

Un token fabricado (sin MAC válido) o alterado (otra fase, otro alcance, otra ventana) da `token_invalid`. Se elige HMAC y no una firma asimétrica porque emisor y verificador son el mismo proceso.

### D5. Emisión por fase, TTL y sin renovación
`issuer.issue(roe, phase, now)`:
- exige que `phase ∈ roe.phases`, que `now` esté dentro de la ventana y que el RoE no esté revocado;
- `window_end = min(now + ttl(phase), roe.window.end)`, con el TTL de `policy.yaml`;
- deja la emisión en bitácora (`token.issue`, OK) y, si rechaza, también (`BLOCKED` con motivo).

No existe `renew`. Un token vencido no se extiende: hay que pedir uno nuevo, y eso queda registrado. **Tokens de varias fases en paralelo** (respuesta a la pregunta abierta): se permiten, porque cada uno habilita solo su fase y la máquina de estados del engagement ya ordena las fases.

### D6. Revocación (respuesta a "¿qué pasa si el RoE se revoca?")
`issuer.revoke(engagement_id, by)` deja `roe.revoke` en bitácora y marca el engagement. Desde ese momento, `verify` devuelve `token_revoked` para **todos** los tokens de ese engagement, incluso los vivos, y `issue` rechaza. No se espera a que venzan.

### D7. Cambios en el Harness
- `Harness(guard, audit, tools, killswitch, issuer)`: el emisor es obligatorio. Es un cambio de firma: se actualizan `conftest.py` y los tests, que dejan de construir tokens a mano y usan un emisor de prueba.
- Orden en `invoke`: integridad de la bitácora → kill switch → `issuer.verify(token)` (`token_invalid` / `token_revoked`) → token vivo → Guard → exclusiones (`excluded`) → HITL → write-ahead → adaptador.
- `BLOCK_REASONS` suma: `token_revoked`, `excluded`, `roe_invalid`, `roe_tampered`, `phase_not_in_roe` y `outside_window`.

### D8. "Ninguna ruta crea ScopeToken fuera del emisor"
Python no impide construir un objeto, pero un token sin MAC válido no sirve para nada. Además, un test estático recorre `harness/` y falla si aparece `ScopeToken(` fuera de `harness/tokens.py`.

## Riesgos
- Si la clave HMAC queda en una variable de entorno compartida con los agentes, se pierde la garantía. Mitigación: los agentes no tienen acceso al entorno del harness (se documenta para el sandbox del 006).
- Un reloj del host manipulado afecta la ventana. Fuera de alcance: se asume el reloj del host del laboratorio.

## Revisión del `security-reviewer` (implementación)
Corregido, cada uno con su test:
- **`issue()` no confía en el objeto `RoE`:** vuelve a parsear su fuente. Un `dataclasses.replace(roe, cidrs=("0.0.0.0/0",))` ya no amplía el token.
- **Sin firma de tokens fuera del emisor:** el método `_mint_for_tests` salió del código de producción y la firma de prueba vive en `tests/conftest.py`. El test estático también busca `X.ScopeToken(` y `._mac` por atributo.
- **La clave no llega a las herramientas:** se saca de `os.environ` al leerla y los adaptadores corren con `safe_env()`, sin `PTAAS_*` ni credenciales. `repr(issuer)` no la muestra.
- **Revocación:** se lee de la bitácora en cada `verify`/`issue`, así que vale entre emisores y entre reinicios. El emisor ahora exige una bitácora.
- **Tokens con tipos raros** (fase como texto, MAC no ASCII o no texto): dan `token_invalid` y se registran como BLOCKED, sin excepciones crudas.
- **RoE malformado** (`scope: []`, fechas fuera de rango, `!!set`, `!!binary`): da `roe_invalid`, nunca una excepción cruda.
- **Exclusiones que cubren todo por unión** (dos `/25` sobre un `/24`): el RoE se rechaza.

Limitaciones aceptadas:
- **Aprobación no autenticada (D3):** cualquiera puede recalcular `roe_sha256`. La firma del aprobador (Ed25519) queda como mejora.
- **Exclusiones textuales:** excluir `10.99.0.1` no bloquea `dvwa.lab.test` si ese nombre resuelve a esa IP. Resolver y volver a validar antes de actuar es el ataque A4 y se hace en los adaptadores reales del change 004.
- **Mismo proceso:** código malicioso dentro del proceso del harness puede leer atributos privados (`_TokenIssuer__key`). La defensa es de arquitectura: los agentes no corren en ese proceso, solo llegan por `Harness.invoke`.
- **Borde de la ventana:** `is_live` incluye el instante final y `issue` lo excluye. Es inofensivo, porque no se emite un token de duración cero.
