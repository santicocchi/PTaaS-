# Delta — authorization (change 003)

Tests: tests/test_roe_and_tokens.py

## Requirement: RoE completo y aprobado
Un RoE DEBE tener `engagement_id`, alcance, ventana, fases, al menos un contacto de emergencia y aprobación cuyo `roe_sha256` coincida con el contenido. El parser DEBE devolver todos los errores con campo y motivo.

### Scenario: RoE sin alcance ni contactos
- GIVEN un RoE sin `scope` y con `emergency_contacts` vacío
- WHEN se parsea
- THEN se rechaza con un error por cada campo, y no se puede emitir ningún token

### Scenario: RoE modificado después de aprobado
- GIVEN un RoE aprobado al que luego se le agrega un CIDR
- WHEN se parsea
- THEN se rechaza como `roe_tampered`

## Requirement: Alcance máximo del laboratorio
Cada CIDR del RoE DEBE estar contenido en `targets.lab_only_cidrs` y cada dominio DEBE ser igual o subdominio de `lab_only_domains`.

### Scenario: CIDR demasiado amplio (A8)
- GIVEN un RoE con alcance `0.0.0.0/0`, o `10.0.0.0/8`, o una IP pública
- WHEN se parsea
- THEN se rechaza indicando el CIDR fuera del laboratorio

### Scenario: dominio fuera del laboratorio
- GIVEN un RoE con el dominio `example.com`
- WHEN se parsea
- THEN se rechaza

## Requirement: Ventana en UTC con zona horaria explícita
La ventana DEBE declarar zona horaria, convertirse a UTC, tener `start < end` y durar como máximo 7 días.

### Scenario: ventana invertida
- GIVEN un RoE con `end` anterior a `start`
- WHEN se parsea
- THEN se rechaza

### Scenario: fecha sin zona horaria
- GIVEN un RoE con `start: 2026-11-20T09:00:00` (sin zona)
- WHEN se parsea
- THEN se rechaza

### Scenario: mismo instante en zonas distintas (A7)
- GIVEN dos RoE con la misma ventana escrita en `-03:00` y en `Z`
- WHEN se emiten tokens en el mismo instante
- THEN ambos tienen la misma ventana en UTC

## Requirement: Las exclusiones prevalecen sobre el alcance
Un objetivo excluido DEBE bloquearse aunque esté dentro del alcance. Un RoE cuyas exclusiones cubren todo el alcance DEBE rechazarse.

### Scenario: host excluido dentro del CIDR autorizado
- GIVEN un RoE con alcance 10.99.0.0/24 y exclusión 10.99.0.1
- WHEN se invoca una acción sobre 10.99.0.1
- THEN se bloquea con `reason = excluded` y queda en bitácora

### Scenario: exclusión que anula todo
- GIVEN un RoE con alcance 10.99.0.0/24 y exclusión 10.99.0.0/24
- WHEN se parsea
- THEN se rechaza

## Requirement: Emisión por fase, con TTL y sin renovación automática
El emisor DEBE emitir un token por fase solo para fases del RoE, dentro de la ventana, con vencimiento `min(ahora + TTL de la fase, fin de la ventana)`. NO DEBE existir renovación automática. Toda emisión y todo rechazo DEBEN quedar en bitácora.

### Scenario: RoE válido
- GIVEN un RoE válido que autoriza `recon`
- WHEN se emite un token de `recon`
- THEN el token es de fase RECON, vence según el TTL de `policy.yaml` y hay un registro `token.issue` OK

### Scenario: fase no autorizada en el RoE
- GIVEN un RoE con `phases: [recon]`
- WHEN se pide un token de `validate`
- THEN se rechaza con `phase_not_in_roe` y queda registrado

### Scenario: fuera de la ventana
- GIVEN un RoE cuya ventana terminó
- WHEN se pide un token
- THEN se rechaza con `outside_window` y queda registrado

### Scenario: token vencido no se renueva
- GIVEN un token vencido
- WHEN se invoca una acción
- THEN se bloquea con `token_expired` y no se emite ningún token nuevo sin una llamada explícita al emisor

## Requirement: Integridad del token
El Harness DEBE aceptar solo tokens con MAC válido del emisor. Un token fabricado, alterado o de otro engagement NO DEBE habilitar acciones.

### Scenario: token fabricado
- GIVEN un ScopeToken creado a mano con alcance `0.0.0.0/0`
- WHEN se invoca una acción
- THEN se bloquea con `token_invalid` y queda registrado

### Scenario: token alterado
- GIVEN un token emitido para RECON al que se le cambia la fase a VALIDATE
- WHEN se invoca una acción de VALIDATE
- THEN se bloquea con `token_invalid`

### Scenario: ningún ScopeToken fuera del emisor
- GIVEN el código de `harness/`
- WHEN se buscan construcciones de `ScopeToken(`
- THEN solo aparecen en `harness/tokens.py`

## Requirement: Revocación del RoE
Revocar el RoE DEBE invalidar de inmediato todos los tokens del engagement, incluidos los vivos, e impedir nuevas emisiones.

### Scenario: token vivo después de revocar
- GIVEN un token vivo de `recon` y el RoE revocado
- WHEN se invoca una acción en alcance
- THEN se bloquea con `token_revoked`, y hay un registro `roe.revoke` con quién revocó
