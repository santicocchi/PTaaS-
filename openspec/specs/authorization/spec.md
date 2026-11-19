# Delta — authorization

Tests: tests/test_authorization.py, tests/test_roe_and_tokens.py, tests/test_red_team_guard.py, tests/authorization/test_pinned_addresses.py, tests/authorization/test_review_004.py

## Requirement: Enforcement de alcance
El sistema DEBE rechazar toda acción activa sobre un activo fuera del RoE vigente.

### Scenario: activo fuera de alcance
- GIVEN un RoE que autoriza 10.0.0.0/24
- WHEN un agente intenta escanear 10.0.1.5
- THEN la acción es bloqueada y registrada en la bitácora

## Requirement: Vigencia del token
El sistema NO DEBE ejecutar acciones con un scope token vencido.

### Scenario: token vencido
- GIVEN un token cuya ventana terminó
- WHEN un agente invoca una acción en el activo autorizado
- THEN la acción es bloqueada (BLOCKED) y registrada

## Requirement: Fase del token
Un token DEBE habilitar únicamente acciones de su fase.

### Scenario: acción de otra fase
- GIVEN un token de fase ANALYZE
- WHEN se invoca una acción de VALIDATE
- THEN la acción es bloqueada y registrada

## Requirement: Kill switch
El sistema DEBE detener toda ejecución al activar el kill switch.

### Scenario: kill switch activo
- GIVEN un engagement en curso y el kill switch activado
- WHEN cualquier agente invoca una acción
- THEN se registra ABORTED y no se ejecuta la herramienta

<!-- Archivado desde el change 003-roe-and-tokens (Tests: tests/test_roe_and_tokens.py) -->

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

<!-- Archivado desde el change 008-spec-hardening -->

## Requirement: Aprobación humana atada a engagement y fase
Una aprobación humana DEBE identificar engagement, fase, acción y objetivo. Una aprobación NO DEBE habilitar la acción en otro engagement ni en otra fase.

### Scenario: aprobación reutilizada en otro engagement
- GIVEN una aprobación de `poc_catalog.run_parametrized` sobre `dvwa.lab.test` en el engagement `eng-1`
- WHEN un agente del engagement `eng-2` invoca la misma acción sobre el mismo objetivo
- THEN el resultado es PENDING_HITL, la herramienta no se ejecuta y queda en bitácora

### Scenario: aprobación válida
- GIVEN una aprobación para `eng-1`, fase VALIDATE, acción y objetivo
- WHEN un agente de `eng-1` invoca esa acción en fase VALIDATE
- THEN la acción se ejecuta y se registra OK

## Requirement: Normalización del objetivo
El Guard DEBE normalizar el objetivo antes de decidir: minúsculas, sin espacios ni punto final; una IPv4 mapeada a IPv6 DEBE evaluarse como IPv4. Un objetivo que no se puede interpretar DEBE bloquearse.

### Scenario: hostname con mayúsculas y punto final
- GIVEN un token que autoriza `lab.example.test`
- WHEN se invoca una acción sobre `HOST.Lab.Example.Test.`
- THEN la decisión es la misma que para `host.lab.example.test` (OK)

### Scenario: IPv4 fuera de alcance escrita como IPv6 mapeada
- GIVEN un token que autoriza 10.0.0.0/24
- WHEN se invoca una acción sobre `::ffff:10.0.1.5`
- THEN la acción es bloqueada y registrada

### Scenario: objetivo con puerto, esquema o ruta
- GIVEN un token que autoriza `lab.example.test`
- WHEN se invoca una acción sobre `http://lab.example.test:80/x`
- THEN la acción es bloqueada: el objetivo debe ser un host o una IP

## Requirement: Token emitido por el harness
El harness DEBE aceptar solo tokens emitidos por su emisor (integridad verificable). Un token construido o modificado fuera del emisor NO DEBE habilitar acciones. (Implementación: change 003.)

### Scenario: token fabricado
- GIVEN un ScopeToken creado a mano con alcance 0.0.0.0/0
- WHEN un agente invoca una acción con ese token
- THEN la acción es bloqueada y registrada como token inválido

### Scenario: token alterado
- GIVEN un token emitido para la fase RECON
- WHEN se cambia su fase a VALIDATE y se usa
- THEN la acción es bloqueada y registrada como token inválido

<!-- Archivado desde el change 009-red-team-guard -->

## Requirement: El gate humano lo decide la política
Toda acción en una fase listada en `gates_hitl` de `policy.yaml` DEBE exigir aprobación humana, sin importar lo que declare la Action.

### Scenario: validación declarada sin aprobación (R13)
- GIVEN un token de VALIDATE y una Action con `requires_human_approval=False`
- WHEN un agente la invoca sin aprobación registrada
- THEN el resultado es PENDING_HITL y la herramienta no se ejecuta

## Requirement: Lo destructivo lo declara el adaptador
El Harness DEBE bloquear toda acción cuyo adaptador sea destructivo o no lo declare, aunque la Action diga lo contrario.

### Scenario: adaptador destructivo con Action no destructiva (R14)
- GIVEN un adaptador con `destructive=True`
- WHEN se invoca con una Action `destructive=False`
- THEN se bloquea con `reason = destructive`

## Requirement: Un nombre autorizado debe resolver dentro del alcance
Antes de actuar sobre un nombre, el Harness DEBE resolverlo y exigir que todas sus IP estén en los CIDR del token y no estén excluidas. Si no resuelve, DEBE bloquear.

### Scenario: nombre que resuelve fuera de alcance (A4)
- GIVEN un token que autoriza `lab.example.test` y 10.0.0.0/24
- WHEN `app.lab.example.test` resuelve a 8.8.8.8, o a 10.0.0.7 y 10.0.1.7
- THEN se bloquea con `dns_out_of_scope`

### Scenario: nombre que resuelve a un host excluido
- GIVEN una exclusión 10.0.0.1
- WHEN el nombre resuelve a 10.0.0.1
- THEN se bloquea con `excluded`

### Scenario: nombre que no resuelve
- GIVEN un nombre sin registros DNS
- WHEN se invoca una acción sobre él
- THEN se bloquea con `dns_unresolved`

<!-- Archivado desde el change 004-recon-loop-a -->

## Requirement: La herramienta usa la IP que validó el Harness
Después de validar la resolución de un nombre, el Harness DEBE pasarle al adaptador las IP validadas (`addresses`). Si el objetivo es una IP, `addresses` DEBE ser esa IP. Un adaptador que se conecta al objetivo NO DEBE dejar que la herramienta resuelva el nombre de nuevo.

### Scenario: DNS rebinding entre la validación y la ejecución
- GIVEN un nombre que resuelve a 10.0.0.50 cuando lo valida el Harness y a 8.8.8.8 en la consulta siguiente
- WHEN se invoca `httpx.probe` o `nmap.service_scan` sobre ese nombre
- THEN el comando lleva 10.0.0.50 y no el nombre, y el resolver se consultó una sola vez

### Scenario: objetivo que ya es una IP
- GIVEN el objetivo 10.0.0.5
- WHEN se invoca un adaptador
- THEN recibe `addresses = ("10.0.0.5",)` y el resolver no se consulta

### Scenario: adaptador que no acepta las direcciones
- GIVEN un adaptador cuyo `run` no recibe `addresses`
- WHEN corre el test de contrato de adaptadores
- THEN el test falla

## Requirement: Un nombre excluido también excluye sus IP
Al emitir el token, el emisor DEBE resolver cada nombre excluido del RoE y DEBE agregar sus IP a las exclusiones del token, cubiertas por su MAC. Así un host excluido por nombre NO DEBE alcanzarse por su IP ni por otro nombre que resuelva a ella. Si el nombre no resuelve al emitir, la emisión NO DEBE fallar por eso.

### Scenario: host excluido por nombre y alcanzado por IP
- GIVEN un RoE que excluye `juiceshop.lab.test`, que resuelve a 10.99.0.11
- WHEN se invoca una capability sobre `10.99.0.11` o sobre otro nombre que resuelve a esa IP
- THEN se bloquea con `excluded` y el adaptador no recibe la llamada

### Scenario: nombre excluido que no resuelve
- GIVEN un RoE que excluye un nombre que no resuelve al momento de emitir
- WHEN se emite el token
- THEN el token se emite y el nombre sigue excluido como texto

## Requirement: Rate limit por IP en el Harness
`Harness.invoke` DEBE limitar las invocaciones por IP de destino a `rate_limit_rps_per_target` de `policy.yaml`, antes de escribir el OK y de llamar al adaptador. El límite DEBE contarse por IP, no por nombre, para que dos nombres del mismo host compartan el presupuesto.

### Scenario: dos nombres, una IP
- GIVEN varios nombres que resuelven a la misma IP y un límite de 5 por segundo
- WHEN se piden 8 invocaciones, cada una con un nombre distinto o con la IP, en el mismo segundo
- THEN 5 pasan en ese segundo y las otras 3 esperan al siguiente
