# Delta — authorization (change 004)

Tests: tests/authorization/test_pinned_addresses.py, tests/authorization/test_review_004.py

## ADDED Requirement: La herramienta usa la IP que validó el Harness
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

## ADDED Requirement: Un nombre excluido también excluye sus IP
Al emitir el token, el emisor DEBE resolver cada nombre excluido del RoE y DEBE agregar sus IP a las exclusiones del token, cubiertas por su MAC. Así un host excluido por nombre NO DEBE alcanzarse por su IP ni por otro nombre que resuelva a ella. Si el nombre no resuelve al emitir, la emisión NO DEBE fallar por eso.

### Scenario: host excluido por nombre y alcanzado por IP
- GIVEN un RoE que excluye `juiceshop.lab.test`, que resuelve a 10.99.0.11
- WHEN se invoca una capability sobre `10.99.0.11` o sobre otro nombre que resuelve a esa IP
- THEN se bloquea con `excluded` y el adaptador no recibe la llamada

### Scenario: nombre excluido que no resuelve
- GIVEN un RoE que excluye un nombre que no resuelve al momento de emitir
- WHEN se emite el token
- THEN el token se emite y el nombre sigue excluido como texto

## ADDED Requirement: Rate limit por IP en el Harness
`Harness.invoke` DEBE limitar las invocaciones por IP de destino a `rate_limit_rps_per_target` de `policy.yaml`, antes de escribir el OK y de llamar al adaptador. El límite DEBE contarse por IP, no por nombre, para que dos nombres del mismo host compartan el presupuesto.

### Scenario: dos nombres, una IP
- GIVEN varios nombres que resuelven a la misma IP y un límite de 5 por segundo
- WHEN se piden 8 invocaciones, cada una con un nombre distinto o con la IP, en el mismo segundo
- THEN 5 pasan en ese segundo y las otras 3 esperan al siguiente
