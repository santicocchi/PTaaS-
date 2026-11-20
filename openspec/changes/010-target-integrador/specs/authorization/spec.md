# Delta — authorization (change 010)

Tests: tests/authorization/test_integrador_scope.py

## MODIFIED Requirement: Alcance máximo del laboratorio
Cada CIDR del RoE DEBE estar contenido en `targets.lab_only_cidrs` y cada dominio DEBE ser igual o subdominio de `lab_only_domains`. `lab_only_domains` DEBE incluir `phantomcorp.lab.test` y `lab_only_cidrs` NO DEBE cambiar.

### Scenario: RoE del práctico integrador
- GIVEN `demo/roe-integrador.yaml` con `phantomcorp.lab.test` y `10.99.0.12/32`
- WHEN se parsea
- THEN se acepta

### Scenario: nombre corto o red del curso
- GIVEN un RoE con el dominio `phantomcorp` (sin `.lab.test`) o con un CIDR de `cyberlab_labnet` fuera de `10.99.0.0/24`
- WHEN se parsea
- THEN se rechaza indicando el valor fuera del laboratorio

## ADDED Requirement: El target del integrador vive solo en la red aislada
El servicio `phantomcorp` de `lab/docker-compose.yml` DEBE estar solo en la red `lab`, con IP dentro de `lab_only_cidrs`, y DEBE requerir el perfil `integrador`.

### Scenario: servicio bien declarado
- GIVEN `lab/docker-compose.yml`
- WHEN el test lo lee
- THEN `phantomcorp` tiene `profiles: [integrador]`, solo la red `lab`, IP `10.99.0.12` y alias `phantomcorp.lab.test`, solo las claves permitidas, y las IP fijas de los objetivos quedan fuera del `ip_range` dinámico

### Scenario: target conectado a la red de herramientas
- GIVEN un compose donde `phantomcorp` también está en `tools`
- WHEN corre el test
- THEN el test falla

## ADDED Requirement: Solo `phantomcorp` en el engagement integrador
Con la RoE del integrador, toda acción sobre DVWA o Juice Shop (por nombre o por IP) DEBE bloquearse y quedar en bitácora. El motivo es `out_of_scope`, porque no están en el alcance; además figuran en las exclusiones, que prevalecen si alguien amplía el alcance por error (`excluded`).

### Scenario: acción sobre DVWA durante el integrador
- GIVEN un token emitido desde `demo/roe-integrador.yaml`
- WHEN se invoca `httpx.probe` sobre `dvwa.lab.test`, `juiceshop.lab.test` o sus IP
- THEN se bloquea con `out_of_scope` o `excluded`, queda en bitácora como `BLOCKED` y el adaptador no recibe la llamada

### Scenario: alcance ampliado por error
- GIVEN la RoE del integrador con el alcance ampliado a `10.99.0.0/24` y los tres dominios
- WHEN se invoca sobre `dvwa.lab.test`, `juiceshop.lab.test`, `10.99.0.10` o `10.99.0.11`
- THEN se bloquea con `excluded`

### Scenario: nombre del integrador que resuelve fuera del alcance
- GIVEN `phantomcorp.lab.test` resolviendo a 10.99.0.50
- WHEN se invoca cualquier capability sobre ese nombre
- THEN se bloquea con `dns_out_of_scope`
