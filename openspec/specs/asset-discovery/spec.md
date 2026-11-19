# Spec — asset-discovery

Tests: tests/test_engagement_and_loops.py, tests/asset_discovery/test_recon_loop.py, tests/asset_discovery/test_asset_graph.py, tests/asset_discovery/test_rate_limit.py

<!-- Archivado desde el change 004-recon-loop-a (reemplaza los requisitos anteriores, que modificó) -->

## Requirement: Relevamiento solo dentro de alcance
El sistema DEBE descubrir únicamente activos cubiertos por el scope token vigente. Antes de encolar un activo descubierto, el orquestador DEBE consultar al Guard. Un activo fuera de alcance o excluido DEBE guardarse en el grafo con `in_scope = false` y su motivo, DEBE quedar en la bitácora (`asset.discovered`, `BLOCKED`) y NO DEBE llegar a ningún adaptador.

### Scenario: subdominio fuera de alcance
- GIVEN un token que autoriza `lab.example.test`
- WHEN el recon descubre `otro.ejemplo.org` como referencia
- THEN el activo se registra como "fuera de alcance", no se sondea y queda en bitácora

### Scenario: descubrimiento excluido
- GIVEN un RoE que excluye `juiceshop.lab.test`
- WHEN subfinder lo devuelve como subdominio
- THEN queda en el grafo con `in_scope = false` y motivo `excluded`, y no se encola

### Scenario: el orquestador encola por error un activo fuera de alcance
- GIVEN un orquestador con el filtro de alcance desactivado (test de defensa en profundidad)
- WHEN intenta sondear `203.0.113.7`
- THEN `Harness.invoke` lo bloquea con `out_of_scope` y el adaptador no recibe la llamada

## Requirement: Pasivo antes que activo
En cada iteración, el orquestador DEBE ejecutar las capabilities pasivas antes que las activas, y NO DEBE ejecutar ninguna si el engagement no está en `RECON` (lo que exige la aprobación `first_active_action`).

### Scenario: orden de técnicas
- GIVEN un dominio autorizado sin inventario previo
- WHEN comienza el relevamiento
- THEN las capabilities pasivas se ejecutan antes que las activas

### Scenario: engagement sin aprobación de la primera acción activa
- GIVEN un engagement en `AUTHORIZED`
- WHEN se arranca el loop A
- THEN no se invoca ninguna capability y el loop termina con motivo "engagement fuera de RECON"

## Requirement: Modelo de grafo de activos
El sistema DEBE producir un `AssetGraph` con, por activo: id determinista (SHA-256 de `tipo:dirección` normalizada), tipo (`domain`, `ip` o `http_service`), dirección, tecnologías detectadas, herramienta de origen, iteración en la que apareció y si está en alcance.

### Scenario: activo sin herramienta de origen
- GIVEN un activo propuesto sin `source_tool`
- WHEN se intenta incorporarlo al grafo
- THEN se rechaza por schema inválido

### Scenario: el mismo activo descubierto dos veces
- GIVEN `DVWA.lab.test.` devuelto por subfinder y `dvwa.lab.test` devuelto por httpx
- WHEN se incorporan al grafo
- THEN queda un solo activo y la segunda vez no cuenta como nuevo

## Requirement: Grafo persistido, append-only y versionado por iteración
El grafo DEBE persistirse por engagement en SQLite append-only. La versión del grafo DEBE ser el número de iteración y los activos nuevos de una iteración DEBEN ser los insertados en ella.

### Scenario: reinicio entre iteraciones
- GIVEN un grafo con 3 activos de la iteración 1
- WHEN se reabre el grafo en otro proceso
- THEN tiene los mismos 3 activos y la próxima iteración es la 2

### Scenario: intento de modificar el grafo
- GIVEN un grafo persistido
- WHEN se intenta UPDATE o DELETE sobre la tabla de activos
- THEN la base lo rechaza

## Requirement: Loop de relevamiento acotado
El loop A DEBE detenerse cuando no aparezcan activos nuevos o al alcanzar el tope de iteraciones de `policy.yaml`. También DEBE detenerse, sin reintentar, si el Harness aborta (kill switch, bitácora rota, token vencido o revocado).

### Scenario: sin activos nuevos
- GIVEN una iteración que no agrega activos al grafo
- WHEN el agente evalúa continuar
- THEN `LoopDecision` es `stop` con motivo "grafo estabilizado"

### Scenario: tope alcanzado
- GIVEN que se llegó a `max_loop_iterations.recon`
- WHEN el agente propone otra iteración
- THEN el harness la rechaza y el engagement avanza de fase

### Scenario: kill switch durante el loop
- GIVEN un loop A en la iteración 2
- WHEN se activa el kill switch del engagement
- THEN el loop se detiene en la acción siguiente, no reintenta y termina con motivo "abortado"

## Requirement: Una herramienta que falla no rompe el loop
Si una herramienta devuelve error o salida inválida, el orquestador DEBE dejarlo en la bitácora (`tool.error`, `ABORTED`, con el tipo de error) y DEBE seguir con los demás activos y herramientas. Dos salidas inválidas seguidas de la misma herramienta DEBEN escalar a HITL y esa herramienta NO DEBE volver a usarse en el engagement.

### Scenario: subfinder sin salida a internet
- GIVEN subfinder devolviendo vacío en el laboratorio
- WHEN corre la iteración 1
- THEN el loop sigue con httpx y nmap sobre las semillas del RoE

### Scenario: httpx con timeout
- GIVEN httpx que excede su timeout sobre un host
- WHEN corre la iteración
- THEN queda `tool.error` con motivo `timeout` y nmap igual corre sobre ese host

## Requirement: Respeto del rate limit
El sistema NO DEBE superar `rate_limit_rps_per_target`, ni en las solicitudes de cada herramienta ni en las invocaciones del orquestador sobre un mismo objetivo.

### Scenario: ráfaga de sondeos
- GIVEN un límite de 5 rps por target
- WHEN el adaptador intenta emitir más de 5 solicitudes por segundo
- THEN el adaptador se auto-limita y no excede el umbral

### Scenario: ráfaga de invocaciones del orquestador
- GIVEN un límite de 5 por segundo y un reloj de prueba
- WHEN el orquestador pide 8 invocaciones sobre el mismo host en el mismo segundo
- THEN 5 pasan en ese segundo y las otras 3 esperan al siguiente (el límite lo aplica `Harness.invoke` por IP, ver authorization)

## Requirement: Entrega a correlación
Cuando el loop A termina, el sistema DEBE entregar a correlación los activos en alcance que tengan al menos una tecnología con versión. Los activos fuera de alcance NO DEBEN entregarse.

### Scenario: activo con versión
- GIVEN `dvwa.lab.test` con la tecnología `Apache HTTP Server:2.4.25`
- WHEN el loop A termina
- THEN se entrega como candidato de `cve.lookup`

### Scenario: activo fuera de alcance con versión
- GIVEN `203.0.113.7` en el grafo con `in_scope = false` y una tecnología con versión
- WHEN el loop A termina
- THEN no se entrega

### Scenario: el alcance cambió desde el descubrimiento
- GIVEN `www.dvwa.lab.test` guardado en alcance y un token nuevo que lo excluye
- WHEN se pide la entrega con ese token
- THEN `www.dvwa.lab.test` no se entrega: la entrega vuelve a consultar al Guard

## Requirement: El estado del loop sobrevive a un reinicio
El grafo DEBE persistir, además de los activos, el estado del loop: qué iteraciones terminaron, el motivo de parada y las herramientas deshabilitadas por HITL. Al reabrir el engagement, el orquestador DEBE retomar desde ese estado: el tope de iteraciones cuenta entre corridas, un loop terminado no se vuelve a correr y una herramienta escalada sigue deshabilitada.

### Scenario: el tope vale entre corridas
- GIVEN un tope de 2 iteraciones y un loop que ya lo alcanzó
- WHEN se vuelve a correr el loop
- THEN no se ejecuta ninguna iteración nueva y termina con "tope de iteraciones alcanzado"

### Scenario: corte a mitad de una iteración
- GIVEN un loop que se cortó durante la iteración 2, antes de marcarla terminada
- WHEN se vuelve a correr
- THEN repite la iteración 2 sobre la misma frontera y no la saltea

### Scenario: herramienta escalada y reinicio
- GIVEN httpx deshabilitado por dos salidas inválidas seguidas
- WHEN se reabre el engagement y se corre el loop
- THEN httpx no se invoca

## Requirement: Un dato malformado de la herramienta no tumba el loop
Un `Location` u otro dato de la salida que no se pueda interpretar DEBE descartarse sin cortar el loop.

### Scenario: Location malformado
- GIVEN una respuesta 302 con `Location: http://[::1` o con un puerto inválido
- WHEN el orquestador procesa la salida de httpx
- THEN la redirección se descarta y el loop sigue
