# Delta — validation (change 010, tasks 2.6 y 2.7)

Tests: tests/demo/test_integrador.py

## ADDED Requirement: Las demos eligen la RoE entre las plantillas del repo
`demo/pipeline.py` DEBE aceptar `--roe pipeline|integrador` (por nombre, nunca una ruta) y por defecto DEBE usar `pipeline`. La RoE `integrador` DEBE exigir `--lab`: la simulación graba salidas de DVWA. Al importar una entrega, El engagement DEBE llamarse `demo-<plantilla>-…`. Al importar una entrega, `demo/validation.py` DEBE aceptar el RoE solo si coincide con la plantilla que indica el nombre del engagement (`demo/roe-pipeline.yaml` o `demo/roe-integrador.yaml`) salvo `engagement_id`, la ventana y el hash de aprobación, y DEBE rechazar una entrega de simulación con la RoE del integrador. Así una entrega forjada no cambia de target sin que cambie el nombre que ve el Reviewer.

### Scenario: entrega con la RoE del integrador
- GIVEN una entrega cuyo RoE es `demo/roe-integrador.yaml` con su engagement y una ventana sana
- WHEN se importa
- THEN se acepta

### Scenario: RoE del integrador modificada
- GIVEN esa entrega con `dvwa.lab.test` quitado de las exclusiones, o con el alcance ampliado a `10.99.0.0/24`, y el hash recalculado
- WHEN se importa
- THEN se rechaza porque no coincide con ninguna plantilla del repo

### Scenario: engagement de otra plantilla
- GIVEN una entrega del engagement `demo-pipeline-…` con la RoE del integrador (o al revés), o de un engagement sin prefijo conocido
- WHEN se importa
- THEN se rechaza

### Scenario: RoE elegida por ruta o integrador sin laboratorio
- GIVEN `--roe /tmp/mia.yaml`, o `--roe integrador` sin `--lab`
- WHEN corre `demo/pipeline.py`
- THEN termina con error, sin crear bitácora ni entrega

## ADDED Requirement: Procedencia del target del integrador
Cuando la RoE es la del integrador y corre contra el laboratorio, `demo/validation.py` DEBE registrar en la bitácora del host, antes de cualquier envío, el `Id` de la imagen `ptaas-phantomcorp` y el commit del repo del curso que se usó para construirla (`PTAAS_INTEGRADOR_CONTEXT` de `lab/.env`). Si alguno no se puede obtener (incluido un timeout o una ruta que no es absoluta), DEBE registrarse como `desconocido`, sin frenar la corrida. `git` corre sin shell, con `core.fsmonitor=false` y `--no-optional-locks`, porque el repo del curso es de terceros.

### Scenario: procedencia registrada
- GIVEN la imagen `ptaas-phantomcorp` con Id `sha256:<64 hex>` y el contexto en el commit `1234abc`
- WHEN corre la validación con la RoE del integrador en `--lab`
- THEN la bitácora tiene `target.provenance` con, en `target` (la evidencia solo admite `<ruta>#sha256=`), `ptaas-phantomcorp@sha256:<64 hex>` y `repo@1234abc`

### Scenario: sin `lab/.env` o sin imagen
- GIVEN que no hay `PTAAS_INTEGRADOR_CONTEXT`, `docker image inspect` o `git rev-parse` fallan, o devuelven algo que no es un hash (p. ej. caracteres de control)
- WHEN se calcula la procedencia
- THEN se registra `desconocido` en ese campo
