# Spec — vuln-analysis

Tests: tests/test_schemas.py, tests/test_engagement_and_loops.py, tests/test_authorization.py, tests/vuln_analysis/test_loop_b.py, tests/vuln_analysis/test_resolution.py

## Requirement: Análisis no destructivo
El análisis DEBE usar solo capabilities marcadas `destructive: false`.

### Scenario: capability destructiva
- GIVEN un adaptador con `destructive: true`
- WHEN el agente intenta usarlo en fase ANALYZE
- THEN el harness lo bloquea y lo registra

## Requirement: Análisis no valida explotabilidad
El análisis NO DEBE ejecutar PoCs ni acciones de fase VALIDATE.

### Scenario: acción de validación en ANALYZE
- GIVEN un token de fase ANALYZE
- WHEN se invoca `poc_catalog.run_parametrized`
- THEN la acción es bloqueada por fase y registrada

## Requirement: Estado explícito por hallazgo
Cada candidato analizado DEBE resolverse como `confirmed`, `discarded` o `inconclusive`, con justificación y referencias de evidencia.

### Scenario: resultado sin justificación
- GIVEN un `PrioritizedVuln` sin `rationale`
- WHEN se intenta persistir
- THEN se rechaza por schema inválido

<!-- Modificado por el change 005-correlation-analysis-loop-b -->
## Requirement: Priorización con CVSS v4, EPSS y contexto
La prioridad DEBE derivarse de forma reproducible con `0.6·CVSS + 2.5·EPSS + 0.25·criticidad`.
- El CVSS DEBE ser el puntaje base disponible (4.0 o, si no hay, 3.1) y el resultado DEBE indicar su versión.
- La criticidad DEBE salir del RoE y valer 3 si falta, con el `rationale` diciéndolo.
- Sin CVSS NO DEBE calcularse una prioridad numérica: el hallazgo va al final como "sin puntaje".

### Scenario: mismos insumos, misma prioridad
- GIVEN dos corridas con idénticos insumos
- WHEN se calcula la prioridad
- THEN el resultado es idéntico

### Scenario: hallazgo sin CVSS
- GIVEN un hallazgo CWE-693 de ZAP sin CVE ni CVSS
- WHEN se prioriza
- THEN no tiene prioridad numérica y queda después de todos los que sí tienen

<!-- Modificado por el change 005-correlation-analysis-loop-b -->
## Requirement: Loop de detección acotado
El loop B DEBE avanzar por candidato con un plan fijo de verificaciones: primero los templates de nuclei cuya clasificación coincide con su CWE o tecnología, después ZAP sobre el servicio. ZAP DEBE correr como mucho una vez por servicio y por corrida. El loop DEBE detenerse:
- con hallazgo resuelto;
- tras dos iteraciones sin información nueva;
- al alcanzar `max_loop_iterations.detection`;
- sin reintentar, si el Harness aborta (kill switch, bitácora rota, token vencido o revocado).

Su estado DEBE persistirse append-only, y el tope DEBE contar entre corridas.

### Scenario: sin ganancia de información
- GIVEN dos iteraciones consecutivas sin evidencia nueva
- WHEN el agente evalúa continuar
- THEN `LoopDecision` es `stop` y el hallazgo queda `inconclusive`

### Scenario: ZAP una vez por servicio
- GIVEN tres candidatos sobre `http://dvwa.lab.test:80`
- WHEN corre el loop B
- THEN `zap.baseline_scan` se invoca una sola vez sobre ese servicio

### Scenario: reinicio a mitad del loop
- GIVEN un loop B cortado en la iteración 2 de un candidato
- WHEN se vuelve a correr
- THEN retoma la iteración 2 de ese candidato y no reinicia el tope

## Requirement: Reintento y escalado
Ante dos salidas con schema inválido, el sistema DEBE escalar a HITL.

### Scenario: schema inválido repetido
- GIVEN dos respuestas consecutivas que no validan
- WHEN se procesa la tercera solicitud
- THEN el estado pasa a PENDING_HITL y no se reintenta

<!-- Archivado desde el change 005-correlation-analysis-loop-b -->

## Requirement: Una versión sola no confirma
Un candidato cuya única evidencia es la versión reportada NO DEBE resolverse como `confirmed`. Para confirmarlo hace falta evidencia de una herramienta de análisis con confianza alta, o una verificación del catálogo en VALIDATE.

### Scenario: CVE por versión sin evidencia de análisis
- GIVEN un candidato por CVE con evidencia solo de versión
- WHEN el loop B termina sin evidencia de nuclei ni de ZAP
- THEN queda `inconclusive` y no `confirmed`

### Scenario: evidencia del mismo CWE que el CVE
- GIVEN un candidato por CVE con CWE-693 y una alerta de ZAP de confianza alta por falta de CSP (CWE-693)
- WHEN se resuelve el candidato por CVE
- THEN queda `inconclusive`: la evidencia de una clase de debilidad no prueba el CVE, y confirma solo su propio candidato por CWE

## Requirement: Análisis solo con el engagement en ANALYZE
El loop B DEBE recibir el engagement y NO DEBE invocar ninguna capability si su estado no es `ANALYZE`, al que solo se llega pasando por el gate `first_active_action`. El token de fase no alcanza.

### Scenario: token ANALYZE válido y engagement en CORRELATE
- GIVEN un token de fase ANALYZE vigente y un engagement en `CORRELATE`
- WHEN se arranca el loop B
- THEN no se invoca nuclei ni ZAP y el resultado dice "engagement fuera de ANALYZE"

## Requirement: Resolución con reglas fijas
- Un candidato DEBE quedar `confirmed` solo con evidencia de análisis de confianza alta: un template de nuclei que matcheó o una alerta de ZAP con confianza High o Confirmed.
- DEBE quedar `discarded` solo si coincide con una entrada de la lista revisada de falsos positivos, y el `rationale` DEBE citarla.
- Que una herramienta no encuentre nada NO DEBE descartar un candidato.

### Scenario: dos herramientas coinciden
- GIVEN la alerta 10038 de ZAP y el template `ptaas-missing-csp` sobre la misma URL
- WHEN se resuelve el candidato CWE-693
- THEN queda `confirmed` con las dos evidencias

### Scenario: falso positivo conocido
- GIVEN una alerta que coincide con una entrada de `data/false_positives.yaml`
- WHEN se resuelve
- THEN queda `discarded`, el `rationale` cita la entrada y el hallazgo sigue en el informe

### Scenario: silencio de la herramienta
- GIVEN un candidato CWE-1021 y una corrida de nuclei sin resultados
- WHEN se resuelve
- THEN no queda `discarded`

## Requirement: Contradicciones
Si dos verificaciones equivalentes (según la tabla curada de equivalencias) corrieron sobre la misma URL y una marcó el problema y la otra no, el candidato DEBE quedar `inconclusive`, DEBE nombrar las dos verificaciones en el `rationale` y DEBE marcarse para revisión humana. NO DEBE descartarse por contradicción.

### Scenario: ZAP marca y nuclei no
- GIVEN la alerta 10038 de ZAP sobre `/` y el template equivalente `ptaas-missing-csp` sin resultado sobre `/`
- WHEN se resuelve el candidato
- THEN queda `inconclusive`, para revisión humana, con las dos verificaciones citadas

## Requirement: Lista de falsos positivos revisada
Cada entrada de `data/false_positives.yaml` DEBE tener id, herramienta, regla o template, patrón de URL, motivo, revisor y fecha. Una entrada NO DEBE aplicar a un candidato con CVE ni a uno de riesgo alto.

### Scenario: entrada que intenta tapar un CVE
- GIVEN una entrada de falso positivo que coincide con un candidato por CVE
- WHEN se carga la lista o se resuelve el candidato
- THEN la entrada no se aplica y el test de la lista falla
