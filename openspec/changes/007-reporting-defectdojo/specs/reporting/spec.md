# Delta — reporting (change 007)

Tests: tests/reporting/test_required_fields.py, tests/reporting/test_cvss4.py, tests/reporting/test_build_from_audit.py, tests/reporting/test_validation_status.py, tests/reporting/test_structure.py, tests/reporting/test_redaction.py, tests/reporting/test_disclosure.py, tests/reporting/test_duplicates.py, tests/reporting/test_versioning.py, tests/reporting/test_defectdojo_export.py, tests/reporting/test_delivery_gate.py, tests/reporting/test_report_review_cli.py

## MODIFIED Requirement: Hallazgo completo
Cada hallazgo del informe, salvo los `discarded`, DEBE tener un CWE con la forma `CWE-<n>`, un vector CVSS v4.0 válido y una remediación no vacía, tomados de una entrada revisada de `data/report_catalog.yaml` (por CVE y, si no hay, por CWE). Una entrada sin revisor, con revisor `pendiente` o con revisor igual al autor NO DEBE usarse. Un puntaje CVSS 3.1 NO DEBE convertirse a 4.0. Si falta algún campo, el informe NO DEBE generarse ni escribirse ningún archivo, el error DEBE nombrar cada `finding_id` y cada campo faltante, y DEBE quedar un control `report.generation_failed` por hallazgo y campo.

### Scenario: hallazgo sin CWE
- GIVEN un hallazgo con CWE `unknown`
- WHEN se genera el informe
- THEN falla con `MissingField` que nombra el `finding_id` y el campo `cwe`, no existe `report-v1.json` y la bitácora tiene `report.generation_failed` ABORTED con motivo `missing_cwe` y `subject` igual al `finding_id`

### Scenario: hallazgo sin remediación
- GIVEN un hallazgo cuya entrada curada tiene `remediation` vacía o solo espacios
- WHEN se genera el informe
- THEN falla nombrando el campo `remediation` y no se escribe ningún archivo

### Scenario: CVE con puntaje 3.1 y sin vector curado
- GIVEN un hallazgo con `CVE-2021-41773`, `cvss_version` 3.1 y sin entrada curada para ese CVE ni para su CWE
- WHEN se genera el informe
- THEN falla nombrando el campo `cvss_v4_vector`

### Scenario: varios campos faltantes
- GIVEN dos hallazgos, uno sin CWE y otro sin remediación
- WHEN se genera el informe
- THEN el error nombra los dos `finding_id` con su campo y hay dos `report.generation_failed`

### Scenario: entrada curada sin revisar
- GIVEN una entrada de `data/report_catalog.yaml` con `reviewer` igual a `author`
- WHEN se genera el informe con un hallazgo de ese CWE
- THEN la entrada no se usa y el informe falla nombrando los campos que no tiene

## ADDED Requirement: Vector CVSS v4.0 válido y sin LLM
El vector DEBE validarse con un parser determinista: prefijo `CVSS:4.0/`, las 11 métricas base presentes una vez y en el orden de la especificación de FIRST, métricas opcionales como mucho una vez y en su orden, solo valores permitidos y sin salto de línea final. El puntaje DEBE calcularse desde el vector con el algoritmo de referencia de FIRST y la severidad DEBE salir del puntaje. Cada hallazgo DEBE mostrar vector, puntaje y severidad junto al EPSS con la fecha del snapshot.

### Scenario: vector válido
- GIVEN el vector `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`
- WHEN se valida
- THEN se acepta, el puntaje coincide con el de la calculadora de FIRST para ese vector y la severidad es `Critical`

### Scenario: vector con cola inventada
- GIVEN el vector base válido seguido de `/basura`
- WHEN se valida
- THEN se rechaza

### Scenario: métrica duplicada, faltante o fuera de orden
- GIVEN un vector con `AV:N` dos veces, otro sin `SA` y otro con `AC` antes de `AV`
- WHEN se validan
- THEN los tres se rechazan

### Scenario: valor no permitido o salto de línea final
- GIVEN un vector con `AV:X` y otro válido seguido de un salto de línea
- WHEN se validan
- THEN los dos se rechazan

### Scenario: vector 3.1
- GIVEN el vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- WHEN se valida como 4.0
- THEN se rechaza

### Scenario: EPSS junto al CVSS
- GIVEN un hallazgo con EPSS 0.973 y otro sin EPSS
- WHEN se genera el informe
- THEN el primero muestra `0.973` con la fecha del snapshot de feeds y el segundo muestra "sin dato"

## ADDED Requirement: Informe armado desde los hallazgos y la bitácora
El informe DEBE construirse desde los `PrioritizedVuln`, los `CandidateFinding` y la bitácora del engagement, con la cadena verificada antes de leerla. Cada referencia de evidencia del informe DEBE ser `ruta#sha256=<hex>` y DEBE verificar contra su archivo. Con la cadena rota, con una evidencia que no verifica, o con el engagement fuera de REPORT, el informe NO DEBE generarse.

### Scenario: evidencia del loop C en el informe
- GIVEN un hallazgo con un `validation.attempt` OK cuya evidencia verifica
- WHEN se genera el informe
- THEN el hallazgo lista esa referencia `ruta#sha256=<hex>` y el anexo B la incluye

### Scenario: evidencia alterada
- GIVEN un archivo de evidencia modificado después de registrarse
- WHEN se genera el informe
- THEN falla con `evidence_mismatch` nombrando la referencia y no se escribe ningún archivo

### Scenario: cadena rota
- GIVEN una bitácora con un registro intermedio alterado
- WHEN se genera el informe
- THEN se lanza `AuditIntegrityError` y no se escribe ningún archivo

### Scenario: engagement fuera de REPORT
- GIVEN un engagement en VALIDATE
- WHEN se genera el informe
- THEN falla con `engagement_not_in_report` y no se escribe ningún archivo

## ADDED Requirement: Validado y no validado visibles
El estado de validación de cada hallazgo DEBE salir de la bitácora: `validated` solo con un `validation.attempt` OK del hallazgo cuya evidencia verifica y tiene `result` `validated` y `truncated` falso. Todo otro caso DEBE mostrarse como "no validado" con su motivo (`no_catalog_entry`, `reviewer_rejected`, `reviewer_timeout`, `request_budget_exhausted`, bloqueo del Guard, verificación negativa, error del sandbox, pendiente de revisión o no intentado). Si el registro de aprobaciones dice `validated` y la bitácora no lo respalda, el informe NO DEBE generarse.

### Scenario: validado en sandbox
- GIVEN un hallazgo con un intento positivo registrado y su evidencia íntegra
- WHEN se genera el informe
- THEN el hallazgo dice "Validado en sandbox"

### Scenario: no validado por falta de revisión
- GIVEN un hallazgo con `validation.closed` motivo `reviewer_timeout`
- WHEN se genera el informe
- THEN el hallazgo dice "No validado" con el motivo "no validado por falta de revisión"

### Scenario: confirmado por análisis sin validar
- GIVEN un hallazgo `confirmed` del loop B sin ningún registro de validación
- WHEN se genera el informe
- THEN dice "confirmado por análisis, no validado en sandbox" y el motivo "no se intentó validar"

### Scenario: evidencia truncada
- GIVEN un `validation.attempt` OK cuya evidencia tiene `result` `validated` y `truncated: true`
- WHEN se genera el informe
- THEN el hallazgo no aparece como validado

### Scenario: cierre validado sin respaldo en la bitácora
- GIVEN un hallazgo con un cierre `validated` en `closures` y ningún `validation.attempt` positivo en la bitácora
- WHEN se genera el informe
- THEN falla con `validation_mismatch` y no se escribe ningún archivo

## ADDED Requirement: Hallazgo de severidad alta no validado
Un hallazgo `High` o `Critical` no validado DEBE aparecer en el informe con su severidad, en su lugar por prioridad, marcado "No validado: requiere verificación manual" con su motivo, listado aparte en la sección de riesgo y contado en el resumen ejecutivo. NO DEBE omitirse ni bajarse de severidad.

### Scenario: alto sin entrada en el catálogo
- GIVEN un hallazgo con severidad `High` y `validation.closed` motivo `no_catalog_entry`
- WHEN se genera el informe
- THEN aparece con severidad `High`, en el mismo orden que tendría si estuviera validado, con la marca de verificación manual, y la sección 7 y el resumen ejecutivo lo cuentan

## ADDED Requirement: Estructura PTES §7 y resumen ejecutivo
El informe DEBE tener, en este orden: resumen ejecutivo, introducción (alcance del RoE y metodología), recolección de información, evaluación de vulnerabilidades, confirmación en sandbox, post-explotación, riesgo y exposición, conclusión y los anexos de bitácora, evidencias, descartados, divulgación y reproducibilidad. El resumen ejecutivo DEBE armarse por plantilla, sin LLM, y NO DEBE contener `CVE-`, `CWE-`, `CVSS:`, direcciones IP, rutas de archivo ni referencias `#sha256=`. La sección de alcance NO DEBE incluir contactos de emergencia ni nombres de personas.

### Scenario: orden de las secciones
- GIVEN un informe generado
- WHEN se leen los títulos de primer nivel del markdown y las claves de secciones del JSON
- THEN aparecen en el orden indicado

### Scenario: resumen sin jerga
- GIVEN hallazgos con CVE, CWE, vector e IP
- WHEN se genera el resumen ejecutivo
- THEN no contiene ninguna de esas expresiones y sí la postura general y el conteo por severidad

### Scenario: postura general
- GIVEN un informe con un hallazgo `High` y ninguno `Critical`
- WHEN se genera el resumen ejecutivo
- THEN la postura general es "alta"

### Scenario: impacto curado con jerga
- GIVEN una entrada curada cuyo `business_impact` contiene `CWE-79`
- WHEN se genera el informe con un hallazgo de esa entrada
- THEN la entrada es inválida y el informe falla nombrando el campo `business_impact`

### Scenario: alcance sin datos de contacto
- GIVEN un RoE con contactos de emergencia y aprobador con nombre
- WHEN se genera el informe
- THEN el informe tiene el `roe_sha256` y la ventana en UTC, y no tiene los contactos ni el nombre del aprobador

## ADDED Requirement: Sin datos sensibles en el informe
Todo texto que entra al informe desde herramientas o evidencia DEBE pasar por la redacción, que reemplaza cada coincidencia de la lista de patrones de `harness/redaction.py` por `[redacted:<id>]`. Después, el JSON y el markdown completos DEBEN escanearse con la misma lista: si queda alguna coincidencia, el informe NO DEBE generarse y el error DEBE nombrar el patrón y la sección, nunca el valor. Los SHA-256 de 64 hex y los hashes cortos de 12 hex NO DEBEN tomarse como datos sensibles.

### Scenario: cookie con valor en la evidencia de una herramienta
- GIVEN una observación de ZAP cuya evidencia contiene `Set-Cookie: PHPSESSID=abc123; HttpOnly`
- WHEN se genera el informe
- THEN el informe no contiene `abc123` y contiene `[redacted:`

### Scenario: lista de patrones
- GIVEN un texto por patrón con `Authorization: Basic YWRtaW46cGFzc3dvcmQ=`, `Bearer eyJhbGciOi...`, un JWT, `password=s3cret`, `http://dvwa.lab.test/x?token=s3cret`, una clave PEM, `AKIAABCDEFGHIJKLMNOP`, `admin@juice-sh.op`, el MD5 `5f4dcc3b5aa765d61d8327deb882cf99`, un canario `ptaas1a2b3c4d` y `admin:password`
- WHEN se redacta
- THEN ningún valor queda en la salida

### Scenario: hashes de la bitácora intactos
- GIVEN una referencia `evidence/eng-1/f-1-1.json#sha256=<64 hex>` y un hash corto de 12 hex
- WHEN se escanea el informe
- THEN no hay coincidencias

### Scenario: dato sensible que no pasó por la redacción
- GIVEN un título de hallazgo que llega con `admin@juice-sh.op` por un campo que no se redacta
- WHEN se escanea el informe final
- THEN el informe no se genera, falla con `sensitive_data` nombrando el patrón `email` y la sección, y el mensaje no contiene el correo

## ADDED Requirement: Plantilla de divulgación ISO/IEC 29147 para el laboratorio
El informe DEBE incluir un aviso por hallazgo no descartado con identificador (huella), título, producto y versión afectados, descripción, impacto, severidad CVSS v4.0, estado de validación, remediación, referencias y línea de tiempo tomada de la bitácora. El estado de divulgación DEBE ser `not_applicable_lab` y el punto de contacto DEBE ser un rol. Un hallazgo sobre un host fuera del laboratorio NO DEBE tener plantilla y el informe NO DEBE generarse.

### Scenario: aviso de un hallazgo de DVWA
- GIVEN un hallazgo validado sobre `dvwa.lab.test`
- WHEN se genera el informe
- THEN el anexo D tiene su aviso con estado `not_applicable_lab`, la fecha del primer intento de validación tomada de la bitácora y ningún correo ni nombre de persona

### Scenario: host fuera del laboratorio
- GIVEN un hallazgo sobre `app.example.com`
- WHEN se genera el informe
- THEN falla con `not_lab_target` y no se escribe ningún archivo

## ADDED Requirement: Hallazgos duplicados entre ejecuciones
Cada hallazgo DEBE tener una huella determinista `fp1-<32 hex>` calculada solo desde `asset_id` y la clave (CVE o CWE), sin engagement, fechas, herramientas, puntajes ni evidencia. Dos hallazgos con la misma huella DEBEN fusionarse en uno, con la evidencia unida y todos los intentos de validación. Con informes anteriores entregados, cada hallazgo DEBE marcarse `new` o `recurring`, y las huellas anteriores ausentes DEBEN listarse como `not_observed`. Un informe anterior sin `report.delivered` con su SHA-256 en su propia bitácora NO DEBE usarse.

### Scenario: misma huella en dos engagements
- GIVEN el mismo CWE sobre el mismo activo en `eng-1` y `eng-2`
- WHEN se calcula la huella en cada uno
- THEN es la misma

### Scenario: huella distinta por activo o clave
- GIVEN el mismo CWE sobre dos activos distintos, y dos CWE sobre el mismo activo
- WHEN se calculan las huellas
- THEN las cuatro son distintas

### Scenario: dos corridas en el mismo engagement
- GIVEN dos hallazgos con la misma huella, uno con un intento negativo y otro con un intento positivo que verifica
- WHEN se genera el informe
- THEN hay un solo hallazgo, `validated`, con los dos intentos listados

### Scenario: hallazgo recurrente y no observado
- GIVEN `eng-1/report-v1` entregado con las huellas A y B, y `eng-2` con A y C
- WHEN se genera el informe de `eng-2` con `--previous eng-1/report-v1`
- THEN A es `recurring`, C es `new` y B aparece como `not_observed`, no como corregido

### Scenario: informe anterior no entregado o alterado
- GIVEN `eng-1/report-v1` sin `report.delivered`, o con un SHA-256 distinto del registrado
- WHEN se usa como `--previous`
- THEN se rechaza y el informe no se genera

## ADDED Requirement: Versiones inmutables y reproducibles
Cada informe DEBE escribirse como `report-v<N>.json` sin sobrescribir, con `N` igual a 1 más la cantidad de `report.generated` del engagement en la bitácora, y DEBE registrarse en la bitácora con `report.generated`, su referencia `ruta#sha256` y `subject` `report-v<N>`. El informe NO DEBE contener la hora de generación: su `as_of` DEBE ser la del registro `audit_seq`. Una versión nueva DEBE indicar la que reemplaza y los cambios por huella. `python -m harness.reporting reproduce` DEBE reconstruir la versión desde la bitácora hasta `audit_seq` y las entradas con hash, y salir con 0 solo si el JSON y el markdown coinciden byte a byte.

### Scenario: reproducción exacta
- GIVEN `report-v1` generado y registros agregados a la bitácora después
- WHEN se ejecuta `reproduce` para `report-v1`
- THEN sale con 0

### Scenario: snapshot de entradas alterado
- GIVEN `inputs-v1.json` modificado después de generar `report-v1`
- WHEN se ejecuta `reproduce`
- THEN sale con 1 indicando la referencia que no coincide

### Scenario: cambio en un hallazgo después de generar
- GIVEN `report-v1` generado y después una corrección de la remediación en la tabla curada
- WHEN se genera el informe otra vez
- THEN se escribe `report-v2` con `supersedes` igual a `report-v1` y su SHA-256, `changes` lista la huella como `modified` con el campo `remediation`, y `report-v1.json` queda igual

### Scenario: intento fallido no consume versión
- GIVEN un intento de generación fallido y después uno exitoso
- WHEN se generan
- THEN el exitoso es `report-v1`

### Scenario: archivo de la versión ya existente
- GIVEN un `report-v1.json` presente en disco sin `report.generated` en la bitácora
- WHEN se genera el informe
- THEN falla sin sobrescribir el archivo

## ADDED Requirement: Exportación a DefectDojo por lista permitida
La exportación DEBE armarse en formato Generic Findings Import con solo los campos de `DD_FIELDS`, desde el archivo de la versión aprobada y con su SHA-256 verificado. `verified` DEBE ser verdadero solo para hallazgos `validated`; la severidad DEBE salir del puntaje CVSS v4.0 y `unique_id_from_tool` DEBE ser la huella. La exportación NO DEBE contener contenido de evidencia, rutas locales, `sandbox_id`, IP de la red `tools`, parámetros de PoC, canarios, registros de la bitácora, decisiones ni nombres del Reviewer, datos del RoE, tokens, claves, el `rationale` del loop B, el anexo de divulgación ni los hallazgos `discarded`. El documento serializado DEBE escanearse con la lista de redacción y, ante una coincidencia, NO DEBE enviarse ni escribirse.

### Scenario: campos exportados
- GIVEN `report-v1` aprobado con un hallazgo validado y uno no validado
- WHEN se arma la exportación
- THEN cada hallazgo tiene solo claves de `DD_FIELDS`, el validado tiene `verified: true`, el otro `verified: false` y la etiqueta `not-validated`, y los dos tienen `unique_id_from_tool` igual a su huella

### Scenario: nada interno en la exportación
- GIVEN un informe con evidencia que tiene extracto, `sandbox_id` `ptaas-sbx-<uuid>`, parámetros de PoC, canario y decisiones del Reviewer
- WHEN se arma la exportación
- THEN el documento no contiene el extracto, `ptaas-sbx-`, los parámetros, el canario, `state/`, `evidence/`, `10.97.0.` ni el nombre del Reviewer

### Scenario: descartado y divulgación fuera
- GIVEN un informe con un hallazgo `discarded` y el anexo de divulgación
- WHEN se arma la exportación
- THEN no hay ningún hallazgo con esa huella ni texto `not_applicable_lab`

### Scenario: dato sensible en la exportación
- GIVEN un título curado que, por error, contiene un correo
- WHEN se arma la exportación
- THEN falla con `sensitive_data`, no se envía nada y no se escribe ningún archivo

### Scenario: archivo del informe cambiado después de aprobar
- GIVEN `report-v1` aprobado y su archivo modificado después
- WHEN se arma la exportación
- THEN falla porque el SHA-256 no coincide y no se envía nada

### Scenario: modo sin instancia
- GIVEN un RoE sin `report_destinations` y `report-v1` aprobado
- WHEN se entrega con los sockets bloqueados
- THEN se escribe `defectdojo-report-v1.json` en formato Generic Findings Import, no se abre ninguna conexión y la bitácora tiene `report.delivered` con modo `offline` y la referencia del archivo

## MODIFIED Requirement: Entrega con aprobación
El informe NO DEBE entregarse, ni por API ni como archivo, sin una aprobación vigente del Reviewer para la última versión y su SHA-256, respaldada por un control `hitl.approve_delivery` en la bitácora. Ningún llamador DEBE poder declarar la aprobación con un valor propio. Sin aprobación, la entrega DEBE registrar `report.delivery` PENDING_HITL con `subject` igual al `report_id` y el engagement DEBE quedar en REPORT. Una aprobación NO DEBE darse por defecto ni por tiempo.

### Scenario: entrega sin aprobación
- GIVEN un informe generado y sin aprobación
- WHEN se intenta entregar
- THEN se lanza `DeliveryNotApproved`, el estado permanece en REPORT, se registra `report.delivery` PENDING_HITL y no se exporta nada

### Scenario: aprobación de una versión anterior
- GIVEN `report-v1` aprobado y después `report-v2` generado
- WHEN se intenta entregar
- THEN se registra PENDING_HITL para `report-v2` y no se exporta nada

### Scenario: aprobación vencida
- GIVEN una aprobación de `report-v1` con más de `approval_ttl_minutes`
- WHEN se intenta entregar
- THEN se trata como sin aprobación y no se exporta nada

### Scenario: aprobación insertada sin la CLI
- GIVEN una fila de aprobación de `report-v1` escrita en el registro sin control en la bitácora
- WHEN se intenta entregar
- THEN se registra PENDING_HITL y no se exporta nada

### Scenario: aprobación revocada
- GIVEN una aprobación de `report-v1` y después un rechazo
- WHEN se intenta entregar
- THEN no se exporta nada y el estado permanece en REPORT

### Scenario: API anterior con booleano
- GIVEN el código de `harness/`
- WHEN se busca una función de entrega que reciba la aprobación como parámetro booleano
- THEN no existe

## ADDED Requirement: CLI de aprobación del informe
`python -m harness.review report` DEBE listar la última versión con su hash corto, sus conteos y los hallazgos altos no validados, y registrar aprobaciones y rechazos con reviewer y motivo obligatorios, en el registro de aprobaciones y en la bitácora (`hitl.approve_delivery` / `hitl.reject_delivery`, `subject` = `report_id`). `approve` DEBE exigir `--sha256` con el hash que mostró `list` y DEBE exigir `--ack-unvalidated-high` si el informe tiene hallazgos `High` o `Critical` no validados. La fila y el control DEBEN escribirse juntos o ninguno. Ante cualquier fallo, la CLI NO DEBE escribir nada.

### Scenario: aprobar sin reconocer altos no validados
- GIVEN `report-v1` con un hallazgo `High` no validado
- WHEN se ejecuta `report approve report-v1 --sha256 <hash>` sin `--ack-unvalidated-high`
- THEN falla indicando la opción faltante y no escribe nada

### Scenario: aprobar con reconocimiento
- GIVEN el mismo informe
- WHEN se ejecuta `report approve` con `--ack-unvalidated-high`, reviewer y motivo
- THEN la fila tiene `ack_unvalidated_high` verdadero y la bitácora tiene `hitl.approve_delivery` con `subject` `report-v1`

### Scenario: aprobar con otro hash
- GIVEN `report-v1` en disco
- WHEN se ejecuta `report approve` con un `--sha256` distinto del que mostró `list`
- THEN falla y no escribe nada

### Scenario: aprobar una versión que no es la última
- GIVEN `report-v1` y `report-v2`
- WHEN se ejecuta `report approve report-v1`
- THEN falla y no escribe nada

### Scenario: aprobar sin motivo
- GIVEN `report-v1`
- WHEN se ejecuta `report approve` con motivo vacío
- THEN falla y no escribe nada

### Scenario: la bitácora falla
- GIVEN una bitácora que no acepta escrituras
- WHEN se ejecuta `report approve`
- THEN la CLI sale con error 3 indicando que la decisión NO quedó registrada, y no hay fila ni control
