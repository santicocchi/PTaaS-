# Design — Change 007: informe completo y DefectDojo

## Contexto
Al terminar el loop C (006), cada hallazgo tiene su estado de análisis (`confirmed`, `inconclusive` o `discarded`, en `PrioritizedVuln`) y su historia de validación en la bitácora: intentos `validation.attempt` con evidencia `ruta#sha256=<hex>`, cierres `validation.closed` con motivo y decisiones `hitl.*` del Reviewer. Hoy `harness/reporting.py` solo valida tres campos de un `Finding` armado a mano, con una expresión CVSS laxa (`(/.+)?$` acepta cualquier cola), y `deliver(report, reviewer_approved: bool)` confía en un booleano que pasa el llamador. No hay nada que arme el informe desde la bitácora, que lo versione, que lo redacte ni que lo exporte.

Además faltan datos: `PrioritizedVuln` no tiene vector CVSS, CWE ni remediación; `CandidateFinding` tiene CWE y un puntaje de feed con su versión (005 D5: nunca se convierte), pero ningún vector. El feed guarda solo `baseScore`.

```
bitácora (cadena íntegra) ─┐
FindingStore (loop B) ─────┤  snapshot sellado     ┌──────────────────────────┐
evidencia (sha256) ────────┼──▶ inputs-vN.json ───▶│ ReportBuilder (sin LLM)  │──▶ report-vN.json (canónico)
tabla curada de informe ───┘                       │ valida, redacta, versiona│      └─▶ report-vN.md (derivado)
                                                   └──────────────────────────┘
                                     report.generated (OK, subject=report-vN, evidence=ref)
                                                               │
                         CLI del Reviewer: report approve report-vN --sha256 <12 hex>
                                     hitl.approve_delivery (subject=report-vN)
                                                               │
                ┌──────────────────────────────────────────────┴──────────────────────┐
                ▼                                                                     ▼
 Harness.invoke(defectdojo.export, target=destino del RoE,             sin destino autorizado:
 token de REPORT, subject=report-vN) ─▶ POST /api/v2/import-scan/      archivo Generic Findings Import
                └──────────────────────────────┬──────────────────────────────────────┘
                                               ▼
                         report.delivered (OK) ─▶ REPORT → DELIVERED
```

## Decisiones

### D1. Generador determinista; el LLM no escribe el informe en este change
`harness/reporting.py` define `ReportBuilder`: recibe la bitácora, el `FindingStore`, el directorio de estado y la tabla curada, y produce el informe por reglas. Igual que los loops B y C (006 D1), el agente `reporting` de `models.yaml` llega después y solo podrá **proponer** texto; ese texto entraría como artefacto con hash, revisado por el Reviewer, y la reproducción usaría el texto guardado, no una nueva generación. En este change no hay LLM en el camino del informe.

- **Por qué:** con `temperature: 0.3` dos corridas dan textos distintos y el criterio 4 ("reproducible a partir de la bitácora") no se cumple.
- **Rechazado:** dejar que el LLM redacte el resumen ejecutivo y guardar solo su salida. Funcionaría para reproducir, pero mete contenido no revisado en lo que se entrega; queda para un change propio con su gate.

### D2. Fuentes del informe y reproducibilidad
El informe es una función pura de: los registros de la bitácora hasta `audit_seq`, un snapshot sellado de las entradas, los archivos de evidencia referenciados y la tabla curada.

- **La bitácora manda para la validación.** El estado de validación de cada hallazgo sale **solo** de la bitácora (D6), no de la tabla `closures` del registro de aprobaciones, que queda como caché.
- **Snapshot sellado.** El `FindingStore` del loop B no está en la cadena. Al generar, el builder escribe `state/reports/<engagement>/inputs-v<N>.json` (con `open("xb")`, como la evidencia de 006 D7) con los `PrioritizedVuln`, los `CandidateFinding` y las observaciones usadas. El informe guarda la referencia `ruta#sha256` de ese snapshot; el informe a su vez queda en la bitácora con su SHA-256. Alterar el snapshot rompe la coincidencia con el informe; alterar el informe rompe la coincidencia con la bitácora.
- **Otras entradas con hash:** SHA-256 de la tabla curada, `catalog_version`, SHA-256 del manifiesto de feeds y de `policy.yaml`, y `generator_version` (constante del módulo).
- **Sin reloj.** El informe no contiene la hora de generación: su `as_of` es el `ts` del registro `audit_seq`. JSON canónico (`sort_keys`, `separators=(",", ":")`, UTF-8, `ensure_ascii=False`), números con formato fijo (un decimal para CVSS, tres para EPSS), orden fijo de hallazgos: `(priority is None, -priority, finding_id)`, igual que el loop B.
- **Markdown derivado.** `report-v<N>.md` se renderiza desde el JSON; no es fuente de nada.
- **Comando de reproducción:** `python -m harness.reporting reproduce --engagement <id> --report report-v<N>` verifica la cadena, verifica cada referencia, vuelve a construir con los registros hasta `audit_seq` y compara byte a byte el JSON y el markdown. Sale 0 si coinciden y 1 si no, indicando el primer campo distinto.
- **Rechazado:** que el loop B escriba cada observación como evidencia con hash en el momento. Es más fuerte (la observación quedaría anclada cuando ocurre, no al generar el informe), pero toca los loops A y B; queda como riesgo aceptado.

### D3. Campos obligatorios y tabla curada del informe
Cada hallazgo del informe (todos menos los `discarded`, ver D7) DEBE tener CWE, vector CVSS v4.0 válido y remediación. Ninguno de los tres sale del LLM ni de un texto libre de una herramienta: salen de `data/report_catalog.yaml`, una tabla curada y revisada como la lista de falsos positivos (005 D10) y la allow-list de templates (005 D9).

- **Clave:** `CVE-AAAA-N` si el candidato tiene CVE; si no, `CWE-N`. Primero se busca por CVE y después por CWE.
- **Campos de cada entrada:** `title`, `technical_description`, `business_impact` (lenguaje no técnico, D8), `remediation`, `references` (por ejemplo `WSTG-CONF-07`), `cvss_v4_vector`, `author`, `reviewer`, `date`.
- **Entrada válida:** `reviewer` no vacío, distinto de `pendiente` y distinto de `author` (sin distinguir mayúsculas, como la lista de falsos positivos); `author`, `reviewer`, `date` y `cvss_v4_vector` son texto (una fecha YAML sin comillas no vale). Una entrada sin revisar no existe para el builder.
- **CWE:** sale del candidato y DEBE cumplir `^CWE-[1-9][0-9]{0,4}\Z`. `unknown` no es un CWE.
  - **CWE curado (decisión del 20/11):** una entrada por CVE puede traer `cwe`. Se usa solo si el feed no trae CWE (`unknown`, como los CVE que NVD publica sin CWE). Si el feed trae otro distinto, el informe falla con `cwe`: no se elige uno. En una entrada por CWE el campo `cwe` hace inválida la entrada. Así el CWE sigue saliendo de una persona que revisó la tabla, no del LLM ni del texto del feed.
  - **Simulación:** los CVE sintéticos del feed de prueba (`CVE-2099-…`) tienen sus entradas en `demo/report_catalog_sim.yaml`, que `demo/report.py` suma solo mientras el manifiesto de `data/feeds/` diga `synthetic: true` (en simulación y con `--lab`, porque los dos usan el mismo snapshot). No entran a la tabla del repo.
- **Sin conversión de CVSS.** Un CVE con solo puntaje 3.1 en el feed no se convierte a 4.0 (005 D5). Si la tabla no tiene un vector 4.0 para ese CVE (o para su CWE), el informe no se genera.
- **Fallo:** si falta algo, no se escribe ningún archivo de informe, se lanza `MissingField` con el `finding_id` y el nombre del campo (`cwe`, `cvss_v4_vector` o `remediation`) y queda un control `report.generation_failed` ABORTED con motivo `missing_cwe`, `invalid_cvss_vector` o `missing_remediation` y `subject` = `finding_id` (uno por hallazgo y campo, en orden). El builder junta todos los faltantes antes de fallar: el error lista todos, no solo el primero.
  - Sin CWE válido (y sin CVE) no hay entrada que buscar: el faltante es solo `cwe`, sin sumar el vector y la remediación de ese hallazgo.
  - Sin entrada para la clave: faltan `cvss_v4_vector` y `remediation`.
  - Con una entrada que existe pero no vale: se nombran los campos por los que no vale (`reviewer`, `title`, `date`...). Los que no son `cwe`, `cvss_v4_vector` ni `remediation` se registran con el motivo `invalid_catalog_entry`, así la bitácora dice el motivo real.
- **Rechazado:** tomar el `vectorString` 4.0 del NVD. El snapshot de feeds no lo guarda hoy y agregarlo toca la capability `correlation`; queda para otro change. Mientras tanto, un CVE sin entrada curada hace fallar el informe, que es lo que pide el criterio 1.

### D4. Validación del vector CVSS v4.0 sin LLM
`harness/cvss4.py` define `parse_vector(text) -> Cvss4Vector` y lanza `InvalidVector` con el motivo. Reglas, todas deterministas:

1. Prefijo exacto `CVSS:4.0/`. Sin espacios, sin minúsculas en claves ni valores, sin salto de línea final (`\Z`, 006 A5).
2. Las 11 métricas base, **todas, una vez y en este orden**: `AV:[NALP]`, `AC:[LH]`, `AT:[NP]`, `PR:[NLH]`, `UI:[NPA]`, `VC:[HLN]`, `VI:[HLN]`, `VA:[HLN]`, `SC:[HLN]`, `SI:[HLN]`, `SA:[HLN]`.
3. Métricas opcionales, como mucho una vez cada una y en el orden de la especificación de FIRST: `E:[XAPU]`, `CR/IR/AR:[XHML]`, `MAV:[XNALP]`, `MAC:[XLH]`, `MAT:[XNP]`, `MPR:[XNLH]`, `MUI:[XNPA]`, `MVC/MVI/MVA:[XHLN]`, `MSC:[XHLN]`, `MSI/MSA:[XSHLN]`, `S:[XNP]`, `AU:[XNY]`, `R:[XAUI]`, `V:[XDC]`, `RE:[XLMH]`, `U:(X|Clear|Green|Amber|Red)`.
4. Cualquier otra clave, valor, separador vacío o duplicado: inválido.

El puntaje se calcula con el algoritmo de referencia de FIRST (macrovectores y tabla de búsqueda), probado contra vectores de ejemplo de la calculadora oficial. La severidad sale del puntaje: 0.0 `None`, 0.1–3.9 `Low`, 4.0–6.9 `Medium`, 7.0–8.9 `High`, 9.0–10.0 `Critical`. Si el candidato trae un puntaje 4.0 del feed y difiere del calculado, el informe muestra los dos y marca la diferencia; manda el calculado desde el vector curado.

- **Presentación con EPSS:** cada hallazgo muestra vector, puntaje, severidad y, al lado, EPSS con la fecha del snapshot. Sin EPSS: "sin dato". Con `feed_stale`: "dato desactualizado".
- **Rechazado:** la expresión actual (`CVSS4_RE`), que acepta `CVSS:4.0/AV:N/.../SA:N/basura`. Se reemplaza por el parser.
- **Puntaje:** lo calcula la biblioteca `cvss==3.4` (fijada en `requirements.txt`, decisión del 2026-11-20), solo con un vector que ya pasó el parser propio. Con métricas de amenaza o ambientales distintas de `X` el puntaje deja de ser el base, así que el informe muestra la nomenclatura de FIRST (`CVSS-B`, `CVSS-BT`, `CVSS-BE` o `CVSS-BTE`) junto al puntaje.
- **Puntaje del feed:** solo se compara con el calculado si el del mismo candidato es 4.0; un 3.1 se muestra, pero nunca se marca como "distinto".

### D5. Estructura PTES §7
El JSON del informe tiene estas secciones, en este orden, y el markdown las renderiza con los mismos títulos:

| # | Sección | Contenido |
|---|---|---|
| 1 | Resumen ejecutivo | D8. |
| 2 | Informe técnico — Introducción | Alcance del RoE (CIDR, dominios, exclusiones, ventana en UTC, `roe_sha256`, rol del aprobador; sin contactos ni nombres) y metodología (PTES, NIST SP 800-115, OWASP WSTG, CVSS v4.0, EPSS, CWE). |
| 3 | Recolección de información | Activos del grafo en alcance (host, puertos, tecnologías), con la cantidad de registros OK de RECON en la bitácora. |
| 4 | Evaluación de vulnerabilidades | Hallazgos priorizados (D3, D4, D6), con huella (D10) y evidencia por referencia. |
| 5 | Confirmación en sandbox | Por hallazgo: estado de validación, intentos, `poc_id`, `catalog_version` y referencias de evidencia. Sin parámetros ni canario. |
| 6 | Post-explotación | Texto fijo: fuera del alcance; no se realiza explotación (regla dura 4). |
| 7 | Riesgo y exposición | Conteo por severidad y estado de validación; hallazgos de severidad alta no validados (D7). |
| 8 | Conclusión | Texto armado por plantilla desde los conteos. |
| A | Anexo: bitácora | Conteo por resultado (OK, BLOCKED, PENDING_HITL, ABORTED), `audit_seq`, hash de ese registro y el comando de verificación. |
| B | Anexo: evidencias | Cada referencia `ruta#sha256` usada. |
| C | Anexo: descartados | Hallazgos `discarded` con el id de la entrada de falsos positivos que los descartó. |
| D | Anexo: divulgación | Plantilla ISO/IEC 29147 por hallazgo (D11). |
| E | Anexo: reproducibilidad | Entradas con hash (D2), `generator_version`, versión anterior que reemplaza y cambios (D9). |

### D6. Validado y no validado, desde la bitácora
Para cada hallazgo, recorriendo la bitácora hasta `audit_seq`:

- **`validated`**: existe un `validation.attempt` OK con `subject` = `finding_id` cuya evidencia verifica (`verify_evidence`) y tiene `result: "validated"` y `truncated: false`. Se muestra "Validado en sandbox".
- **Cada intento tiene que venir del loop C real** (revisión de seguridad, B1). Para todo `validation.attempt` del hallazgo: lo registró `validation-orchestrator`; antes hay un `poc_catalog.run_parametrized` OK en fase `validate` con el mismo `subject` (el registro write-ahead de `Harness.invoke`), y los intentos nunca son más que esos envíos; su evidencia está en `evidence/<engagement>/<finding_id>-<n>.json` y el documento dice `finding_id` = `subject`. Un intento sin envío previo o de otro agente falla con `validation_mismatch`; una evidencia de otro hallazgo, de otro engagement, borrada, alterada o que no es JSON falla con `evidence_mismatch`, aunque el intento sea ABORTED.
- **`not_validated`**, con motivo visible, en este orden de precedencia:
  1. `validation.closed` con su motivo: `no_catalog_entry` ("sin verificación en el catálogo"), `reviewer_rejected` ("validación rechazada por el Reviewer"), `reviewer_timeout` ("no validado por falta de revisión", 006 D5), `request_budget_exhausted` ("presupuesto de validación agotado");
  2. un BLOCKED de `poc_catalog.run_parametrized` con ese `subject` (por ejemplo `dns_out_of_scope`): "bloqueado por alcance";
  3. intentos que verifican pero ninguno positivo: "verificación negativa"; todos ABORTED: "error del sandbox";
  4. el último pedido o decisión del Reviewer: un PENDING_HITL sin decisión posterior es "pendiente de revisión"; un `hitl.reject` posterior sin cierre, "validación rechazada por el Reviewer"; un `hitl.approve` sin intento, "aprobado, sin intento registrado";
  5. nada de lo anterior (por ejemplo, el engagement no pasó por VALIDATE): "no se intentó validar".
- **Evidencia que no verifica:** si un `validation.attempt` referencia un archivo que no existe o cuyo SHA-256 no coincide, el informe no se genera (`evidence_mismatch`, nombrando la referencia). Una evidencia alterada nunca se degrada en silencio a "no validado".
- **Desacuerdo con el registro:** si `closures` dice `validated` y la bitácora no, el informe no se genera (`validation_mismatch`). Ante la duda, no se afirma una validación.
- El estado de análisis (`confirmed` / `inconclusive`) se muestra aparte del de validación: un `confirmed` no validado dice "confirmado por análisis, no validado en sandbox".

### D7. Hallazgo "no validado" de severidad alta
Respuesta a "¿cómo se trata un hallazgo no validado de severidad alta?":

- **Se informa siempre y con su severidad.** No se omite, no se baja de severidad y no se mueve al final: el orden sigue siendo por prioridad (D2).
- **Va marcado.** En la sección 4 lleva "No validado: requiere verificación manual" y el motivo (D6). La sección 7 los lista aparte y el resumen ejecutivo los cuenta en una línea propia.
- **El Reviewer lo reconoce de forma explícita.** Si el informe tiene hallazgos `High` o `Critical` no validados, `report approve` exige `--ack-unvalidated-high`; sin esa opción falla y no escribe nada. La lista se muestra en `report list`.
- **En DefectDojo** sale con su severidad, `verified: false` y la etiqueta `not-validated` (D12). Solo un `validated` sale con `verified: true`.
- **Los `discarded`** no son hallazgos del informe: van al anexo C. El loop B ya impide descartar por la lista de falsos positivos una observación de riesgo `High` (005).
- **Rechazado:** bloquear la entrega mientras haya altos sin validar. Un hallazgo sin entrada en el catálogo nunca podría validarse y el engagement quedaría trabado en REPORT; se prefiere que la persona lo reconozca y quede en la bitácora.

### D8. Resumen ejecutivo para audiencia no técnica
Plantilla determinista en español, armada desde los conteos y el campo `business_impact` de la tabla curada:

- nivel de riesgo general por regla fija: "crítico" si hay algún `Critical`, "alto" si hay algún `High`, "medio" si hay algún `Medium`, "bajo" en otro caso (en el recorrido del laboratorio "la postura es alta" se leía como algo bueno);
- conteo por severidad, separando validados y no validados;
- los tres hallazgos distintos de mayor prioridad (el mismo en varios hosts cuenta una vez), con su `business_impact`, sin identificadores técnicos;
- recomendaciones resumidas: la primera oración de la remediación de esos tres;
- una línea con los altos no validados (D7).

El resumen NO DEBE contener `CVE-`, `CWE-`, `CVSS:`, direcciones IP, rutas de archivo ni referencias `#sha256=`. Un test lo controla con esas expresiones. Si un `business_impact` curado las contiene, la entrada de la tabla es inválida.

### D9. Versionado del informe
Respuesta a "¿cómo se versiona un informe si cambia un hallazgo después de generado?":

- **Cada versión es inmutable.** `report-v<N>.json` se escribe con `open("xb")`; nunca se sobrescribe. `N` = 1 + cantidad de `report.generated` del engagement en la bitácora (sobrevive reinicios), que tienen que ser `report-v1`, `report-v2`... en orden (si no, `version_conflict`). Un intento fallido no consume número.
- **Todo fallo queda en la bitácora**, salvo con la cadena rota (ahí no se escribe nada): un archivo de la versión que ya existe es `version_conflict`, un error que no es de los previstos es `internal_error`. Si falla la escritura de un archivo o el `report.generated` después de escribir, los archivos de esa versión se borran (todavía no son una versión) para que el próximo intento no choque para siempre.
- **Cambiar algo es una versión nueva.** Dentro de REPORT no corren los loops, así que lo que cambia es la tabla curada, la lista de falsos positivos o lo que el Reviewer pidió al rechazar. Una versión nueva lleva `supersedes: {report_id, sha256}` y `changes`: por huella (D10), `added`, `removed` o `modified` con la lista de campos que cambiaron, calculado de forma determinista contra la versión anterior.
- **La aprobación es por versión y por hash.** Aprobar `report-v1` no aprueba `report-v2`. Solo se puede aprobar y entregar la **última** versión: generar una nueva deja sin efecto la aprobación de la anterior aunque no haya vencido.
- **Después de DELIVERED** no se generan versiones nuevas en ese engagement (`engagement_delivered`); una fe de erratas queda fuera de este change. Como `Engagement` no persiste, alcanza con un `report.delivered` OK en la bitácora para que falle, aunque el estado en memoria diga REPORT.
- **Rechazado:** un único informe que se actualiza en el lugar con un historial adentro. No hay forma de probar qué versión vio el Reviewer.

### D10. Hallazgos duplicados: huella determinista
- **Huella:** `fp1-` + los primeros 32 hex del SHA-256 del JSON canónico `{"v":1,"asset":<asset_id>,"key":<CVE o CWE>}`. `asset_id` ya es determinista y no depende del engagement (`harness/assets.py`); `key` es la misma clave del `dedupe` de `schemas.py`. No entran fechas, herramientas, puntajes, evidencia ni el `engagement_id`.
- **Dentro de un engagement:** `dedupe` ya junta por `(asset_id, CVE|CWE)`. Si igual llegan al builder dos hallazgos con la misma huella, se fusionan: unión ordenada de evidencia, la confianza mayor y el estado de validación más fuerte que la bitácora respalde (`validated` gana solo con evidencia que verifica). Todos los intentos de todas las corridas se muestran; no se promedian (006 D9).
- **Entre engagements:** `--previous <engagement>/<report-id>` (repetible) carga informes entregados de otros engagements. Cada uno se acepta solo si su bitácora verifica y tiene un `report.delivered` de ese informe con ese SHA-256. Cada hallazgo queda `new` o `recurring` (con el engagement y la versión donde apareció) y el informe lista como `not_observed` las huellas anteriores que ya no aparecen. "No observado" no es "corregido": el texto lo dice así.
- **En DefectDojo:** la huella va en `unique_id_from_tool`, para que la deduplicación de DefectDojo use la misma identidad.

### D11. Plantilla de divulgación ISO/IEC 29147 para hallazgos del laboratorio
Anexo D, un aviso por hallazgo no descartado, con: identificador (huella), título, producto afectado y versión (tecnologías del activo en el grafo), descripción, impacto, severidad (vector y puntaje CVSS v4.0), estado de validación, remediación o mitigación, referencias (CWE y WSTG) y línea de tiempo tomada de la bitácora (primer registro OK de análisis del host, primer intento de validación, versión del informe).

- **Estado de divulgación fijo:** `not_applicable_lab` ("objetivo intencionalmente vulnerable del laboratorio: no se notifica al fabricante"). Un host fuera de `lab_only_domains`/`lab_only_cidrs` no tiene plantilla: el builder falla con `not_lab_target`. Por el RoE eso no debería pasar; el control es defensa en profundidad.
- **Punto de contacto:** un rol ("equipo de divulgación del servicio"), nunca un nombre ni un correo.
- **Distribución:** la plantilla es parte del informe y NO se exporta a DefectDojo.

### D12. Qué sale hacia DefectDojo y qué no
Respuesta a "¿qué información NO debe salir del sistema hacia DefectDojo?".

La exportación se arma con una **lista permitida** de campos (`DD_FIELDS` en `harness/defectdojo.py`), no quitando campos de algo más grande. Por hallazgo no descartado:

| Campo de Generic Findings Import | Valor |
|---|---|
| `title` | título curado |
| `severity` | severidad del puntaje CVSS v4.0 (`Critical`/`High`/`Medium`/`Low`/`Info`) |
| `description` | descripción técnica curada + vector y puntaje CVSS v4.0 + EPSS con fecha + estado de validación y motivo + `report_id` y SHA-256 del informe + SHA-256 de cada evidencia (sin ruta) |
| `mitigation` | remediación curada |
| `impact` | `business_impact` curado |
| `references` | CWE y WSTG |
| `cwe` | número del CWE |
| `vulnerability_ids` | el CVE, si hay |
| `date` | fecha (UTC) de `as_of` |
| `active` / `verified` / `false_p` | `true` / `true` solo si `validated` / `false` |
| `unique_id_from_tool` | huella (D10) |
| `component_name` / `component_version` | tecnología del activo, si la hay |
| `endpoints` | host y puerto del hallazgo, sin query ni fragmento |
| `tags` | `ptaas`, `validated` o `not-validated` y el motivo de D6 |

NO sale, aunque esté en el informe o en el estado:
- contenido de la evidencia: extractos, cuerpos, encabezados de respuesta y nombres o atributos de cookies (solo viaja el SHA-256 del archivo);
- rutas locales (`state/...`, `evidence/...`), `sandbox_id`, nombres de contenedores e IP de la red `tools` o del runner;
- parámetros de la PoC, canarios y solicitudes armadas (cómo reproducir queda en el informe, no en una herramienta de terceros);
- registros de la bitácora, hashes de la cadena salvo el del informe, decisiones del Reviewer, sus nombres y sus motivos;
- datos del RoE: contactos de emergencia, aprobador, criticidad de activos y exclusiones;
- tokens, MAC, claves (la de DefectDojo viaja solo en el encabezado `Authorization`), y el `rationale` interno del loop B;
- el anexo de divulgación (D11) y los hallazgos `discarded`.

Después de armar el documento, el escáner de D13 corre sobre todo el JSON serializado. Una coincidencia aborta la exportación (`sensitive_data`) y no se envía ni se escribe nada.

### D13. Redacción de datos sensibles
`harness/redaction.py` reúne las reglas. Reutiliza las de la evidencia (006 D7): `Authorization`, `Cookie` y `Set-Cookie` como `[redacted]`, cookies sin valor y `Location` sin query ni fragmento. Se suma una lista de patrones, todos con expresión fija (la tabla resume; la lista vigente es la del código):

| Id | Qué detecta | Expresión (resumen) |
|---|---|---|
| `auth-header` | encabezado de autorización con valor, hasta el fin de línea | `(?i)\bauthorization\s*:[ \t]*\S[^\r\n]*` |
| `bearer` | token bearer | `(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*` |
| `cookie-value` | encabezado de cookie con valor, hasta el fin de línea (todos los pares) | `(?i)\b(set-)?cookie\s*:[ \t]*[^\s;=]+=[^\r\n]*` |
| `api-key-header` | encabezado de clave sin `=` (`X-API-Key: ...`) | `(?i)\b(x-api-key|api-key|x-auth-token|x-access-token)\s*:[ \t]*\S[^\r\n]*` |
| `session-id` | identificadores de sesión conocidos | `(?i)\b(PHPSESSID|JSESSIONID|connect\.sid|token)=[^;&\s]+` |
| `jwt` | JWT | `\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*` |
| `credential-param` | credencial en query o formulario | `(?i)\b(password|passwd|pwd|pass|secret|api[_-]?key|access[_-]?token)=[^&\s]+` |
| `url-query` | query o fragmento en una URL | `\bhttps?://[^\s?#]+[?#]\S*` |
| `private-key` | clave privada PEM | `-----BEGIN [A-Z ]*PRIVATE KEY-----` |
| `aws-key` | clave de acceso AWS | `\bAKIA[0-9A-Z]{16}\b` |
| `email` | correo electrónico (usuarios del lab, contactos) | `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b` |
| `md5-hash` | hash MD5 suelto (contraseñas de DVWA) | `(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])`; el escaneo final tolera la huella `fp1-<32 hex>` que arma el builder, la redacción no |
| `canary` | canario de una validación | `ptaas[0-9a-f]{8}` |
| `lab-default-cred` | credenciales por defecto del lab | `(?i)\badmin\s*[:/]\s*(password|admin123)\b` |

- **Dos pasos.** (1) Cada campo de texto libre que entra al informe (títulos y textos de herramientas, extractos) pasa por `redact()`, que reemplaza cada coincidencia por `[redacted:<id>]`. Los textos curados no se redactan: se validan, y una entrada curada con una coincidencia es inválida. (2) Sobre el JSON y el markdown finales corre `scan()`: si queda **alguna** coincidencia, el informe no se genera (`sensitive_data`, con el id del patrón y la sección, nunca el valor).
- **Lo que no es sensible y se permite:** los SHA-256 de 64 hex (el patrón MD5 no los toca por los límites de la expresión), los hashes cortos de 12 hex y las IP y nombres del laboratorio en alcance.
- **El snapshot de entradas también.** `inputs-v<N>.json` es inmutable y su hash va en el informe, así que lo sensible no puede entrar ni ahí: guarda solo las observaciones usadas (host y CWE de los hallazgos), con `check_id`, `url` y `evidence` redactados, igual que el `rationale`, el `title` y las `evidence_refs` de los hallazgos, y pasa por `scan()` antes de escribirse.
- **Markdown:** el texto de una herramienta va como código en línea, en una sola línea y sin acentos graves, para que un `<script>` o un `# 9.` de la evidencia no se interprete como HTML ni como título.
- **El extracto de 512 bytes** de la evidencia de 006 (riesgo aceptado allí) entra al informe solo redactado y nunca a DefectDojo.
- La lista vive en código, con un test por patrón (positivo y negativo). Agregar un patrón es un cambio revisado por el `security-reviewer`.

### D14. Gate de entrega con la CLI del Reviewer
Se reutiliza el mecanismo de 006 (D5, D6), con un sujeto distinto: el `report_id` (`report-v<N>`, que cumple `SUBJECT_RE` y no choca con los `finding_id`, que empiezan con `f-`).

- **Registro:** `state/<engagement>.approvals.sqlite3` gana la tabla append-only `delivery_decisions` (`report_id`, `decision`, `reviewer`, `reason`, `decided_at`, `expires_at`, `report_sha256`, `ack_unvalidated_high`). Mismos triggers contra UPDATE y DELETE.
- **CLI:** `python -m harness.review --engagement <id> report list | report approve <report_id> --sha256 <12 hex> [--ack-unvalidated-high] --reviewer <n> --reason "<t>" | report reject <report_id> --reviewer <n> --reason "<t>"`. `list` muestra la última versión, su hash corto, sus conteos y los altos no validados. `approve` falla sin escribir si la versión no es la última, si el hash no coincide, si el archivo no verifica contra la bitácora, si falta `--ack-unvalidated-high` cuando hace falta, o si motivo o reviewer están vacíos.
- **Bitácora:** `hitl.approve_delivery` / `hitl.reject_delivery`, agente `reviewer:<n>`, `subject` = `report_id`, evidencia = referencia hasheada de la fila con su número (006 A3). Fila y control juntos o ninguno (006 M5, error 3).
- **La bitácora manda:** la decisión vigente es el control `hitl.*_delivery` más nuevo para ese `report_id` y la única fila que respalda. Una fila sin control no habilita nada (006 M1).
- **Vencimiento:** `gates_hitl` `before: deliver` gana `approval_ttl_minutes` (60). Vencida vale lo mismo que ninguna. Nunca se aprueba por defecto ni por tiempo.
- **Sin aprobación:** `deliver` registra el control `report.delivery` PENDING_HITL con `subject` = `report_id`, lanza `DeliveryNotApproved` y el engagement queda en REPORT. Esto reemplaza al `deliver(report, reviewer_approved: bool)` actual: ningún llamador puede declarar la aprobación con un booleano.
- **Implementación:** `harness/delivery.py` (`deliver`, `check_delivery_decision`, `record_delivery_decision`), la tabla en `harness/approvals.py` y el subcomando `report` de `harness/review.py`. `report list` muestra el estado (`pending`, `approved`, `rejected`, `expired` o `delivered`).
- **Resumen de la entrega:** `report.delivered` apunta a `reports/<engagement>/delivered-<report_id>.json`, que guarda el `report_id`, el SHA-256 del informe, el modo, el destino, la referencia de la exportación y la de la aprobación. Así `--previous` (D10) puede comprobar que lo entregado es exactamente esa versión.
- **Fallos de la entrega:** `report.delivery` ABORTED con motivo (`killswitch`, `sensitive_data`, `evidence_mismatch`, `timeout`, `exec_error`, `invalid_output`, `adapter_error`, `out_of_scope`). `out_of_scope` cubre el token de REPORT que no se emite y el bloqueo del Guard en el envío; el motivo exacto queda en el `token.issue` o la acción BLOCKED. Las precondiciones sin intento (engagement fuera de REPORT, `report.delivered` ya en la bitácora, ningún informe generado) se rechazan sin registro: no hubo acción. La bitácora manda: si ya hay `report.delivered`, no se vuelve a entregar aunque el estado en memoria sea REPORT. El kill switch se vuelve a mirar después del envío.

### D15. Exportación a DefectDojo por `Harness.invoke`
`harness/adapters/defectdojo_adapter.py` define `DefectDojoExport`: `name = "defectdojo.export"`, `allowed_phases = (Phase.REPORT,)`, `destructive = False`, con `run_subject(action, target, token, addresses, subject)`.

- **El destino lo autoriza el RoE.** El RoE gana `report_destinations` (por ahora uno solo: `host`, `ip` como IP o CIDR /32, `port` y `dd_engagement_id`), contenido en `targets.report_destination_domains` / `report_destination_cidrs` de `profiles.yaml` (la red `tools`, 10.97.0.0/24). El emisor arma el token de REPORT con **solo** esos destinos como alcance, no con los objetivos: en REPORT ninguna acción puede tocar un objetivo del laboratorio (I4). El Guard no cambia: decide por el token, igual que siempre.
- **El gate lo decide la política.** `gates_hitl` `before: deliver` gana `capabilities: [defectdojo.export]` y `Guard.needs_approval` lo consulta, sin importar lo que declare la Action (009 R13). Sin `subject`: `missing_subject`.
- **Envío atado a lo aprobado.** Como en 006, el orquestador de entrega carga la aprobación en el Guard solo para ese envío y la retira después, y le pasa al adaptador el `report_id` y el SHA-256 aprobados. El adaptador vuelve a leer el archivo, verifica el SHA-256 y arma la exportación desde ese archivo; si no coincide, no envía.
- **Una sola llamada fija:** `POST /api/v2/import-scan/` con `scan_type=Generic Findings Import`, el id de engagement del RoE, `close_old_findings=false` y el archivo de D12. A la IP fijada por el Harness, con `Host: <nombre>`, sin redirecciones, con timeout (`reporting.defectdojo.timeout_s`), respuesta acotada (`max_response_bytes`) y sin variables de proxy.
- **Clave:** `PTAAS_DEFECTDOJO_API_KEY` del entorno, sin valor por defecto, en el encabezado `Authorization: Token <clave>`, nunca en la URL, en la bitácora ni en la evidencia. Sin clave: error tipado y no se envía nada.
- **Errores tipados:** `timeout`, `exec_error` (conexión), `invalid_output` (respuesta no 2xx o no JSON). El engagement queda en REPORT; con la aprobación todavía vigente se puede reintentar (la deduplicación por `unique_id_from_tool` evita duplicados en DefectDojo).
- **Evidencia del envío:** `reports/<engagement>/export-<report_id>.json` con el SHA-256 del documento enviado, el código HTTP, el id de test que devolvió DefectDojo y los conteos. Sin la clave ni el cuerpo completo de la respuesta.

### D16. Modo sin instancia: archivo de importación
Si el RoE no tiene `report_destinations`, la entrega escribe `state/reports/<engagement>/defectdojo-<report_id>.json` en formato Generic Findings Import, con el mismo armado de D12 y el mismo escaneo de D13. Es local: no abre conexiones (un test con sockets bloqueados lo prueba) y no pasa por `Harness.invoke`, porque no actúa sobre ningún activo ni destino. Igual exige la aprobación vigente de D14 y queda en la bitácora como `report.delivered` con modo `offline` y la referencia del archivo.

- **No hay caída automática a offline** después de un fallo del envío por API: el modo sale del RoE, no de un error. Así "entregado" significa siempre lo mismo.
- **Rechazado:** pasar el modo offline por `Harness.invoke` con un objetivo ficticio. Ensuciaría el Guard con un objetivo que no existe.

### D17. Cierre REPORT → DELIVERED
`Engagement.advance()` a DELIVERED exige `before_deliver`. Ese permiso ya no se otorga con `engagement.approve("before_deliver")` (lanza `TransitionError`): `Engagement.grant_delivery()` solo lo acepta con una marca que importa `harness/delivery.py`, y un test controla que nadie más en `harness/` la use. lo otorga `deliver()` solo después de (1) verificar la cadena, (2) confirmar que el kill switch no está activo, (3) confirmar la aprobación auditada de D14 para la última versión y su SHA-256 y (4) registrar `report.delivered` OK. Si cualquier paso falla, el estado queda en REPORT.

- **Kill switch activo:** `report.delivery` ABORTED, sin exportar.
- **Cadena rota:** `AuditIntegrityError`, el engagement pasa a ABORTED (008), sin exportar.
- **El builder solo corre en REPORT.** En otro estado falla con `engagement_not_in_report` sin escribir nada; en ABORTED tampoco genera (ver Preguntas abiertas).

### D18. Evals
`evals/cases/reporting.json` suma casos donde la respuesta correcta es **no entregar o no afirmar**: hallazgo sin entrada curada, vector con métrica duplicada, evidencia alterada, `closures` que dice validado sin respaldo en la bitácora, aprobación de una versión anterior, aprobación sin `--ack-unvalidated-high`, kill switch activo y una cookie con valor en el texto de una herramienta. La salida esperada es un fallo con el campo o el motivo, o PENDING_HITL, nunca `delivered: true`.

## Cambios a archivos de configuración
- `data/report_catalog.yaml`: tabla curada nueva (D3), con entradas para los CWE del catálogo de PoC y de los templates de la allow-list.
- `harness/policy.yaml`: `gates_hitl` `before: deliver` con `approval_ttl_minutes: 60` y `capabilities: [defectdojo.export]`; sección `reporting.defectdojo` con `timeout_s` y `max_response_bytes`.
- `harness/profiles.yaml`: `targets.report_destination_domains` y `targets.report_destination_cidrs` (red `tools`).
- RoE: sección opcional `report_destinations` (entra al `roe_sha256`).
- `report.render` sigue declarada en `policy.yaml` y `tools.yaml` como capability local sin objetivo: no se invoca por `Harness.invoke` y cada ejecución queda como `report.generated` o `report.generation_failed`.

## Riesgos y limitaciones
- **Observaciones ancladas tarde:** las del loop B quedan selladas al generar el informe, no cuando ocurrieron (D2). Quien controla el `FindingStore` antes de generar puede cambiarlas; la validación, en cambio, sale de la cadena.
- **Vector por clase:** el vector curado es por CVE o por CWE, no por instancia. Dos instancias del mismo CWE con impacto distinto llevan el mismo vector; corregirlo exige una entrada específica.
- **Patrones de redacción:** una lista fija no detecta todo; por eso la exportación es por lista permitida (D12) y el informe falla ante una coincidencia en lugar de entregar.
- **Identidad del Reviewer:** sigue siendo texto libre sin autenticación (riesgo aceptado en 006).
- **DefectDojo sin instancia en el laboratorio:** el modo API se prueba contra un servidor HTTP falso en el test; el recorrido real queda para cuando haya instancia (ver Preguntas abiertas).
- **Riesgos aceptados de la entrega (revisión de seguridad del PR 2):**
  - la clave viaja por HTTP en claro dentro de la red `tools` del laboratorio; con una instancia fuera del laboratorio hay que pasar a HTTPS con el SNI y el Host fijados;
  - `timeout_s` acota cada operación del socket, no la conexión entera; cada lectura sigue acotada por `max_response_bytes`;
  - el Guard acepta subdominios de `allowed_domains`; la IP fija /32 sigue siendo el único destino posible;
  - `_INTERNAL_RE` tiene la red `10.97.x` escrita a mano: es defensa en profundidad, la protección principal es la lista permitida;
  - el gate en el Harness es la aprobación en memoria del Guard (mismo diseño que el 006); `deliver()` es el único lugar que la otorga y la retira;
  - `DeliveryContext.clock` es inyectable para los tests.
- **Riesgos aceptados de la demo y del CWE curado (revisión de seguridad del PR 3):**
  - un CWE curado distinto del del feed queda en la bitácora con el motivo `missing_cwe`: el campo es el correcto, pero el motivo dice "falta" cuando hay un conflicto;
  - si la entrada por CVE no vale (por ejemplo, sin revisar), se usa la entrada por CWE y los problemas de la del CVE no se informan (comportamiento previo de `lookup`);
  - el informe de una simulación no se marca como tal, y en la demo los activos salen sin tecnologías (el grafo del runner no se lee);
  - `--catalog` acepta cualquier archivo: quien corre la demo en el host es de confianza (mismo supuesto que el Reviewer del 006).

## Preguntas abiertas
1. ~~**Cálculo del puntaje CVSS v4.0**~~ Resuelta el 2026-11-20: biblioteca `cvss==3.4` fijada (D4). La validación del vector sigue siendo propia.
2. **Versión de DefectDojo y campos de Generic Findings Import:** hay que fijar la versión y confirmar si su importador acepta CVSS v4.0 y EPSS en campos propios. Hasta confirmarlo, viajan dentro de `description` (D12).
3. **Instancia de DefectDojo en `lab/docker-compose.yml`:** agregarla (varios servicios y bastante memoria) o mantener solo el modo offline y el servidor falso de los tests.
4. **Informe de un engagement abortado:** PTES pide informar lo hecho aunque se aborte; este change no genera informe en ABORTED.
5. **Fe de erratas después de DELIVERED:** fuera de este change (D9).
</content>
</invoke>
