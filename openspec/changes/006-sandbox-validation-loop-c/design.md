# Design — Change 006: sandbox efímero y loop C

## Contexto
El loop B (005) termina con `PrioritizedVuln` en estado `confirmed`, `discarded` o `inconclusive`. Un candidato con evidencia de versión sola queda, como mucho, `inconclusive` (005 D4) y espera una verificación del catálogo en VALIDATE. Hoy esa pieza no existe: `run_parametrized` (`harness/poc/catalog.py`) evalúa respuestas, pero el único `Sender` es el de la demo (`demo/checkpoint1.py`), que envía desde el proceso del runner. No hay contenedor por validación, no hay aprobación por hallazgo (el `Guard` aprueba por acción y target) y nadie orquesta el loop C.

```
PrioritizedVuln (confirmed | inconclusive) ──▶ cola de revisión ──▶ CLI del Reviewer
                                                                     approve | reject (con motivo)
                                                                           │
                                           ┌───────────────────────────────┘
                                           ▼
                     loop C por hallazgo (decide_validation, tope 2)
                     Harness.invoke(poc_catalog.run_parametrized, subject=finding_id)
                                           │
                                           ▼
                     sandbox efímero: docker run --rm en la red interna `lab`
                     una solicitud, límites de tiempo y tamaño, se destruye siempre
                                           │
                                           ▼
                     ValidationEvidence ─▶ archivo redactado + bitácora (path#sha256)
```

Todo pasa por `Harness.invoke` con un token de VALIDATE. El sandbox es un detalle del adaptador: ningún agente ni módulo lanza contenedores por su cuenta.

## Decisiones

### D1. Orquestador determinista, igual que los loops A y B
`harness/validation.py` define `ValidationLoop`, con la misma forma que `AnalysisLoop`: recibe `harness`, un token de VALIDATE, el `FindingStore`, el engagement y el catálogo. Elige la entrada del catálogo **por reglas**: CWE del hallazgo igual al de la entrada y host del hallazgo dentro de `lab_targets`. Los parámetros salen del grafo de activos (host, puerto, endpoint observado), no de un texto libre. El agente con LLM llega después y solo podrá **proponer** `poc_id` y parámetros sobre este orquestador; el harness los valida con `run_parametrized`, que ya rechaza ids fuera del catálogo y parámetros no declarados.

- **Qué hallazgos entran:** `confirmed` e `inconclusive`. Un `discarded` no se valida.
- **Sin entrada del catálogo:** el hallazgo queda `not_validated`, motivo `no_catalog_entry`, sin invocar nada.
- **Engagement fuera de VALIDATE o kill switch activo:** el loop no arranca y lo registra, igual que el loop B.
- **`lab_targets`:** cada nombre se traduce con un mapa explícito a FQDN del laboratorio (`LAB_TARGET_HOSTS` en `harness/poc/catalog.py`: `dvwa` → `dvwa.lab.test`, `juice-shop` → `juiceshop.lab.test`). El host del hallazgo se compara completo y en forma canónica (minúsculas, sin punto final, sin quitar caracteres). El catálogo rechaza un nombre que no esté en el mapa.
- **Bloqueo no fatal del Guard** (`out_of_scope`, `excluded`, `dns_out_of_scope`…): el hallazgo termina `not_validated` con ese motivo, no `pending_hitl`.

### D2. Aprobación por hallazgo, no por target
Respuesta a "¿cómo se ata el gate humano a cada hallazgo?": la aprobación actual (`Guard.approve(action, target, ...)`) aprueba **todo** lo que vaya a ese host. Con dos hallazgos en `dvwa.lab.test`, aprobar uno aprobaría el otro. Por eso:

- `Guard.approve` y `Guard.approved` ganan un argumento `subject` (el `finding_id`). La clave pasa a ser `(engagement, fase, acción, target canónico, subject)`.
- `Harness.invoke` gana `subject: str | None = None`. Una acción con `requires_human_approval` o en una fase con gate (VALIDATE) **sin** `subject` se bloquea con `missing_subject`. Así nadie puede invocar la validación "en general".
- Un `subject` que no es un `finding_id` válido se rechaza **antes que nada** en `invoke`, con un registro BLOCKED `invalid_subject` sin `subject`. Si se validara después, la escritura de los registros de denegación fallaría y la acción bloqueada no quedaría en bitácora.
- El `subject` queda en la cadena de la bitácora (campo opcional que entra al hash) en los registros de `invoke` y en los controles `hitl.*` y `validation.*`. Una bitácora anterior gana la columna al abrirse.
- El `Guard` sigue sin LLM y sin estado externo: el orquestador le carga la aprobación vigente (D5) solo para el envío de ese hallazgo y la retira después.

### D3. Sandbox efímero: un contenedor por solicitud
`harness/sandbox.py` define `DockerSandbox`, que implementa `Sender`. Por cada envío:

1. Barre contenedores huérfanos con la etiqueta `ptaas.sandbox=<engagement>` (`docker rm -f`).
2. Verifica con `docker network inspect` que la red del laboratorio tenga `Internal: true`. Si no, no envía y devuelve `sandbox_error` (`network_not_internal`).
3. Lanza `docker run --rm` con la imagen `ptaas-sandbox` fijada por digest y estas opciones fijas, armadas en el código y no configurables por el agente:
   `--network <red lab> --read-only --tmpfs /tmp:size=1m --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --memory 128m --pids-limit 32 --cpus 0.5 --label ptaas.sandbox=<engagement> --name ptaas-sbx-<uuid>`.
   Sin volúmenes montados y sin variables de entorno del host.
4. Le pasa por stdin un JSON con la solicitud (método, path, encabezados declarados, IP fijada, `Host`) y lee por stdout un JSON con la respuesta. El script del sandbox (`lab/sandbox/send.py`) solo hace **una** solicitud HTTP a la IP recibida y termina.
5. En un `finally`, `docker rm -f ptaas-sbx-<uuid>`, haya salido bien o mal.

- **Dirección:** el `Sender` del catálogo es `(poc_id, params)`. El adaptador `poc_catalog.run_parametrized` lo envuelve con las IP fijadas que le pasa el `Harness` (igual que la demo), así el sandbox solo puede apuntar a una IP ya validada por el Guard. El script del sandbox además rechaza una IP fuera de `10.99.0.0/24`: defensa en profundidad.
- **`sandbox_id`:** el nombre del contenedor. Queda en la evidencia y en la bitácora.

Respuesta a "¿cómo se prueba que el sandbox no puede salir a internet?":
- **Por construcción:** la red `lab` es `internal: true` en compose, sin gateway. Docker no la enruta hacia afuera.
- **Antes de cada envío:** el chequeo de `Internal: true` (paso 2). Si alguien cambia el compose, la validación se frena.
- **Test unitario:** el argv que arma `DockerSandbox` nunca contiene `--network host`, `bridge` ni `-v`, y siempre contiene las opciones del paso 3.
- **Test de integración (con docker, marcado `lab`):** se lanza el sandbox real con destinos fuera del laboratorio (`1.1.1.1:80`, la IP del runner en la red `tools`) usando el modo de diagnóstico del script, que omite su propia lista de IP, y se espera error de conexión en ambos. Así se prueba la red, no solo el filtro del script.

### D4. Límites
`policy.yaml` gana `sandbox.limits`:

| Límite | Valor | Qué pasa al superarlo |
|---|---|---|
| `request_timeout_s` | 10 | El script corta la solicitud: resultado `timeout`. |
| `container_timeout_s` | 30 | El adaptador mata el contenedor: resultado `timeout`. |
| `max_response_bytes` | 65536 | Se lee hasta el límite y se marca `truncated: true`. Una respuesta truncada queda `not_validated` aunque el evaluador dé positivo sobre lo leído (por ejemplo, uno de encabezados o cookies): superar un límite nunca produce un positivo. |
| `max_requests_per_finding` | 2 | Igual al tope del loop C (`max_loop_iterations.validation`). |
| `max_requests_per_engagement` | 20 | El loop C se detiene con `request_budget_exhausted`. |

El conteo de solicitudes sale de la bitácora (OK de `poc_catalog.run_parametrized` en el engagement), no de un contador en memoria: sobrevive a un reinicio.

### D5. Registro de aprobaciones y timeout del Reviewer
`harness/approvals.py` define `ApprovalStore`, un SQLite append-only (`state/<engagement>.approvals.sqlite3`, triggers que impiden UPDATE y DELETE, como el `FindingStore`).

- **Revisiones de la solicitud:** la cola guarda una fila por cada versión de lo que se enviaría (host, entrada del catálogo y parámetros), con un hash corto (12 hex del SHA-256 canónico). Si la elección del loop cambia, o vuelve a una anterior, es una revisión nueva.
- **Decisiones:** cada fila tiene `finding_id`, `decision` (`approved` | `rejected`), `reviewer`, `reason`, `decided_at`, `expires_at`, la revisión y el hash de la solicitud. Una aprobación vale solo para su revisión y su hash, y el loop envía exactamente esa revisión.
- **La bitácora manda:** la decisión vigente es la del control `hitl.*` más nuevo de la bitácora para ese `subject`. Ese control lleva una referencia hasheada de la fila, con su número de fila, así respalda una sola fila. Una fila sin control, o una copia de una fila, no habilita tráfico. El orden de las filas del registro no cuenta.
- **Revocación:** un rechazo posterior revoca una aprobación vigente. La aprobación se verifica (vigencia, revocación, bitácora y hash) antes de cada intento, no una vez por hallazgo.

Respuesta a "¿qué pasa si el Reviewer no responde?":
- **Nunca se aprueba por defecto.** Un hallazgo sin decisión queda `PENDING_HITL` y no se envía nada.
- `policy.yaml` gana `gates_hitl.validation_timeout_minutes` (60). Pasado ese tiempo desde que el hallazgo entró a la cola sin decisión, el loop lo cierra como `not_validated`, motivo `reviewer_timeout`. El informe lo muestra como "no validado por falta de revisión", no como descartado.
- **Una aprobación vence** a los `gates_hitl.approval_ttl_minutes` (60). Una aprobación vencida vale lo mismo que ninguna. Así una aprobación de ayer no habilita tráfico hoy.
- Un `rejected` cierra el hallazgo como `not_validated`, motivo `reviewer_rejected`, y no se vuelve a pedir en ese engagement.

### D6. CLI del Reviewer
`python -m harness.review --engagement <id> --state-dir state`:
- `list`: hallazgos en la cola (`finding_id`, CWE, host, prioridad, entrada del catálogo que se usaría, parámetros y hash de la solicitud) con su estado (`pending`, `approved`, `rejected`, `expired`).
- `approve <finding_id> --request <hash> --reviewer <nombre> --reason "<texto>"`. El hash es el que mostró `list`: si la solicitud en cola cambió, la aprobación falla sin escribir. Así se aprueba lo que se vio.
- `reject <finding_id> --reviewer <nombre> --reason "<texto>"`. Sobre una aprobación vigente, la revoca.

`--reviewer` y `--reason` son obligatorios; un motivo vacío se rechaza. Aprobar un hallazgo que no está en la cola, que ya tiene una aprobación vigente o que fue rechazado falla con un mensaje y no escribe nada. Cada decisión se registra en la bitácora con `record_control` (`hitl.approve` / `hitl.reject`, target = host del hallazgo, `subject` = `finding_id`, evidencia = referencia de la fila). La CLI no envía tráfico: solo escribe la decisión.

Registro y bitácora se escriben juntos o ninguno: dentro de un `BEGIN IMMEDIATE` del registro se inserta la fila, se escribe la bitácora y recién después COMMIT. Si la bitácora falla, ROLLBACK y la CLI sale con error 3 diciendo que la decisión NO quedó registrada. Si falla el COMMIT después de la bitácora, queda un control sin fila, que no habilita nada (D5), y el error se informa.

### D7. Evidencia y redacción
Por cada intento se escribe `state/evidence/<engagement>/<finding_id>-<intento>.json` y la bitácora guarda `ruta#sha256=<hex>` (el formato de `EVIDENCE_RE`). El archivo contiene:
- **Qué:** `poc_id`, `poc_version`, `catalog_version`, parámetros, `sandbox_id`, intento.
- **Solicitud:** método, path, `Host`, IP. Sin cuerpo si no lo declara la entrada.
- **Respuesta:** código, encabezados de una lista permitida (`Content-Type`, `Server`, `Location` sin query ni fragmento, `Content-Length`, `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`), nombres y atributos de `Set-Cookie` **sin el valor**, SHA-256 del cuerpo completo y un extracto de hasta 512 bytes alrededor del canario o de la coincidencia del evaluador. El resto del cuerpo no se guarda.
- **Resultado:** `validated` | `not_validated` | `failed`, detalle del evaluador y `truncated`. Con `truncated: true` el resultado nunca es `validated` (D4).

Cualquier encabezado `Authorization`, `Cookie` o `Set-Cookie` que llegue se reemplaza por `[redacted]` antes de escribir. La evidencia prueba la condición; no copia datos del laboratorio que no hacen falta para probarla.

### D8. Fallo a mitad de ejecución
- **El contenedor falla o no arranca:** `ABORTED` con motivo `sandbox_error`, el intento cuenta y el loop sigue con el siguiente intento o el siguiente hallazgo.
- **Timeout:** `ABORTED` con `timeout`, igual tratamiento.
- **No se pudo destruir el contenedor** (`docker rm -f` falla): registro de control `sandbox.cleanup_failed` y el loop C **se detiene** para todo el engagement. Un contenedor vivo que no controlamos es peor que una validación pendiente. Retomar exige que una persona lo resuelva y vuelva a correr el loop, que empieza barriendo huérfanos (D3 paso 1).
- **Kill switch o integridad de la bitácora rota en el medio:** se aborta como en el loop B; el `finally` del sandbox igual destruye el contenedor.

### D9. Resultados distintos entre corridas
Respuesta a "¿cómo se maneja una verificación que arroja resultados distintos entre corridas?":
- **El canario es nuevo en cada intento** (`new_canary()`), así que una respuesta cacheada o un reflejo de una corrida anterior no cuenta como positivo.
- Un intento positivo **detiene** el loop: `validated`. La evaluación es determinista sobre la respuesta, así que un positivo con el canario de ese intento es evidencia suficiente.
- Un negativo o un error permite **un** reintento (tope 2). Si ninguno es positivo, el hallazgo queda `not_validated`, o `failed` si todos los intentos fueron errores del sandbox.
- Se registran todos los intentos. Si un hallazgo da positivo en un engagement y negativo en otro, el informe muestra los dos; no se promedian.

### D10. Proponer una nueva verificación inerte
Una entrada nueva del catálogo es un change como cualquier otro: `openspec/changes/<id>/` con la entrada, el evaluador que usa y un test contra el laboratorio.
- La entrada gana `proposed_by`. El cargador rechaza una entrada con `approved_by` vacío o igual a `proposed_by`: nadie aprueba su propia verificación.
- El `evaluator` tiene que existir en `EVALUATORS`. Un evaluador nuevo es código del harness y entra por el mismo change, con revisión del `security-reviewer`.
- Agregar o cambiar una entrada sube `catalog_version`. La evidencia guarda esa versión (D7).

### D11. Evals
`evals/cases/validation.json` suma casos donde la respuesta correcta es **no actuar**: hallazgo rechazado por el Reviewer, aprobación vencida, hallazgo `discarded`, host fuera de `lab_targets`, parámetro extra propuesto, kill switch activo y presupuesto de solicitudes agotado. La salida esperada en todos es `not_validated` o `pending_hitl`, sin `poc_id` inventado.

## Cambios a archivos de configuración
- `harness/policy.yaml`: `sandbox.limits` (D4), `gates_hitl.validation_timeout_minutes` y `gates_hitl.approval_ttl_minutes` (D5).
- `harness/poc/catalog.yaml`: `proposed_by` en cada entrada; las existentes se completan con quien las escribió.
- `lab/docker-compose.yml`: build de la imagen `ptaas-sandbox` (sin servicio corriendo; se usa con `docker run`). El runner gana acceso al socket de docker **solo** si la demo corre desde adentro; por defecto el loop C corre en el host del laboratorio.
- `lab/sandbox/Dockerfile` y `lab/sandbox/send.py`: imagen mínima `python:3.12-alpine` fijada por digest, sin dependencias externas (`http.client`).

## Riesgos y limitaciones
- **Acceso a docker:** quien corre el loop C puede lanzar contenedores. El adaptador arma el argv completo con valores fijos y el agente no lo toca, pero el proceso tiene ese permiso. Se documenta y no se monta el socket en el runner por defecto.
- **Un solo tipo de solicitud:** el sandbox hace HTTP simple. Una verificación que necesite sesión o varios pasos no entra en este change.
- **Truncado:** una respuesta grande puede esconder un positivo; elegimos el falso negativo antes que el falso positivo.
- **Timeout del Reviewer en horas de trabajo:** 60 minutos puede ser corto en una práctica; es configurable, pero nunca se aprueba solo.

## Revisión del security-reviewer (implementación)

La revisión encontró 1 bloqueante y 9 mejoras, y la revisión automática de los commits sumó 5 hallazgos más. Todos están corregidos, con un test negativo escrito antes de la corrección, y los deltas de spec se actualizaron donde cambiaba el comportamiento.

| # | Hallazgo | Corrección |
|---|---|---|
| B1 (alta) | El loop recalculaba la verificación en cada corrida y enviaba esa, no la aprobada. Una observación nueva del loop B o un cambio del catálogo después de aprobar cambiaba la ruta, el parámetro, el puerto o la verificación sin que nadie lo aprobara. | La cola guarda una revisión por solicitud (host, entrada y parámetros). Se envía exactamente la revisión aprobada. Si la elección cambia, es otra revisión: queda pendiente y pide una decisión nueva. |
| M1 | Una fila de aprobación insertada en el SQLite sin pasar por la CLI habilitaba tráfico. | La aprobación vale solo si tiene su control `hitl.approve` en la bitácora, con el mismo reviewer y la referencia hasheada de la fila. |
| M2 | El `finding_id` no quedaba en la bitácora. | Campo opcional `subject` en la cadena (entra al hash) en los registros de `invoke` y en los controles `hitl.*` y `validation.*`. Las bitácoras anteriores ganan la columna al abrirse y siguen verificando. |
| M3 | No se podía revocar una aprobación vigente. | Un `reject` sobre una aprobación vigente la revoca: la última decisión manda. |
| M4 | La aprobación se verificaba una vez por hallazgo, no antes de cada intento. | Se vuelve a verificar (vigencia, revocación, bitácora y hash) antes de cada intento. Si venció entre intentos, el segundo no se envía. |
| M5 | Verificar e insertar no era atómico, y el registro y la bitácora podían divergir en silencio. | `BEGIN IMMEDIATE`: se inserta la fila, se escribe la bitácora y recién después COMMIT. Si la bitácora falla, ROLLBACK y la CLI sale con error 3. Si falla el COMMIT después de la bitácora, queda un control sin fila, que no habilita nada (M1). |
| M6 | Un bloqueo no fatal del Guard (`out_of_scope`, `excluded`, `dns_out_of_scope`) terminaba como `pending_hitl`. | Termina `not_validated` con el motivo real. |
| M7 | Una respuesta truncada podía dar positivo con un evaluador de encabezados o cookies, contra "superar un límite NO DEBE producir un resultado positivo". | Respuesta truncada → `not_validated`, con el motivo en el detalle de la evidencia. |
| M8 | Un `adapter_error` después de enviar (por ejemplo, la evidencia no se pudo escribir) no quedaba como intento y no contaba entre reinicios. | Todo error, también `adapter_error`, queda como `validation.attempt` ABORTED con su motivo. |
| M9 | `Location` podía llevar tokens en la query o en el fragmento. | Se guarda sin query ni fragmento. |
| A1 (e11b719) | `lab_targets` comparaba solo el primer label del host sin guiones: `dvwa.evil.example` o `d-v-w-a.lab.test` pasaban por `dvwa`. | Host canónico completo contra un mapa explícito de FQDN (`LAB_TARGET_HOSTS`). El catálogo rechaza un nombre que no esté en el mapa. |
| A2 | Con un `subject` malformado, la escritura de los registros de denegación (kill switch, bloqueo del Guard) fallaba: la acción bloqueada no quedaba en bitácora y cambiaba el tipo de excepción. | `invoke` valida el `subject` antes que nada: un registro BLOCKED `invalid_subject` sin `subject`, y el adaptador no corre. Scenario nuevo en audit-log. |
| A3 | Revocación reversible: una copia de la fila aprobada insertada después del rechazo coincidía con la referencia auditada y revivía la aprobación. | La decisión vigente sale del control `hitl.*` más nuevo de la bitácora. La referencia incluye el número de fila, así cada control respalda una sola fila. |
| A4 | La cola podía cambiar entre `list` y `approve`, y el Reviewer aprobaba algo que no había visto. | `list` muestra el hash corto de la solicitud. `approve` exige `--request` y rechaza otro hash sin escribir nada. El loop solo envía si el hash aprobado es el de lo que va a enviar. |
| A5 | Las expresiones terminadas en `$` aceptaban un salto de línea final (`"F-1\n"` pasaba como `subject`). | `\Z` en `SUBJECT_RE`, `EVIDENCE_RE` (anterior a este change, con el mismo problema) y las expresiones nuevas del change. |

Quedan como riesgos aceptados, para un próximo change o el informe:
- **Identidad del Reviewer:** `--reviewer` es texto libre sin autenticación. Quien puede ejecutar la CLI puede aprobar con cualquier nombre; el control real es quién tiene acceso al host del laboratorio y a la bitácora.
- **Alcance de red del sandbox:** el contenedor puede llegar a cualquier servicio de la red `lab`, no solo al objetivo del hallazgo. Lo acotan la IP fijada por el Guard y el filtro del script, que es defensa en profundidad, no aislamiento de red.
- **Barrido por engagement:** los huérfanos se barren por la etiqueta del engagement. Un contenedor vivo de otro engagement no se toca.
- **Extracto de 512 bytes:** puede contener datos del laboratorio que rodean al canario o a la coincidencia del evaluador.
- **Chequeos previos de la CLI:** "ya aprobado" y "ya rechazado" se leen del registro, no de la bitácora. En el peor caso la CLI rechaza una decisión válida; no puede habilitar tráfico, porque el loop decide con la bitácora.
- **Test de salida a internet sin correr:** el test con docker real (`1.1.1.1:80` y la red `tools`, marcado `lab`) no se corrió en este entorno, que no tiene docker. Hay que correrlo en el host del laboratorio antes de dar por probado que el sandbox no sale.
