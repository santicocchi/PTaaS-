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

### D2. Aprobación por hallazgo, no por target
Respuesta a "¿cómo se ata el gate humano a cada hallazgo?": la aprobación actual (`Guard.approve(action, target, ...)`) aprueba **todo** lo que vaya a ese host. Con dos hallazgos en `dvwa.lab.test`, aprobar uno aprobaría el otro. Por eso:

- `Guard.approve` y `Guard.approved` ganan un argumento `subject` (el `finding_id`). La clave pasa a ser `(engagement, fase, acción, target canónico, subject)`.
- `Harness.invoke` gana `subject: str | None = None`. Una acción con `requires_human_approval` o en una fase con gate (VALIDATE) **sin** `subject` se bloquea con `missing_subject`. Así nadie puede invocar la validación "en general".
- El `Guard` sigue sin LLM y sin estado externo: el orquestador le carga las aprobaciones vigentes leídas del registro de aprobaciones (D5).

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
| `max_response_bytes` | 65536 | Se lee hasta el límite y se marca `truncated: true`. El evaluador corre sobre lo leído; si el canario o la condición quedaron afuera, el resultado es negativo. Truncar nunca produce un positivo. |
| `max_requests_per_finding` | 2 | Igual al tope del loop C (`max_loop_iterations.validation`). |
| `max_requests_per_engagement` | 20 | El loop C se detiene con `request_budget_exhausted`. |

El conteo de solicitudes sale de la bitácora (OK de `poc_catalog.run_parametrized` en el engagement), no de un contador en memoria: sobrevive a un reinicio.

### D5. Registro de aprobaciones y timeout del Reviewer
`harness/approvals.py` define `ApprovalStore`, un SQLite append-only (`state/<engagement>.approvals.sqlite3`, triggers que impiden UPDATE y DELETE, como el `FindingStore`). Cada fila: `finding_id`, `decision` (`approved` | `rejected`), `reviewer`, `reason`, `decided_at`, `expires_at`. La decisión vigente es la última fila del hallazgo.

Respuesta a "¿qué pasa si el Reviewer no responde?":
- **Nunca se aprueba por defecto.** Un hallazgo sin decisión queda `PENDING_HITL` y no se envía nada.
- `policy.yaml` gana `gates_hitl.validation_timeout_minutes` (60). Pasado ese tiempo desde que el hallazgo entró a la cola sin decisión, el loop lo cierra como `not_validated`, motivo `reviewer_timeout`. El informe lo muestra como "no validado por falta de revisión", no como descartado.
- **Una aprobación vence** a los `gates_hitl.approval_ttl_minutes` (60). Una aprobación vencida vale lo mismo que ninguna. Así una aprobación de ayer no habilita tráfico hoy.
- Un `rejected` cierra el hallazgo como `not_validated`, motivo `reviewer_rejected`, y no se vuelve a pedir en ese engagement.

### D6. CLI del Reviewer
`python -m harness.review --engagement <id> --state-dir state`:
- `list`: hallazgos en la cola (`finding_id`, CWE, host, prioridad, entrada del catálogo que se usaría, parámetros) con su estado (`pending`, `approved`, `rejected`, `expired`).
- `approve <finding_id> --reviewer <nombre> --reason "<texto>"`.
- `reject <finding_id> --reviewer <nombre> --reason "<texto>"`.

`--reviewer` y `--reason` son obligatorios; un motivo vacío se rechaza. Aprobar un hallazgo que no está en la cola, o que ya tiene decisión vigente, falla con un mensaje y no escribe nada. Cada decisión se registra en la bitácora con `record_control` (`hitl.approve` / `hitl.reject`, target = host del hallazgo). La CLI no envía tráfico: solo escribe la decisión.

### D7. Evidencia y redacción
Por cada intento se escribe `state/evidence/<engagement>/<finding_id>-<intento>.json` y la bitácora guarda `ruta#sha256=<hex>` (el formato de `EVIDENCE_RE`). El archivo contiene:
- **Qué:** `poc_id`, `poc_version`, `catalog_version`, parámetros, `sandbox_id`, intento.
- **Solicitud:** método, path, `Host`, IP. Sin cuerpo si no lo declara la entrada.
- **Respuesta:** código, encabezados de una lista permitida (`Content-Type`, `Server`, `Location`, `Content-Length`, `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`), nombres y atributos de `Set-Cookie` **sin el valor**, SHA-256 del cuerpo completo y un extracto de hasta 512 bytes alrededor del canario o de la coincidencia del evaluador. El resto del cuerpo no se guarda.
- **Resultado:** `validated` | `not_validated` | `failed`, detalle del evaluador y `truncated`.

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
