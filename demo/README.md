# Demo del Checkpoint 1 (5 minutos)

RoE → scope token → acciones permitidas y bloqueadas → bitácora verificable. Todo pasa por
`Harness.invoke`, igual que en producción.

## Cómo correrla

**Simulación** (cualquier máquina, no envía tráfico: el adaptador nmap arma el comando y no
lo ejecuta, y el DNS es una tabla fija con los hosts del laboratorio):

```bash
python -m demo.checkpoint1 --pausa        # --pausa espera Enter entre pasos
```

**Laboratorio real** (nmap de verdad contra DVWA y una verificación del catálogo, dentro de la
red aislada `internal: true`, sin salida a internet):

```bash
docker compose -f lab/docker-compose.yml up -d --build    # la 1ª vez construye el runner con nmap
docker compose -f lab/docker-compose.yml exec runner python -m demo.checkpoint1 --lab --pausa
docker compose -f lab/docker-compose.yml down             # al terminar
```

Cada corrida crea un engagement nuevo (`demo-cp1-<fecha-hora>`) y su bitácora en `demo/out/`
(no se sube al repo). Para verificarla aparte:

```bash
python -m harness.audit verify demo/out/demo-cp1-<fecha-hora>.sqlite3
```

## Guion

| Paso | Qué se ve | Qué decir |
|---|---|---|
| 1 | RoE con `0.0.0.0/0`, un dominio de afuera, sin zona horaria y sin contactos → `roe_invalid` con los 4 errores | El RoE es la única fuente de autoridad. Si está mal, no se emite ningún token. |
| 2 | RoE aprobado (hash SHA-256). Se borra la exclusión de Juice Shop sin re-aprobar → `roe_tampered` | La aprobación cubre el contenido exacto: cambiar algo después la invalida. |
| 3 | Token recon emitido (60 min, HMAC). Pedido de token analyze → `phase_not_in_roe` | Tokens cortos, por fase y firmados. Solo para las fases que habilita el RoE. |
| 4 | `nmap.service_scan` sobre `dvwa.lab.test` → PERMITIDA (en `--lab`, puertos reales) | Pasó token, guard, adaptador y DNS. La decisión se registró antes de ejecutar. |
| 5 | IP de afuera → `out_of_scope` · Juice Shop → `excluded` · ZAP con token de recon → `wrong_phase` · `sqlmap.dump` → `not_allowlisted` | Guard determinista, sin LLM. Los bloqueos también quedan en bitácora. |
| 6 | Token copiado con `0.0.0.0/0` → `token_invalid` | Agrandarse el token rompe la firma. |
| 7 | DNS envenenado: `dvwa.lab.test` → IP de afuera → `dns_out_of_scope` | Bypass A4 del red team: pasaba, ahora se valida la IP resuelta. |
| 8 | Verificación del catálogo con `requires_human_approval=False` → EN ESPERA; el reviewer aprueba → se ejecuta | Bypass R13: el gate lo decide la política, no el agente. Solo PoC inertes del catálogo. |
| 9 | Kill switch → ABORTADA; se reinicia el proceso → sigue ABORTADA | El kill switch vive en la bitácora: reiniciar no lo apaga. |
| 10 | Tabla de la bitácora, `verify` OK, un `UPDATE` rechazado por trigger, y una copia manipulada → `CADENA ROTA` | Append-only y hash encadenado: si alguien "limpia" un intento, se detecta. |

## Qué es real y qué no

- En simulación, lo único simulado es lo que hay *detrás* del Harness (nmap, DNS, la respuesta
  HTTP). Las decisiones de autorización, los tokens y la bitácora son el código real.
- El DNS envenenado (paso 7) es simulado en los dos modos: no tenemos un DNS que mienta.
- El adaptador de la verificación del catálogo es propio de la demo; el definitivo llega con el
  change 006 (sandbox). Solo corre PoC inertes del catálogo versionado.
- La aprobación del reviewer (paso 8) todavía no está autenticada ni queda en bitácora como
  registro propio: es una limitación conocida del 003 (firma Ed25519 como mejora).
- Los intentos fuera de alcance usan `203.0.113.7` (TEST-NET-3, rango reservado para
  documentación). Igual nunca se les envía nada: el Harness los corta antes del adaptador.

---

# Loop A: relevamiento de punta a punta (change 004)

```bash
python -m demo.loop_a                                                    # simulación
docker compose -f lab/docker-compose.yml up -d --build                   # 1ª vez: runner con httpx y subfinder
docker compose -f lab/docker-compose.yml exec runner python -m demo.loop_a --lab
```

Corre el orquestador real con los adaptadores reales (subfinder, httpx y nmap), todo por
`Harness.invoke`. Al final muestra el grafo de activos (qué apareció en cada iteración, qué quedó
fuera de alcance y por qué), lo que se entrega a correlación y la bitácora verificada.

- **Simulación:** las herramientas no se ejecutan; cada una devuelve una salida grabada que pasa
  por el mismo parseo que la real. Incluye un subdominio de afuera (`cdn.example.com`), Juice Shop
  (excluido en el RoE) y una redirección a `203.0.113.7`: los tres quedan en el grafo como
  "fuera de alcance" y ninguno llega a una herramienta.
- **Laboratorio:** subfinder no encuentra nada porque sus fuentes están en internet y el runner
  no tiene salida. El loop sigue con las semillas del RoE: httpx y nmap sobre `dvwa.lab.test`
  (Apache 2.4.25). Juice Shop no se toca porque el RoE lo excluye.

**El runner monta el proyecto de solo lectura.** Las herramientas procesan respuestas de los
objetivos, que son datos hostiles; si algo saliera mal adentro del contenedor, no puede modificar
el código del harness. Lo único escribible es `demo/out/`. Los tests (`pytest`) se corren en tu
máquina, no en el runner.

---

# Pipeline: relevamiento → correlación → análisis (change 005)

**Antes de levantar el laboratorio (una sola vez):** ZAP corre como servicio y su API pide una
clave. La clave no va en el repo: se genera en tu máquina y queda en `lab/.env` (ignorado por
git). Sin ese archivo `docker compose` no arranca y te dice qué falta.

```bash
echo "PTAAS_ZAP_API_KEY=$(openssl rand -hex 16)" > lab/.env
docker compose -f lab/docker-compose.yml up -d --build      # runner con nuclei + servicio zap
```

```bash
python -m demo.pipeline                                                    # simulación
docker compose -f lab/docker-compose.yml exec runner python -m demo.pipeline --lab
```

Usa `demo/roe-pipeline.yaml`, que autoriza recon, correlate, analyze y validate (el RoE del
Checkpoint 1 no autoriza analyze, y eso es lo que muestra su paso 3). Un mismo engagement, un token por fase:

1. **Relevamiento:** el loop A de arriba.
2. **Correlación:** las versiones del grafo contra los snapshots de `data/feeds/`, sin internet.
   Hoy el snapshot es **sintético** (`CVE-2099-…`, la demo lo avisa). El real lo genera el
   equipo con `python tools/build_feeds.py --cpe apache:http_server:2.4.25 …` y lo sube en un PR.
   La confianza de un candidato por versión nunca pasa de media; con un `(Debian)` en el banner
   baja a baja (puede haber backport).
3. **Análisis:** nuclei con los templates propios de `templates/allowlist/` y ZAP por su API
   (modo protegido, solo spider y escaneo pasivo, con `Host` fijado a la IP validada). Muestra
   cada vulnerabilidad con su estado (`confirmed` / `inconclusive`), su prioridad (solo si hay
   CVSS) y `revisar` cuando dos verificaciones equivalentes se contradicen.

**nuclei no corre hasta que una persona revise los templates.** Cada uno tiene en
`templates/allowlist/MANIFEST.md` su hash y un revisor; mientras diga `pendiente` (o el revisor
sea el autor), el adaptador lo saltea y la demo lista por qué. Para habilitarlos: leer cada
YAML, poner tu nombre en la columna `revisor` y subirlo en un PR.

Corrida en el laboratorio (19/11/2026, templates habilitados en una copia temporal): Apache
2.4.25 (Debian) → CVE-2099-0001 y -0002 inconclusos con confianza baja (solo versión);
CWE-693 (falta CSP), CWE-497 (versión en `Server`) y CWE-1004 (cookie sin HttpOnly) confirmados
por evidencia de confianza alta de nuclei o ZAP; sin contradicciones. 12 registros en la bitácora, cadena íntegra.

# Loop C: validación por hallazgo en el sandbox (change 006)

El loop C toma lo que dejó el pipeline y, **por cada hallazgo que apruebe el Reviewer**, corre
una verificación del catálogo (`harness/poc/catalog.yaml`) en un contenedor efímero. No se
genera nada nuevo: solo se parametrizan verificaciones aprobadas (GET o HEAD a una IP del
laboratorio, sin payloads).

Corre **en el host del laboratorio**, que es el que tiene docker. El runner no tiene el socket
de docker a propósito (design.md del 006, D3). Hace falta la imagen del sandbox:

```bash
docker compose -f lab/docker-compose.yml --profile build build sandbox
```

El recorrido tiene cuatro pasos. El 2 y el 3 los hace el Reviewer:

```bash
# 1. Pipeline: deja demo/out/<engagement>.handoff.json y su SHA-256 en la bitácora
docker compose -f lab/docker-compose.yml exec runner python -m demo.pipeline --lab

# 2. El Reviewer abre la fase de validación (gate before_validate). La entrega se verifica y
#    se importa a demo/state/, y se arma la cola del Reviewer. No se envía nada.
python -m demo.validation --lab --engagement <engagement> --approve-phase --reviewer <tu-usuario>

# 3. El Reviewer mira la solicitud (host, verificación, parámetros) y aprueba UNA.
#    La demo imprime el comando exacto, con el hash de la solicitud:
python -m harness.review --engagement <engagement> --state-dir demo/state \
    --audit-dir demo/state approve <finding_id> --request <hash> --reviewer <tu-usuario> \
    --reason "<por qué>"

# 4. Se envía solo lo aprobado, en el sandbox, y queda la evidencia
python -m demo.validation --lab --engagement <engagement>
```

Sin `--lab` es la simulación: el mismo loop, con `docker` simulado (no se ejecuta nada) y la
respuesta del DVWA grabada. Sirve para ensayar el guion. Una entrega de simulación no se
puede validar con `--lab`, ni al revés.

**Por qué `demo/state/` y no `demo/out/`.** El runner procesa respuestas de los objetivos, que
son datos hostiles, y puede escribir `demo/out` entero: la entrega, su bitácora y cualquier
registro. Si las aprobaciones vivieran ahí, desde el runner se podría correr
`harness.review` y aprobar sin el Reviewer. Por eso `demo/out` es solo la bandeja de entrada.
El loop C importa la entrega una vez a `demo/state/`, que en el runner es de solo lectura (el
repo se monta `:ro`). Desde ahí trabajan la bitácora del loop C, las aprobaciones, las
observaciones y la evidencia. Una aprobación escrita en `demo/out` no cuenta.

**Qué se verifica al importar la entrega:**
- la cadena de la bitácora de `demo/out`;
- un solo `handoff.written`, del orquestador, con el SHA-256 del archivo;
- que el modo (sim o lab) sea el de la corrida;
- que el RoE sea exactamente `demo/roe-pipeline.yaml`, salvo `engagement_id`, la ventana (que no
  puede pasar de 8 horas) y el hash de aprobación. El runner no puede tocar esa plantilla, así
  que no se puede quitar una exclusión ni agrandar el alcance editando la entrega, aunque se
  recalculen todos los hashes.

Si algo falla, queda `handoff.rejected` en la bitácora del host y no se envía nada.

Qué mirar en cada paso:

- **Paso 2:** en la bitácora del host quedan `handoff.imported` y `gate.approve` (con el
  Reviewer). CWE-693 (falta CSP) y CWE-1021 (clickjacking) quedan en `pending_hitl` con su
  verificación (POC-CSP-001 y POC-HDR-001), con un `PENDING_HITL` en la bitácora cada uno y
  ningún contenedor. Los CVE y los CWE sin verificación en el catálogo se cierran con
  `no_catalog_entry`, sin enviar nada.
- **Paso 3:** la aprobación queda en el registro de aprobaciones y en la bitácora
  (`hitl.approve`, con el hallazgo como `subject`). Vence a los 60 minutos. Si la solicitud
  cambia, el hash ya no coincide y hay que aprobar de nuevo.
- **Paso 4:** el aprobado pasa a `validated`; el otro sigue en `pending_hitl`, porque la
  aprobación es por hallazgo y no por host. La evidencia (redactada: sin cookies ni
  `Authorization`) queda en `demo/state/` y en la bitácora con su SHA-256: la demo la verifica.
  La imagen que corrió queda como `sandbox.image`. `docker ps -a --filter label=ptaas.sandbox`
  no muestra nada: el contenedor se destruye siempre.

Riesgo aceptado (design.md del 006): el Reviewer es quien tenga acceso al host del
laboratorio; la CLI no lo compara con el aprobador del RoE.

Corrida en el laboratorio (20/11/2026, nube): ver el PR de esta demo.

---

# Informe y entrega (change 007)

El último tramo del recorrido: con lo que dejó el loop C en `demo/state/`, se genera el
informe, el Reviewer lo aprueba y se entrega. Corre en el host, igual que el loop C, y **no
abre ninguna conexión**. El RoE de la demo no tiene `report_destinations`, así que la entrega
es el archivo de importación de DefectDojo (Generic Findings Import) más el resumen de la
entrega.

```bash
# 1 y 2. Pipeline y loop C, como arriba (con sus gates)

# 3. Genera report-v1 y muestra el comando de aprobación, con el hash de esa versión
python -m demo.report --engagement <engagement>

# 4. El Reviewer lee el informe (demo/state/reports/<engagement>/report-v1.md) y lo aprueba
python -m harness.review --engagement <engagement> --state-dir demo/state \
    --audit-dir demo/state report approve report-v1 --sha256 <hash> \
    [--ack-unvalidated-high] --reviewer <tu-usuario> --reason "<por qué>"

# 5. Se entrega solo esa versión, y el engagement pasa a DELIVERED
python -m demo.report --engagement <engagement>
```

**Antes de la primera corrida:** el informe usa la tabla curada `data/report_catalog.yaml`.
Cada entrada necesita un `reviewer` distinto del autor. Mientras diga `pendiente`, la demo
falla y lista qué hallazgo y qué campo faltan, sin escribir ningún informe. Mientras el feed
de `data/feeds/` sea el sintético (también con `--lab`), además se suman las entradas de los
CVE sintéticos (`demo/report_catalog_sim.yaml`), que también se revisan y solo pueden traer
CVE `CVE-2099-…`. Con el feed real esa tabla no se lee. Si la bitácora del loop C no corresponde al modo de la entrega (una imagen simulada en
un recorrido de laboratorio, o al revés) la demo no genera nada.

Qué mirar en cada paso:

- **Paso 3:** `report.generated` en la bitácora del host, con el SHA-256 del informe, y un
  `report.delivery` PENDING_HITL. El informe dice qué hallazgos se validaron en el sandbox y
  cuáles no. Si hay altos o críticos sin validar, aprobar exige `--ack-unvalidated-high`.
- **Paso 4:** `hitl.approve_delivery` con el Reviewer. La aprobación vale 60 minutos y solo
  para esa versión y ese hash: si el archivo cambia, la entrega se aborta con
  `evidence_mismatch`.
- **Paso 5:** `report.delivered` con el resumen de la entrega como evidencia, y en
  `demo/state/reports/<engagement>/` el archivo `defectdojo-report-v1.json` para importar a
  mano. Volver a correr no entrega de nuevo: la bitácora ya tiene `report.delivered`.

Volver a correr el paso 3 no genera otra versión. `--new-version` genera la siguiente, y la
aprobación anterior deja de valer.

**Qué sale de dónde.** Los hallazgos salen de la entrega que importó el loop C, verificada
contra su `handoff.imported`. El estado de validación sale de la bitácora, no de la entrega.
Los activos de la sección 3 se arman con los hosts web de la entrega que están en el
laboratorio y en el RoE (los demás se listan y no entran), con los puertos de las URL observadas.
En esta demo no muestran tecnologías, así que el aviso del anexo D sale sin producto ni versión.
El informe tampoco dice que es una simulación: en simulación, "validado en sandbox" es el
docker simulado. Tampoco aparecen los registros de relevamiento: el grafo y la bitácora del
runner (`demo/out`) no se leen porque el runner los puede escribir.

Corrida en el laboratorio (20/11/2026, Windows con Docker Desktop, templates de nuclei y tabla
curada firmados por el Reviewer): el pipeline encontró en `dvwa.lab.test` CWE-693, CWE-497 y
CWE-1004 confirmados por nuclei y ZAP con confianza alta, más CWE-1021 y CWE-1275 inconclusos y
los dos CVE sintéticos por versión. El loop C validó CWE-693 (falta CSP) en el sandbox con
POC-CSP-001 y evidencia íntegra. `report-v1` salió con 7 hallazgos (1 validado, 1 alto sin
validar, reconocido con `--ack-unvalidated-high`); el Reviewer lo aprobó por su SHA-256 y la
entrega offline dejó `defectdojo-report-v1.json` y el resumen de la entrega. Estado final
DELIVERED, 21 registros en la bitácora del host, cadena íntegra.

# Práctico integrador: `phantomcorp` en el laboratorio (change 010)

El target del práctico final del curso se puede sumar a la red aislada del PTaaS como servicio
**opcional** (perfil `integrador`). No se copia a este repo: se construye desde tu clon del repo
del curso. Queda en `10.99.0.12` con el nombre `phantomcorp.lab.test`, solo en la red `lab`.

En PowerShell, desde la carpeta del PTaaS (agrega la ruta al `lab/.env` que ya tiene la clave de ZAP):

```powershell
python -c "import pathlib; p=pathlib.Path('lab/.env'); p.write_text((p.read_text() if p.exists() else '') + 'PTAAS_INTEGRADOR_CONTEXT=C:/Users/HP/Desktop/LabsSeguridadInformatica2026/labs/labfinal-practico-integrador/entorno/phantomcorp' + chr(10))"
docker compose -f lab/docker-compose.yml --profile integrador up -d --build
```

La RoE es `demo/roe-integrador.yaml`: solo `phantomcorp.lab.test` / `10.99.0.12/32`, con DVWA y
Juice Shop excluidos. El PTaaS hace recon, análisis y verificaciones **inertes**; la explotación
(hitos R2 a R4 del práctico) se hace a mano desde la consola del curso y no pasa por acá.
Sin `--profile integrador`, el laboratorio es el de siempre.
