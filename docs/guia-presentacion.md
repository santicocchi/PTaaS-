# Guía para instalar, presentar y mostrar PTaaS

Tres partes:

1. Cómo instalarlo y correrlo en otra máquina.
2. Qué contar en la presentación.
3. Los comandos de la demo, con el resultado que tiene que salir en cada uno.

Los comandos están pensados para **Windows con PowerShell**, que es donde se hizo la corrida
real del 20/11/2026. Cada uno va en una sola línea. Al final de la parte 1 está la versión
para Linux o macOS.

---

## 1. Instalar y correr en otra máquina

### Qué hace falta

| Programa | Para qué |
|---|---|
| Python 3.12 (con "Add to PATH") | el harness, los tests y las demos que corren en el host |
| Git | clonar el repo |
| Docker Desktop, abierto | el laboratorio: DVWA, Juice Shop, ZAP, el runner y el sandbox |

No hace falta instalar nmap, nuclei ni ZAP en la máquina. Vienen dentro de las imágenes de
Docker y solo corren en la red aislada del laboratorio.

### Paso a paso

```powershell
git clone https://github.com/santicocchi/PTaaS-.git
```
```powershell
cd PTaaS-
```
```powershell
python -m venv .venv
```
```powershell
.venv\Scripts\Activate.ps1
```
Si PowerShell no deja activar el entorno, corré esto antes y volvé a probar (vale solo para
esa ventana):
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
```powershell
pip install -r requirements-dev.txt
```

**Comprobar que todo anda, sin Docker:**
```powershell
python -m pytest -q
```
Tiene que dar `1170 passed, 2 skipped` (los 2 que se saltean necesitan el laboratorio).
```powershell
python evals/run_evals.py --mode golden
```
Tiene que dar `37/37 casos aprobados`.

**Levantar el laboratorio (la primera vez tarda unos minutos):**

1. La clave de la API de ZAP. Se genera en tu máquina y queda en `lab/.env`, que git ignora.
   Hacelo con este comando y no con `echo ... > lab\.env`: PowerShell guardaría el archivo en
   otra codificación y Docker no lo lee.
   ```powershell
   python -c "import secrets,pathlib; pathlib.Path('lab/.env').write_text('PTAAS_ZAP_API_KEY=' + secrets.token_hex(16) + chr(10))"
   ```
2. DVWA, Juice Shop, ZAP y el runner, en una red `internal: true` sin salida a internet.
   ```powershell
   docker compose -f lab/docker-compose.yml up -d --build
   ```
3. La imagen del sandbox del loop C. Solo se construye, no queda corriendo.
   ```powershell
   docker compose -f lab/docker-compose.yml --profile build build sandbox
   ```

Para apagar todo al terminar:
```powershell
docker compose -f lab/docker-compose.yml down
```

### Lo que ya viene firmado en el repo

Estas firmas ya están hechas, así que en otra máquina no hay que repetirlas:

- `templates/allowlist/MANIFEST.md`: los 6 templates de nuclei, con revisor `santiago`.
  Si alguien cambia un `.yaml`, el hash deja de coincidir y ese template no corre.
- `data/report_catalog.yaml` y `demo/report_catalog_sim.yaml`: la tabla curada del informe.
  El autor es `claude` y el revisor `santiago`.

Lo que **no** viaja con el repo, porque se genera en cada máquina:

- `lab/.env`, con la clave de ZAP.
- `demo/out/` y `demo/state/`, con las bitácoras, las aprobaciones, la evidencia y los informes.

### En Linux o macOS

Los mismos pasos cambian en tres comandos:

- Activar el entorno: `source .venv/bin/activate`.
- La clave de ZAP: `echo "PTAAS_ZAP_API_KEY=$(openssl rand -hex 16)" > lab/.env`.
- Las rutas de `--state-dir` y `--audit-dir` van con `/`: `demo/state`.

---

## 2. Qué contar en la presentación

### En una frase

Construimos una plataforma de **pentest autorizado** con agentes de IA, donde lo que se puede
y lo que no se puede hacer **no lo decide el modelo sino el código**:

- un guard determinista;
- tokens firmados por fase;
- una bitácora que no se puede borrar;
- gates humanos antes de cada paso que toca el objetivo.

### El recorrido (lo que hace el sistema)

| Etapa | Qué hace | Herramientas | Control |
|---|---|---|---|
| RoE | Reglas de enfrentamiento: alcance, exclusiones, ventana, fases | `harness/roe.py` | Se aprueba por SHA-256. Si se toca después, no vale. |
| Relevamiento (loop A) | Descubre hosts y servicios hasta que el grafo se estabiliza | subfinder, httpx, nmap | Token de fase recon. Lo fuera de alcance queda en el grafo pero no se toca. |
| Correlación | Cruza versiones con CVE, CVSS y EPSS | snapshots offline de NVD, EPSS y CWE | Sin internet. Una coincidencia solo por versión nunca pasa de confianza media. |
| Análisis (loop B) | Busca fallas concretas y prioriza | nuclei (6 templates firmados) y ZAP pasivo | Solo templates revisados por una persona. ZAP en modo protegido. |
| Validación (loop C) | Confirma cada hallazgo en un contenedor efímero | catálogo de 6 verificaciones inertes (GET o HEAD) | Gate humano por fase y otro por hallazgo. No se generan exploits. |
| Informe y entrega | Informe PTES con CWE, CVSS v4.0 y remediación, exportado a DefectDojo | `harness/reporting.py`, `harness/delivery.py` | El Reviewer aprueba esa versión exacta, por su SHA-256. |

### Los controles (lo que hace que sea "autorizado")

1. **Todo pasa por `Harness.invoke`.** Ningún agente llama a una herramienta directamente. Un
   hook de Claude Code bloquea incluso que el asistente de desarrollo lo haga.
2. **Scope Guard determinista, sin LLM.** Revisa el alcance, las exclusiones, la fase, la
   allow-list de herramientas y la IP a la que resuelve el DNS.
3. **Scope tokens.** Uno por fase, firmados con HMAC y de 60 minutos como máximo. Si un agente
   se "agranda" el token, la firma deja de coincidir.
4. **Bitácora append-only con hash encadenado.** Registra todo, incluidos los bloqueos. Un
   `UPDATE` lo rechaza un trigger, y si alguien borra el trigger, `verify` detecta la cadena rota.
5. **Kill switch persistente.** Vive en la bitácora, así que reiniciar el proceso no lo apaga.
6. **Gates humanos (HITL).** Hay tres:
   - abrir la fase de validación;
   - validar cada hallazgo, con una aprobación atada al hash de la solicitud;
   - entregar el informe, con una aprobación atada al SHA-256 de esa versión.

   Cada una vence a los 60 minutos y queda en la bitácora. Ninguna la puede dar el agente: el
   asistente de desarrollo tampoco pudo aprobar nada durante el trabajo.
7. **Solo laboratorio.** DVWA y Juice Shop en una red Docker `internal: true`. Juice Shop está
   en el alcance pero excluido en el RoE, para mostrar que la exclusión funciona.

### Cómo lo construimos

- **Spec-driven con OpenSpec:** propose → review → implement → archive. Cada comportamiento
  nuevo empieza como un Scenario Given/When/Then, y cada Scenario es primero un test.
- **Sprint 1** (PRs #1 a #8):
  - endurecimiento de specs (008);
  - persistencia de la bitácora (002);
  - RoE y tokens (003);
  - red team del guard (009): 16 ataques convertidos en 45 tests, que también se corrigieron;
  - demo del Checkpoint 1.
- **Sprint 2:**
  - relevamiento real (004);
  - correlación y análisis con nuclei y ZAP (005);
  - Checkpoint 2, con evals;
  - sandbox y loop C (006);
  - informe y DefectDojo (007, PRs #18 a #23).
- **Antes de cerrar cada change:** tests en verde y una revisión del agente `security-reviewer`.
  Esa revisión encontró problemas reales que se corrigieron, por ejemplo:
  - que se pudiera entregar dos veces;
  - un informe que decía "validado" sin haber pasado por el Harness;
  - cookies sin redactar en un archivo sellado.

### Números para la diapositiva

| Qué | Cuánto |
|---|---|
| Tests | 1170 en verde (1172 recolectados) |
| Evals golden | 37/37 |
| Scenarios en las specs | 345, en 10 capabilities |
| Changes | 002 a 009 cerrados (005 y 006 con una task opcional abierta) |
| PRs mergeados | 23 |
| Agentes con prompt propio | orquestador, relevamiento, correlación, análisis, validación, informe y triage, más el Reviewer humano |

### Corrida real en el laboratorio (20/11/2026)

- **Pipeline:** sobre `dvwa.lab.test`, 7 hallazgos.
  - CWE-693 (falta CSP), CWE-497 (versión expuesta en `Server`) y CWE-1004 (cookie sin
    HttpOnly) confirmados por nuclei y ZAP.
  - CWE-1021 (clickjacking) y CWE-1275 (SameSite) inconclusos.
  - Dos CVE del feed sintético, encontrados solo por la versión.
- **Loop C:** el Reviewer aprobó CWE-693, que se validó en el sandbox con POC-CSP-001 y
  evidencia íntegra. CWE-1021 quedó esperando su aprobación, porque cada hallazgo se aprueba
  por separado.
- **Informe:** `report-v1`, aprobado por su SHA-256 y entregado como archivo de importación
  de DefectDojo. Estado final `DELIVERED`, 21 registros en la bitácora y la cadena íntegra.

### Lo que hay que decir con honestidad

- Los CVE `CVE-2099-…` son de un **feed sintético**. El real se genera con
  `tools/build_feeds.py` y todavía no lo subimos.
- La entrega a DefectDojo fue **offline**: un JSON para importar. El modo API está
  implementado y probado contra un DefectDojo falso, pero no contra uno real.
- Las evals están en modo golden. El modo `live`, que llama al modelo, está listo pero no se
  corrió con la clave del equipo.
- Los riesgos aceptados están en el `design.md` de cada change. Por ejemplo, el Reviewer es
  quien tenga acceso al host del laboratorio.

---

## 3. La demo, comando por comando

Hay dos demos. Elegí según el tiempo que tengas.

### Opción A: Checkpoint 1, 5 minutos, sin Docker

Muestra los controles uno por uno: RoE, tokens, guard, DNS envenenado, gate humano, kill
switch y bitácora. No envía tráfico.

```powershell
python -m demo.checkpoint1 --pausa
```

`--pausa` espera un Enter entre pasos, así podés explicar cada uno. Lo que tiene que salir:

| Paso | Resultado |
|---|---|
| 1 | `roe_invalid (4 errores)`: falta el contacto de emergencia, `0.0.0.0/0`, `example.com` y una fecha sin zona horaria |
| 2 | `RoE válido aprobado por reviewer@lab sha256=…`; al borrar la exclusión, `roe_tampered` |
| 3 | `token recon emitido vence en 60 min`; el pedido de token analyze, `phase_not_in_roe` |
| 4 | `PERMITIDA recon-agent → nmap.service_scan sobre dvwa.lab.test` |
| 5 | `BLOQUEADA` cuatro veces: `out_of_scope`, `excluded` (Juice Shop), `wrong_phase` y `not_allowlisted` (sqlmap) |
| 6 | Token agrandado → `token_invalid` |
| 7 | DNS envenenado → `dns_out_of_scope` |
| 8 | `EN ESPERA … falta aprobación humana (HITL)`; el reviewer aprueba y pasa a `PERMITIDA`, `POC-HDR-001: validated` |
| 9 | `ABORTADA … kill switch activo`, y después de reiniciar, sigue `ABORTADA` |
| 10 | Tabla de 15 registros, `OK: cadena íntegra`, `UPDATE prohibido`, y en la copia manipulada `CADENA ROTA: seq=4` |

Al final: `Resumen: 2 acciones ejecutadas, 7 bloqueadas, 15 registros`.

La misma demo con nmap de verdad contra DVWA (necesita el laboratorio levantado):
```powershell
docker compose -f lab/docker-compose.yml exec runner python -m demo.checkpoint1 --lab --pausa
```

### Opción B: el recorrido completo en el laboratorio, 10 a 15 minutos

Con el laboratorio levantado (parte 1). Son seis comandos. Los pasos 3 y 5 los hace el
Reviewer, que sos vos.

**Importante:** cada corrida crea un engagement nuevo, con la fecha y la hora en el nombre.
Los ejemplos usan el de la corrida real, `demo-pipeline-20261120-070022`. En tu corrida
copiá el nombre que imprime el paso 1, y los hashes que imprimen los pasos 2 y 4. La demo
imprime cada comando ya armado: solo cambiás el usuario y el motivo.

**1. Pipeline: relevamiento, correlación y análisis** (corre dentro del runner)
```powershell
docker compose -f lab/docker-compose.yml exec runner python -m demo.pipeline --lab
```
Resultado:
```
Pipeline 005 · demo-pipeline-20261120-070022 · LABORATORIO REAL (red aislada)
── 1. Relevamiento (estado RECON)
   grafo estabilizado; 1 activos con versión, servicios web en: dvwa.lab.test
── 2. Correlación (estado CORRELATE)
   Snapshot SINTÉTICO: los CVE-2099-… son datos de prueba, no CVE reales.
   ok; 2 candidatos por versión
── 3. Análisis (estado ANALYZE)
   nuclei: 6 templates aprobados, 0 sin correr
   ok; 7 vulnerabilidades priorizadas
   prioridad  estado       qué              host                 confianza
        7.27  inconclusive CVE-2099-0001    dvwa.lab.test        low
        4.18  inconclusive CVE-2099-0002    dvwa.lab.test        low
           —  confirmed    CWE-1004         dvwa.lab.test        high
           —  inconclusive CWE-1021         dvwa.lab.test        medium
           —  inconclusive CWE-1275         dvwa.lab.test        medium
           —  confirmed    CWE-497          dvwa.lab.test        high
           —  confirmed    CWE-693          dvwa.lab.test        high
   tool.error dvwa.lab.test → ABORTED exit_code
OK: cadena íntegra
```
El `tool.error … exit_code` es subfinder. Sus fuentes están en internet y el runner no tiene
salida, así que falla, queda registrado, y el loop sigue con los hosts del RoE. Sirve para
mostrar que la red está aislada de verdad.

**2. El Reviewer abre la fase de validación** (corre en tu máquina, no en el runner)
```powershell
python -m demo.validation --lab --engagement demo-pipeline-20261120-070022 --approve-phase --reviewer santiago
```
Resultado:
```
   entrega importada a demo\state (SHA-256 011a4854b187…)
   gate before_validate: aprobado por santiago (en la bitácora)
   ok; 7 hallazgos
   f-267975a2afd3e289 pending_hitl   falta aprobación del Reviewer  CWE-693   POC-CSP-001
   f-64f93c9b0452c40e pending_hitl   falta aprobación del Reviewer  CWE-1021  POC-HDR-001
   (los otros 5: not_validated  no_catalog_entry)
OK: cadena íntegra
```
Abajo imprime el comando de aprobación de cada pendiente, con el hash de la solicitud.

**3. El Reviewer aprueba un hallazgo**
```powershell
python -m harness.review --engagement demo-pipeline-20261120-070022 --state-dir demo\state --audit-dir demo\state approve f-267975a2afd3e289 --request e1d7815d0f0c --reviewer santiago --reason "verificar falta de CSP en el lab"
```
Resultado: `f-267975a2afd3e289: approved por santiago`.

**4. Se valida solo lo aprobado, en el sandbox**
```powershell
python -m demo.validation --lab --engagement demo-pipeline-20261120-070022
```
Resultado:
```
   f-267975a2afd3e289 validated      -                              CWE-693   POC-CSP-001
      evidencia evidence/demo-pipeline-20261120-070022/f-267975a2afd3e289-1.… íntegra
   f-64f93c9b0452c40e pending_hitl   falta aprobación del Reviewer  CWE-1021  POC-HDR-001
   control  hitl.approve                 dvwa.lab.test    OK   [f-267975a2afd3e289]
   validate poc_catalog.run_parametrized dvwa.lab.test    OK   [f-267975a2afd3e289]
OK: cadena íntegra
```
Para mostrar que el contenedor no quedó vivo:
```powershell
docker ps -a --filter label=ptaas.sandbox
```
La lista sale vacía.

**5. Se genera el informe**
```powershell
python -m demo.report --engagement demo-pipeline-20261120-070022
```
Resultado:
```
   report-v1 generado: demo\state\reports\demo-pipeline-20261120-070022\report-v1.json y …\report-v1.md
   report-v1 · SHA-256 3c002a1babf5 · 7 hallazgos (1 validados, 6 sin validar, 1 altos o críticos sin validar)
   report-v1 espera la aprobación del Reviewer (pending).
   report.generated           report-builder         OK            [report-v1]
   report.delivery            report-delivery        PENDING_HITL  [report-v1]
OK: cadena íntegra
```
Para leer el informe antes de aprobarlo:
```powershell
notepad demo\state\reports\demo-pipeline-20261120-070022\report-v1.md
```

**6. El Reviewer aprueba esa versión, y se entrega**
```powershell
python -m harness.review --engagement demo-pipeline-20261120-070022 --state-dir demo\state --audit-dir demo\state report approve report-v1 --sha256 3c002a1babf5 --ack-unvalidated-high --reviewer santiago --reason "informe del lab revisado"
```
Resultado: `report-v1: approved por santiago`.

`--ack-unvalidated-high` hace falta porque hay un hallazgo alto sin validar (el CVE sintético).
El Reviewer reconoce explícitamente que lo entrega igual.

```powershell
python -m demo.report --engagement demo-pipeline-20261120-070022
```
Resultado:
```
   entregado (offline) · estado DELIVERED
   exportación para DefectDojo: reports/demo-pipeline-20261120-070022/defectdojo-report-v1.json
   resumen de la entrega:       reports/demo-pipeline-20261120-070022/delivered-report-v1.json
Bitácora del host (21 registros; los del informe y su camino):
   handoff.imported           validation-demo        OK
   gate.approve               reviewer:santiago      OK
   validation.attempt         validation-orchestrator OK            [f-267975a2afd3e289]
   report.generated           report-builder         OK            [report-v1]
   report.delivery            report-delivery        PENDING_HITL  [report-v1]
   hitl.approve_delivery      reviewer:santiago      OK            [report-v1]
   report.delivered           report-delivery        OK            [report-v1]
OK: cadena íntegra
```

### Momentos para mostrar en vivo, si sobra tiempo

- **No se entrega dos veces.** Corré de nuevo el último comando. Dice
  `ya entregado (report.delivered en la bitácora)` y no se entrega otra vez.
- **Si el informe cambia, la aprobación no vale.** En otra corrida, después de aprobar y antes
  del último `demo.report`, editá una palabra de `report-v1.md`. La entrega se aborta con
  `evidence_mismatch` y queda en la bitácora. Esa versión ya no se puede entregar: hay que
  generar otra con `--new-version` y aprobarla de nuevo. Por eso conviene mostrarlo al final.
- **Sin aprobación no se valida nada.** En el paso 4, CWE-1021 sigue `pending_hitl` porque
  nadie lo aprobó, aunque está en el mismo host.

### Ensayo sin laboratorio (simulación)

Es el mismo recorrido sin `--lab` y sin Docker: las herramientas devuelven salidas grabadas y
el sandbox es simulado. Sirve para practicar el guion. Las decisiones del guard, los tokens,
las aprobaciones y la bitácora son el código real.

```powershell
python -m demo.pipeline
```
En simulación aparecen dos hosts (`dvwa.lab.test` y `www.dvwa.lab.test`) y 12 vulnerabilidades,
con 6 templates aprobados. Después siguen los mismos pasos 2 a 6 sin `--lab`, con el
engagement que imprime el pipeline. Una entrega de simulación no se puede validar con `--lab`,
ni al revés.
