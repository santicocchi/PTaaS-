# Checkpoint 2: Sprint 2 (conectar el swarm)

El plan pide para este checkpoint una demo de recon → correlación → análisis sobre el laboratorio, con
bitácora verificable y resultados de evals. Los comandos están en [`demo/README.md`](../demo/README.md),
en las secciones "Loop A" y "Pipeline".

## Qué se cerró en el sprint

| Change | Qué agrega | Revisión de seguridad |
|---|---|---|
| 004 recon-loop-a | Loop A con subfinder, httpx y nmap. Grafo de activos persistido. IP fijada por el Harness (`-u http://ip -H Host`). Rate limit por IP. Runner de solo lectura. | Hallazgos corregidos con test (`design.md` del 004) |
| 005 correlation-analysis-loop-b | Snapshots offline de NVD/EPSS con manifiesto. Confianza por reglas. nuclei con templates propios en una allow-list con hash y revisor. ZAP por API en modo protegido. Loop B con contradicciones, falsos positivos y prioridad. | 4 bloqueantes y 6 mejoras corregidos con test (`design.md` del 005) |

Specs: 181 Scenarios en `openspec/specs/` (con los deltas del 004 y del 005 archivados). Tests: 620 en verde.

## Guion de la demo (unos 8 minutos)

Antes de empezar, con el laboratorio levantado (`lab/.env` con la clave de ZAP, ver `demo/README.md`):

```bash
docker compose -f lab/docker-compose.yml exec runner python -m demo.pipeline --lab
python -m harness.audit verify demo/out/demo-pipeline-<fecha-hora>.sqlite3
```

| Paso | Qué se ve | Qué decir |
|---|---|---|
| 1 | El RoE `demo/roe-pipeline.yaml`: alcance 10.99.0.0/24, Juice Shop excluido, fases recon/correlate/analyze, criticidad del DVWA = 4 | Un token por fase y nada más. El RoE del Checkpoint 1 no autoriza analyze, y por eso es otro archivo. |
| 2 | Relevamiento: Juice Shop queda como `excluded` en el grafo y no llega a ninguna herramienta | El orquestador consulta al Guard antes de encolar. Además el Harness lo vuelve a frenar (defensa en profundidad). |
| 3 | Correlación: aviso de snapshot **SINTÉTICO**; CVE-2099-0001/0002 con confianza **baja** | No sale nada a internet. `(Debian)` en el banner implica un posible backport, así que una versión sola nunca da `high`. |
| 4 | Análisis: "nuclei: N templates aprobados". Si hay alguno `pendiente`, lo lista y no lo corre. | Cada template tiene hash y un revisor distinto del autor. Un template modificado no corre. |
| 5 | Tabla de vulnerabilidades: CWE-693, 497 y 1004 `confirmed`; los CVE `inconclusive` | Confirmar exige evidencia de confianza alta de nuclei o ZAP. Los CVE esperan a VALIDATE (sprint 3). |
| 6 | Bitácora por fase y `verify` OK | Cada invocación queda registrada antes de ejecutarse, y los controles (`token.issue`, `asset.discovered`) también. |
| 7 (opcional) | `docker logs lab-dvwa-1` durante la corrida: ZAP solo hace GET | El spider no envía formularios (lo encontró el security-reviewer y quedó con test). |

**Si algo falla en vivo:** `python -m demo.pipeline` (simulación) muestra lo mismo con salidas grabadas.

## Evals

```bash
python evals/run_evals.py --mode golden                                    # CI, sin red
ANTHROPIC_API_KEY=... python evals/run_evals.py --mode live --report evals/out/live-<fecha>.json
```

29 casos repartidos en 5 agentes (7 de validación los sumó el change 006):
- orchestrator: 3;
- asset_discovery: 3;
- correlation: 7;
- vuln_analysis: 6;
- validation: 10.

Cada regla de seguridad tiene un test que comprueba que la rúbrica la hace **fallar** cuando la salida está mal, por ejemplo:
- sondear `cdn.example.com`;
- planificar `validate` sin autorización;
- confirmar por versión;
- descartar por contradicción.

El modo `live` usa el prompt de `prompts/` y el modelo de `harness/models.yaml`, y puntúa la respuesta con la misma rúbrica. Sus reglas:
- sin `ANTHROPIC_API_KEY` no llama al modelo;
- un error de la API marca el caso y sigue con el resto;
- con `--report` guarda cada respuesta cruda, las violaciones y los tokens usados;
- `evals/out/` está ignorado por git, así que el informe que va al trabajo se sube a mano.

### Qué cambió antes de la corrida en vivo

- **Prompts alineados con las specs del 004 y el 005** (00, 02, 03 y 04). Los prompts originales del kit no decían nada de:
  - backports;
  - `feed_stale`;
  - contradicciones y `needs_review`;
  - fases que el RoE no autoriza;
  - el formato exacto de la salida.

  Con esos prompts, los casos nuevos habrían fallado por falta de instrucciones y no por el modelo.
- **vuln-001 corregido:** la alerta de ZAP no traía su confianza, así que, según la regla del 005, el caso no podía quedar `confirmed`. Ahora trae `confidence: High`.

### Informe de la corrida en vivo (para completar el equipo)

| Agente | Casos | Pasaron | Qué falló y por qué | Qué cambiamos |
|---|---:|---:|---|---|
| orchestrator | 3 | | | |
| asset_discovery | 3 | | | |
| correlation | 7 | | | |
| vuln_analysis | 6 | | | |
| validation | 3 | | | |

El análisis sale del JSON de `--report`. Para cada falla, anotar:
- si la regla estaba en el prompt;
- si el modelo devolvió otro formato;
- si inventó un dato (CVE, EPSS, CWE).

Todo cambio de prompt después de esta corrida va con otra corrida del agente afectado (spec `agent-contracts`).

## Pendientes para el checkpoint

- **Firmar los templates:** poner un revisor del equipo en `templates/allowlist/MANIFEST.md`. Sin eso nuclei no corre en la demo, y el paso 4 muestra por qué.
- **Snapshot real de NVD/EPSS:** generarlo con `tools/build_feeds.py` desde una máquina con internet. Mientras tanto la demo usa el sintético y lo avisa.
- **Corrida en vivo de las evals:** con la clave del equipo, y completar la tabla de arriba.

## Limitaciones conocidas (detalle en cada `design.md`)

- La clave de ZAP está en el argv del contenedor y en el entorno del runner. Para el laboratorio se acepta; fuera de él iría en un secret montado.
- Quedan 5 reglas activas en ZAP (DOM XSS, scripts, SOAP, Swagger). El adaptador no puede pedirlas, pero se pueden desinstalar.
- El kill switch no corta una espera de ZAP o de nuclei que ya está en curso.
- Las sondas de versión de nmap mandan un `POST /sdk` (400). No cambia estado, pero conviene revisar el perfil.

## Próximo sprint

El 006 (sandbox y loop C): verificaciones del catálogo dentro de un contenedor efímero, con gate humano por hallazgo. Después, el 007 (informe y DefectDojo).
