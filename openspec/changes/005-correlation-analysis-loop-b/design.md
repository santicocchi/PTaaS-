# Design — Change 005: correlación, análisis y loop B

## Contexto
El loop A (004) termina con un grafo de activos y una entrega: los activos en alcance que tienen una tecnología con versión (`Apache httpd:2.4.25`) y los servicios HTTP que no la tienen. De ahí en adelante hoy solo hay reglas sueltas: `CandidateFinding`, `PrioritizedVuln`, `dedupe`, `priority_score` y `decide_detection`. No hay fuentes de datos, no hay herramientas de análisis conectadas y nadie orquesta el loop B. El red team (009) dejó además una deuda: nuclei y ZAP tienen que recibir un host, no una URL armada por el agente (task 4.1).

```
entrega del loop A ─▶ CORRELATE (solo datos)            ANALYZE (tráfico liviano, sin ataques)
                      cve.lookup ─ epss.lookup ─ cwe.map   nuclei.safe_templates ─ zap.baseline_scan
                              │                                      │
                              ▼                                      ▼
                       CandidateFinding (confianza) ──▶ loop B por candidato ──▶ PrioritizedVuln
                                                        decide_detection         confirmed | discarded
                                                                                 | inconclusive
```

Todo pasa por `Harness.invoke`, con un token de la fase que corresponde: CORRELATE para las consultas de datos y ANALYZE para nuclei y ZAP.

## Decisiones

### D1. Orquestación determinista, igual que el loop A
La correlación y el loop B de este change no usan LLM. `harness/correlate.py` cruza datos con reglas fijas y `harness/analysis.py` decide qué verificación corre en cada iteración. El agente con LLM llega después y solo podrá **proponer** sobre este mismo orquestador. Así todo se testea con fixtures, sin red y sin modelo, y las evals miden al agente contra un comportamiento de referencia conocido.

### D2. Snapshots offline de NVD y EPSS
Respuesta a "formato y actualización de los snapshots":

- **Dónde:** `data/feeds/`, versionado en el repo.
  - `nvd.json`: subconjunto de registros con el formato de la API 2.0 de NVD (`vulnerabilities[].cve` con `id`, `published`, `lastModified`, `metrics`, `weaknesses` y `configurations`).
  - `epss.csv`: el CSV de FIRST, con su encabezado `#model_version:…,score_date:…` y las columnas `cve,epss,percentile`.
  - `manifest.json`: por archivo, la fuente (URL), la fecha de descarga, la cantidad de registros y el SHA-256.
- **Cómo se actualiza:** `tools/build_feeds.py` lo corre **una persona**, con internet y fuera de los tests. Baja de NVD solo los CVE de los productos de la tabla de alias (D3) y el EPSS de esos CVE, y escribe el manifiesto. El resultado se sube en un PR como cualquier otro cambio. Nada consulta internet durante un engagement ni en los tests. *(Desde esta sesión NVD, FIRST y MITRE no son alcanzables; por eso el script se deja listo y la primera descarga real la hace el equipo.)*
- **Integridad:** el cliente verifica el SHA-256 de cada archivo contra el manifiesto al cargarlo. Si no coincide o falta el manifiesto, el feed se trata como **no disponible**: no se generan candidatos por CVE, la corrida queda con un registro de control (`feed.unavailable`) y el engagement sigue.
- **Desactualizado:** `policy.yaml` gana `limits.max_feed_age_days` (30). Un snapshot más viejo se usa igual, porque es lo único que hay sin internet, pero cada candidato que salga de él queda marcado `feed_stale` y baja un nivel de confianza (D4). El informe lo dice. No se frena el engagement por eso: un feed viejo da menos hallazgos, no hallazgos falsos.
- **Tests:** usan fixtures sintéticos con identificadores imposibles (`CVE-2099-…`), como ya hacen las evals. Así ningún test afirma algo sobre un CVE real que no verificamos.

### D3. De tecnología a CPE, sin adivinar
El grafo trae nombres distintos para lo mismo: nmap dice `Apache httpd:2.4.25` y httpx dice `Apache HTTP Server:2.4.25`. Una tabla curada, `data/feeds/cpe_aliases.yaml`, mapea esos nombres a `vendor:product` de CPE (`apache:http_server`).
- Un producto que no está en la tabla **no se busca**. No hay coincidencia aproximada de nombres: es la forma más directa de inventar un CVE.
- La versión se compara con los rangos de `configurations` de NVD (`versionStartIncluding`, `versionEndExcluding` y los demás) como tupla numérica. Una versión que no se puede interpretar (`2.4.x`, vacía) no coincide con nada.
- Las tecnologías salen **del grafo**, no del agente. `cve.lookup` recibe como objetivo el host del activo y el adaptador lee las tecnologías de ese host en el `AssetGraph`, así nadie le puede pasar una tecnología inventada.

### D4. Confianza de un candidato
Respuesta a "criterio de confianza":

| Confianza | Cuándo |
|---|---|
| `high` | Una herramienta de análisis observó el problema directamente: un template de nuclei que matcheó o una alerta de ZAP con confianza High o Confirmed. |
| `medium` | CVE por versión, con la misma versión reportada por **dos** herramientas independientes (httpx y nmap), feed al día y CWE conocido. |
| `low` | CVE por versión reportada por una sola herramienta, o banner de un paquete de distribución (`(Debian)`, `(Ubuntu)`), o `cwe: unknown`, o feed desactualizado. |

El caso de la distribución importa en el laboratorio: DVWA dice `Apache/2.4.25 (Debian)`. Debian corrige vulnerabilidades sin cambiar el número de versión (backport), así que el banner no prueba que el CVE esté presente. Por eso **una versión sola nunca confirma un hallazgo**: un candidato que solo tiene evidencia de versión termina, como mucho, `inconclusive`, y para confirmarlo hace falta evidencia de una herramienta de análisis o una verificación del catálogo en la fase VALIDATE (006).

### D5. Lo que falta queda vacío
- CVE sin EPSS en el snapshot: `epss = null`. No se pone 0.
- CVE sin CWE, o con `NVD-CWE-noinfo` o `NVD-CWE-Other`: `cwe = "unknown"`.
- **CVSS:** se guarda el puntaje base que trae NVD **con su versión** (`cvss_version: "4.0"` o `"3.1"`). Un puntaje 3.1 no se convierte a 4.0, porque las fórmulas son distintas y convertir sería inventar. Si no hay ninguno, no hay puntaje.
- **ATT&CK:** una tabla curada `data/attack_map.yaml` (CWE → técnica) da la técnica cuando aplica, por ejemplo CWE-22 → T1190. Si el CWE no está en la tabla, `attack_technique = null`.

### D6. Prioridad
Respuesta a "¿cómo se pondera EPSS frente a CVSS y criticidad del activo?": se mantiene la fórmula que ya está testeada, `0.6·CVSS + 2.5·EPSS + 0.25·criticidad`.
- **CVSS** pesa más porque mide la gravedad técnica.
- **EPSS** es una probabilidad de explotación de 0 a 1. Con 2.5, un EPSS de 0.9 suma lo mismo que casi 4 puntos de CVSS: una vulnerabilidad media que se explota en la práctica sube por encima de una alta que nadie explota.
- **Criticidad** (1 a 5) desempata entre activos.

Detalles:
- La criticidad sale del RoE, con un campo opcional `criticality` (dominio → 1..5). Si falta vale 3, y el `rationale` dice que es el valor por defecto.
- Sin CVSS no hay prioridad numérica: el hallazgo va al final de la lista con "sin puntaje". No se inventa un CVSS para poder ordenarlo.
- Se prioriza con el puntaje que haya (4.0 o 3.1), y el informe muestra la versión al lado.

### D7. Adaptadores de análisis: host, IP fijada y nada más
Esto resuelve la task 4.1 del red team, igual que httpx en el 004. El objetivo es siempre un **host** canónico. El esquema y el puerto salen de los `http_service` en alcance de ese host en el grafo; si no hay ninguno, se usa `http` y 80. En el MVP solo se analiza HTTP, y HTTPS queda como limitación (SNI, igual que en 004).

**`nuclei.safe_templates`** (verificado con nuclei v3.11.1):
- Comando: `-u http://<ip>:<puerto> -H "Host: <nombre>"`, más `-t <archivo>` por cada template del manifiesto (D9), `-dr` (sin redirecciones), `-pt http`, `-nh` (sin sondeo httpx interno), `-ni` (sin OAST), `-duc`, `-jsonl -silent -nc -ot` y `-rl` desde `policy.yaml`.
- Prohibidos en el perfil: `-fr`, `-fhr`, `-mr`, `-code`, `-esc`, `-lfa`, `-headless`, `-dast`, `-as`, `-nt`, `-ntv`, `-ut`, `-up`, `-ud`, `-p`/`-proxy`, `-config`, `-tp`, `-it`, `-o`, `-r`, `-sr`, `-u` con lista y `-l`.
- Verificado:
  - con `-H "Host: …"` el servidor recibe el nombre pedido y nuclei se conecta a la IP;
  - nuclei lee objetivos de stdin si es un pipe (se colgaba igual que httpx; `default_runner` ya usa `stdin=DEVNULL`);
  - cada línea JSONL trae `template-id`, `matched-at`, `ip`, `extracted-results` e `info.classification.cwe-id`.
- La salida se valida por línea, igual que en 004. Una línea cuya `ip` no sea una de las IP validadas se descarta.

**`zap.baseline_scan`** (verificado con ZAP 2.17.0):
- **Dónde corre ZAP:** como servicio del laboratorio (`zap` en `lab/docker-compose.yml`, en modo daemon y dentro de la red `internal`). El adaptador no lanza un proceso: le habla a la API de ZAP con un conjunto **fijo** de endpoints. No hay ningún `/ascan/` en ese conjunto, y un test lo verifica.
- **Clave de la API:** sale de `PTAAS_ZAP_API_KEY`, sin valor por defecto. Compose no arranca ZAP sin ella y la clave nunca va al repo. ZAP solo acepta llamadas a su API desde la IP del runner.
- **Secuencia por invocación:**
  1. modo `protect`;
  2. contexto nuevo que incluye solo `^http://<ip>(:<puerto>)?/.*`;
  3. regla del replacer que fija `Host: <nombre>`;
  4. regla de rate limit de ZAP con `rate_limit_rps_per_target`;
  5. spider con 1 hilo, profundidad 3, 1 minuto como máximo, limitado al contexto (`subtreeOnly`);
  6. espera a que termine el escaneo pasivo;
  7. lectura de alertas con `baseurl` igual a la IP;
  8. limpieza del contexto y de las reglas.
- **Verificado en una red interna de prueba:**
  - el servidor recibe `Host: <nombre>` y ZAP se conecta a la IP;
  - los enlaces a otros hosts quedan en `urlsOutOfScope` y no se visitan;
  - un `ascan` pedido por API en modo `protect` devuelve `mode_violation`;
  - las alertas traen `pluginId`, `alert`, `risk`, `confidence`, `cweid`, `wascid`, `url` y `evidence`.
- **ZAP arranca sin reglas activas:** `-addonuninstall` de `ascanrules`, `fuzz`, `bruteforce` y `oast`. Verificado: sin `ascanrules`, el catálogo de reglas activas pasa de 53 a 5. Las que quedan vienen de otros add-ons; la lista exacta se cierra en la implementación.
- **Errores:** un ZAP que no responde da `exec_error`, y un timeout esperando el spider o el pasivo da `timeout`. Son los motivos del conjunto cerrado del 004: no hace falta ampliar la bitácora.

### D8. Contradicciones entre ZAP y nuclei
Respuesta a "tratamiento de resultados contradictorios":
- **Que una herramienta no diga nada no contradice a la otra.** ZAP y nuclei miran cosas distintas, así que el silencio no es evidencia en contra.
- **Contradicción** es cuando las dos tienen una verificación **equivalente**, las dos corrieron sobre la misma URL, una la marcó y la otra la dio por buena. La equivalencia sale de una tabla `data/check_equivalences.yaml` (por ejemplo, la regla 10038 de ZAP "CSP Header Not Set" con el template `ptaas-missing-csp`).
- Ante una contradicción el hallazgo queda `inconclusive`, con un `rationale` que nombra las dos verificaciones, y se marca para revisión humana. **Nunca se descarta solo por contradicción.**
- Dos herramientas que coinciden suman evidencia: `dedupe` ya fusiona por (activo, CVE o CWE).

### D9. Templates: allow-list con manifiesto y hash
Respuesta a "reglas para registrar un template" y a "¿quién aprueba?":
- **Qué se anota:** `templates/allowlist/MANIFEST.md` tiene una fila por template: id, archivo, SHA-256, origen (propio, o comunitario con commit), qué detecta, qué pide (solo GET o HEAD), autor, revisor y fecha.
- **Quién aprueba:** un integrante distinto del autor, en el PR que lo agrega, después de pasar el `security-reviewer`. El autor no puede ser el revisor.
- **Control estático (test):**
  - cada archivo de la carpeta está en el manifiesto con su hash, y viceversa;
  - solo hay protocolo `http`, con métodos GET o HEAD y `redirects` apagado;
  - no hay `payloads`, `fuzzing`, `attack`, `code`, `headless`, `dns`, `{{interactsh-url}}` ni rutas absolutas;
  - ningún tag está en `exclude_tags`.
- **Control en ejecución:** el adaptador vuelve a calcular el hash de cada template contra el manifiesto y pasa los archivos uno por uno con `-t`. Un template copiado a la carpeta sin registrar, o modificado después de registrado, no corre. Se descarta la firma de templates de nuclei: obliga a manejar una clave, y el hash en el manifiesto revisado da la misma garantía de integridad.
- **Los ≥ 5 templates del laboratorio son propios** y simples: banner de servidor con versión (CWE-497), `X-Powered-By` con versión (CWE-497), CSP ausente (CWE-693), anti-clickjacking ausente (CWE-1021), cookie de sesión sin `HttpOnly` (CWE-1004) y panel de login de DVWA expuesto (`panel`). No se copia nada de nuclei-templates sin revisarlo.

### D10. Falsos positivos conocidos
Respuesta a "¿qué hace el análisis ante un falso positivo conocido del laboratorio?":
- **Dónde se anotan:** en `data/false_positives.yaml`, con el mismo procedimiento de revisión que un template. Cada entrada lleva id, herramienta y regla o template, patrón de URL, motivo, revisor y fecha.
- **Qué pasa con un hallazgo que coincide:** queda `discarded` con un `rationale` que cita la entrada. **No se borra:** sigue en el informe como descartado, con su motivo, para que se pueda auditar.
- **Qué no puede hacer:** una entrada no puede tapar un CVE ni nada de riesgo alto. Para eso hace falta revisión humana caso por caso, y el test de la lista lo verifica.

### D11. Loop B: por candidato, con un plan fijo
- **Entrada:** los candidatos de la correlación más los servicios HTTP en alcance (D11 del 004: los activos sin versión van directo a análisis).
- **Plan de cada candidato:** las verificaciones que aplican a su CWE o a su tecnología, en un orden fijo. Primero los templates de nuclei cuya `classification` coincide, después ZAP sobre el servicio. ZAP corre **una vez por servicio** y sus alertas sirven para todos los candidatos de ese servicio, para no repetir el spider.
- **Iteración:** cada una ejecuta la siguiente verificación del plan y cuenta la evidencia nueva. `decide_detection(historial, tope, resuelto)` decide si sigue. El tope es `max_loop_iterations.detection` (4).
- **Cuándo se resuelve:**
  - `confirmed`: evidencia de análisis con confianza alta (D4);
  - `discarded`: solo un falso positivo conocido (D10). Que una verificación no encuentre nada no descarta (D8): el silencio no es evidencia en contra;
  - `inconclusive`: contradicción, dos iteraciones sin evidencia nueva, o tope alcanzado.
- **Estado persistido:** como en el loop A, el estado se guarda append-only en `state/<engagement>.findings.sqlite3`: candidatos, evidencia por iteración y resultado. Un reinicio retoma donde quedó, y el tope cuenta entre corridas.
- **Barreras:** se detiene sin reintentar ante kill switch, bitácora rota o token vencido o revocado. Dos salidas inválidas seguidas de la misma herramienta escalan a HITL y la herramienta queda deshabilitada, con el mismo mecanismo del 004.

### D12. Evals
Hoy hay 5 casos de correlación y análisis. Se amplían a 12 como mínimo, cubriendo:
- versión de Debian (confianza `low` y no `confirmed`);
- feed desactualizado;
- CVE con CVSS 3.1 sin 4.0 (no se inventa el 4.0);
- producto fuera de la tabla de alias (sin candidatos);
- contradicción ZAP/nuclei (`inconclusive`);
- falso positivo conocido (`discarded` con motivo);
- dos herramientas que coinciden (`confirmed` con las dos evidencias).

## Cambios a archivos de configuración
- `policy.yaml`: `limits.max_feed_age_days: 30`.
- `profiles.yaml`:
  - nuclei pasa a host más IP, con los flags y prohibidos de D7;
  - se agrega el perfil de ZAP (endpoint de la API, tiempos máximos y opciones del spider).
- `tools.yaml`: `zap.baseline_scan` aclara que corre por API contra el servicio del laboratorio.
- `lab/docker-compose.yml`:
  - nuevo servicio `zap` (`zaproxy/zap-stable` 2.17.0 fijado por digest);
  - IP fija para el runner, porque ZAP solo atiende la API desde ella.
- `lab/runner.Dockerfile`: binario de nuclei v3.11.1.
- `demo/roe-pipeline.yaml` (nuevo): fases `recon`, `correlate` y `analyze`, y `criticality`. `demo/roe-lab.yaml` no cambia, porque el Checkpoint 1 muestra que un token de análisis se rechaza cuando el RoE no autoriza esa fase.
- `lab/docker-compose.yml`: healthcheck propio de ZAP contra 10.97.0.20 (el de la imagen apunta a `localhost`, que la API no acepta).

## Riesgos y limitaciones
- **Snapshot inicial:** desde esta sesión no hay acceso a NVD ni a FIRST. El primer `data/feeds/` real lo genera el equipo con `tools/build_feeds.py`. Hasta entonces la demo corre con un snapshot sintético marcado como tal en el manifiesto, y el informe lo dice.
- **Backports:** la regla de D4 evita afirmar CVE que el paquete de la distribución ya corrigió, pero también hace que esos CVE no se confirmen sin una verificación activa. Es el lado correcto del error.
- **ZAP como servicio:** el runner habla con ZAP por HTTP dentro de la red del laboratorio. ZAP queda en la red `internal`, sin salida, y con la API restringida al runner. Si alguien consiguiera la clave desde otro contenedor del laboratorio, tendría un ZAP casi sin reglas activas (ver la revisión de la implementación).
- **HTTPS:** igual que en el 004, con el `Host` fijado no se manda el SNI correcto. Los objetivos del laboratorio son HTTP.
- **Equivalencias y falsos positivos curados a mano:** son tablas chicas y revisadas. Lo que no está en la tabla no se trata como contradicción ni como falso positivo, y queda en el lado conservador.

## Revisión del security-reviewer (implementación)

La revisión encontró 4 bloqueantes. Los 4 están corregidos, con test, y el delta de spec se actualizó donde cambiaba el comportamiento.

| # | Hallazgo | Corrección |
|---|---|---|
| B1 (alta) | Un candidato por CVE se confirmaba con cualquier observación de su mismo CWE: que ZAP viera que falta el CSP "confirmaba" un CVE de Apache con CWE-693. Violaba D4. | El candidato por CVE no toma evidencia por CWE. Sin una verificación atada al CVE (en el MVP no hay), queda `inconclusive` hasta VALIDATE. Esa evidencia confirma solo su candidato por CWE. Scenario nuevo en vuln-analysis. |
| B2 (media) | El spider de ZAP completa y envía formularios por defecto, también POST (login del DVWA, setup, reset). | `setOptionProcessForm` y `setOptionPostForm` en `false` antes del spider. Verificado en el lab: el DVWA recibe de ZAP solo GET. |
| B3 (media) | El loop B (y el correlador) corrían con un token válido aunque el engagement no hubiera pasado por el gate `first_active_action`. | Los dos reciben el `Engagement` y no invocan nada fuera de `ANALYZE` / `CORRELATE`. Requisitos nuevos en vuln-analysis y correlation. |
| B4 (media, proceso) | Con una contradicción en una URL y evidencia fuerte en otra, el candidato quedaba `confirmed`. La spec dice `inconclusive`. | Ahora queda `inconclusive` con `needs_review`, y el `rationale` cita la contradicción y la evidencia fuerte. |

Mejoras de la misma revisión que también se hicieron:
- **Sesión de ZAP por corrida (M1):** `newSession` al empezar y al terminar. Ya no se atribuyen alertas de otra corrida o de otro engagement a este host, y ZAP no retiene historial del objetivo.
- **Clave de la API (M2):** viaja en `X-ZAP-API-Key` y no en la URL; el cliente no sigue redirecciones y los errores no encadenan la excepción original (que tenía la URL).
- **Prefijo de `baseurl` (M3):** se pide con la barra final, así `10.99.0.2` no trae alertas de `10.99.0.20`.
- **Control estático (M4):** rechaza tags escritas como lista y templates que fijan su propio `Host`.
- **Limpieza de ZAP (M5):** `stop` con el `scanId`, cada paso se intenta aunque falle otro, y al empezar se borran reglas de Host `ptaas-*` que haya dejado una corrida cortada.
- **Riesgo de nuclei (M7):** sale de la severidad del template, así un falso positivo no tapa un hallazgo alto de nuclei.
- **Puerto de nuclei (M10):** un resultado en un puerto que no se sondeó se descarta.
- **Scenario «enlace a otro host»:** ahora tiene test (la regex del contexto excluye `203.0.113.7`, `10.99.0.20`, otro puerto, HTTPS y `user@`).

Quedan como limitaciones conocidas, para el 006 o el informe:
- **Reglas activas que quedan en ZAP (M6):** después de desinstalar `ascanrules`, quedan 5 (40026 DOM XSS, 50000 scripts, 90026 y 90029 SOAP, 100043 Swagger). El adaptador no tiene ningún endpoint `/ascan/` y el modo es `protect`, pero un proceso del runner con la clave podría pedir un escaneo activo dentro del contexto mientras corre. Se puede cerrar desinstalando esos add-ons.
- **Clave en el argv de ZAP y en el entorno del runner (M2):** visible con `docker inspect`. Para el laboratorio se acepta; fuera de él iría en un secret montado con `-configfile`.
- **Aprobación de templates y falsos positivos (M4):** cualquier revisor distinto de "pendiente" y del autor aprueba. El control real es la revisión del PR; conviene CODEOWNERS y protección de rama sobre `templates/allowlist/`, `data/` y `harness/profiles.yaml`.
- **Integridad de los feeds (M11):** el manifiesto detecta cambios accidentales, no uno malicioso que también lo recalcule. De nuevo, el control es la revisión del PR.
- **Kill switch durante una espera (M8):** ZAP (hasta 300 s) y nuclei (hasta 600 s) no lo revisan mientras corren. Es el mismo patrón que en el 004.
- **Datos hostiles en el informe (M9):** rutas y evidencia vienen del objetivo. El 007 las tiene que escapar al renderizar.
- **nuclei sin templates aprobados (M13):** el paso queda hecho y, si después se aprueban, no vuelve a correr en ese engagement. Hay que arrancar otro.
- **nmap envía un POST de sondeo (004):** en la corrida del lab apareció `POST /sdk` (400) de las sondas de versión de nmap. No cambia estado, pero va contra "solo lectura": revisar el perfil de nmap en un próximo change.
