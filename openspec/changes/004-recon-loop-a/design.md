# Design — Change 004: recon real y loop A

## Contexto
Hoy el loop A es solo una regla de parada (`decide_recon`). No hay adaptadores de recon pasivo ni de sondeo HTTP, no hay grafo de activos persistido y nadie orquesta las iteraciones. Además, el red team (009) dejó dos deudas que viven en este change: las redirecciones HTTP (A5) y el DNS rebinding, es decir, que la herramienta resuelva el nombre otra vez y llegue a una IP distinta de la que validó el Harness.

```
semillas del RoE ─▶ ┌──────────── iteración i ────────────┐
                    │ 1. pasivo: subfinder.enum (dominios)│
                    │ 2. activo: httpx.probe (hosts)      │──▶ AssetGraph (versión i)
                    │ 3. activo: nmap.service_scan (hosts)│        │
                    └─────────────────────────────────────┘        │
                     todo por Harness.invoke ▲                     ▼
                                             └── decide_recon(i, nuevos, tope)
                                                  continue │ stop ──▶ entrega a correlación (005)
```

## Decisiones

### D1. El orquestador es determinista
El loop A de este change no usa LLM. El orquestador (`harness/recon.py`) arma las acciones a partir del grafo y le pide permiso al Harness para cada una. El agente de recon con LLM llega después y solo podrá **proponer** acciones al mismo orquestador; las reglas de qué se sondea y cuándo se para no cambian. Así el loop A se puede testear completo con fixtures, sin red y sin modelo.

### D2. Semillas y orden pasivo → activo
- **Semillas:** los dominios del RoE que no estén excluidos. Las IP y CIDR del RoE **no** se barren: en el MVP no hay descubrimiento de hosts por rango (sería `nmap -sn` y no está en el perfil). Una IP entra al grafo solo si la descubre un adaptador o si figura suelta en el RoE como /32.
- **Orden por iteración:** primero `subfinder.enum` sobre cada dominio nuevo, después `httpx.probe` sobre cada host nuevo y por último `nmap.service_scan` sobre cada host nuevo. Una técnica activa no se lanza sobre un activo hasta que terminó la pasiva de esa iteración.
- **Gate:** el orquestador exige que el engagement esté en `RECON`, lo que ya requiere la aprobación `first_active_action` de la máquina de estados. Sin esa aprobación no corre ni lo pasivo.

### D3. Adaptadores nuevos

| Capability | Herramienta | Entrada | Salida | Notas |
|---|---|---|---|---|
| `subfinder.enum` | subfinder | un dominio del alcance (nunca IP) | JSONL `{host, input, source}` | Pasivo: no le manda nada al objetivo, pero consulta fuentes públicas |
| `httpx.probe` | httpx | IP validada + nombre en `Host` | JSONL `{url, host, port, status_code, title, webserver, tech}` | Sin seguir redirecciones, con rate limit |

Igual que nmap y nuclei, los argumentos fijos y los prohibidos viven en `profiles.yaml`. Prohibidos:
- subfinder: `-all`, `-recursive`, `-nW`/`-active`, `-oI`/`-ip`, `-proxy`, `-dL`/`-list`, `-config`, `-pc`/`-provider-config`. Los dos primeros amplían las fuentes, los dos siguientes lo vuelven activo (resuelve los nombres), y el resto mete entrada o configuración que el perfil no controla.
- httpx: `-fr`/`-follow-redirects`, `-fhr`/`-follow-host-redirects`, `-maxr`/`-max-redirects`, `-l`/`-list`, `-proxy`/`-http-proxy`, `-x` (métodos), `-body`, `-path`.

Flags verificados contra httpx v1.12.0 y subfinder v2 (`-h`). Con `-u http://<ip> -H "Host: <nombre>"`, httpx manda el `Host` pedido, no hace consultas DNS y no prueba HTTPS. Ante un 302 no sigue la redirección y devuelve el destino en `location`.

**Proxy:** httpx usa `HTTP_PROXY`/`HTTPS_PROXY` del entorno si existen. `safe_env()` pasa a quitar también las variables de proxy: el tráfico al laboratorio nunca sale por un proxy.

**subfinder en el laboratorio.** Las fuentes pasivas están en internet y el runner no tiene salida, así que en el laboratorio subfinder devuelve vacío o falla. Es lo correcto: en desarrollo no se consultan servicios de terceros. Los tests usan fixtures, y el loop A trata el vacío como "sin activos nuevos", no como error.

### D4. IP fijada contra DNS rebinding (task 4.2)
El Harness ya resuelve el nombre y valida **todas** sus IP antes de ejecutar (A4). El problema es que después la herramienta resuelve otra vez y un DNS hostil puede contestarle otra cosa. La solución es que la herramienta no resuelva:

- `ToolAdapter.run(action, target, token, addresses)`: el Harness le pasa al adaptador las IP que validó (`addresses`). Si el objetivo ya es una IP, `addresses = (target,)`. Es un parámetro obligatorio, no opcional: un adaptador que no lo acepte falla contra el Protocol en `mypy --strict` y en el test de contrato. Que además lo **use** se prueba en el test de argv de cada adaptador (el comando lleva la IP, no el nombre).
- `nmap.service_scan` escanea las IP de `addresses`, no el nombre.
- `httpx.probe` sondea `http://<ip>` con el encabezado `Host: <nombre>`. Así el servidor virtual correcto contesta y httpx no hace ninguna consulta DNS.
- `subfinder.enum` es la excepción: no se conecta al objetivo, así que no hay IP que fijar. Recibe `addresses` y lo ignora, y queda documentado.

Es un cambio de firma del contrato (`agent-contracts` / `authorization`): se actualizan `FakeAdapter`, nmap y nuclei. En nuclei el uso real de `addresses` llega con el 005 (task 4.1 de ese change).

### D5. Redirecciones (A5, task 4.1)
httpx no sigue redirecciones salvo que se le pida, y los flags para pedirlo quedan prohibidos en el perfil. Igual, si la respuesta es un 3xx, el `Location` se trata como **descubrimiento**: entra al grafo y pasa por el mismo filtro de alcance que cualquier otro activo. Nunca se visita directamente.

### D6. Salida validada por schema y datos parciales
Cada adaptador parsea su salida a registros tipados, línea por línea:
- Una línea que no cumple el schema se descarta y se cuenta (`invalid_lines`). Las válidas se usan. Respuesta a la pregunta abierta: **los datos parciales se aceptan** si al menos una línea es válida, y la corrida queda marcada `partial`.
- Si ninguna línea es válida y la salida no estaba vacía, el resultado es `invalid_output`. Pasa por `SchemaGate`: dos salidas inválidas seguidas de la misma herramienta escalan a HITL y esa herramienta no se vuelve a usar en el engagement hasta que un humano lo revise.
- Todo lo que viene de la herramienta es dato no confiable: nombres y URL se normalizan con `normalize_target` antes de entrar al grafo, y lo que no normaliza se descarta.

### D7. Errores de herramienta sin romper el engagement
`timeout`, binario ausente, código de salida distinto de 0 o salida inválida:
- el adaptador devuelve `{"status": "error", "error": <tipo>}`, no lanza;
- el orquestador deja un registro de control en la bitácora (`tool.error`, `ABORTED`, motivo `timeout` / `binary_missing` / `exit_code` / `invalid_output`), porque el OK del write-ahead ya dijo que la acción se iba a ejecutar y hay que dejar constancia de que no terminó bien;
- el loop sigue con los demás activos y las demás herramientas.

Lo único que frena el loop son las barreras del Harness: kill switch, bitácora rota o token vencido o revocado. En esos casos el orquestador se detiene y no reintenta.

### D8. AssetGraph y su versionado
Respuesta a "¿cómo se versiona el grafo entre iteraciones?":
- **Activo:** `id` (SHA-256 de `tipo:dirección` normalizada), `type` (`domain` | `ip` | `http_service`), `address`, `technologies`, `source_tool`, `iteration` (en la que apareció), `in_scope` (bool) y `reason` si está fuera.
- **Persistencia:** SQLite append-only en `state/<engagement_id>.assets.sqlite3`, con triggers contra UPDATE y DELETE como la bitácora. Un activo ya visto no se vuelve a insertar (`id` único): eso es la deduplicación.
- **Versión:** la versión del grafo es el número de iteración. "Activos nuevos" de la iteración *i* son las filas insertadas con `iteration = i`, y ese número es el que recibe `decide_recon`. Una tecnología nueva sobre un activo ya conocido se guarda como fila en `asset_tech`, que también es append-only, y no cuenta como activo nuevo.

### D9. Descubrimientos fuera de alcance (task 2.6)
Antes de encolar un activo, el orquestador le pregunta al Guard (determinista) si está en alcance con el token de la fase. Si no está:
- se guarda en el grafo con `in_scope = false` y su motivo (`out_of_scope`, `excluded`);
- queda en la bitácora como control (`asset.discovered`, `BLOCKED`, motivo);
- **nunca** se encola.

Es defensa en profundidad: aunque el orquestador tuviera un bug y lo encolara, `Harness.invoke` lo bloquearía igual. El test 3.3 prueba las dos capas por separado.

### D10. Rate limit
- `httpx.probe` recibe `-rl` con `rate_limit_rps_per_target` de `policy.yaml`. nmap ya tiene `--max-rate`.
- Además, el orquestador tiene un limitador por objetivo (token bucket con reloj inyectable) que no deja invocar más de `rate_limit_rps_per_target` acciones por segundo sobre el mismo host. Así el límite no depende solo del flag de cada herramienta, y se puede testear sin red.

### D11. Entrega a correlación
Respuesta a "¿cuándo se promueve un hallazgo de recon a candidato de correlación?": cuando el loop A para, sea por grafo estabilizado o por tope. En ese momento, cada activo en alcance con al menos una tecnología con versión (por ejemplo `Apache httpd 2.4.25`) se entrega al 005 como entrada de `cve.lookup`. Los activos sin versión quedan en el grafo para el análisis activo del 005 (ZAP y nuclei).

## Riesgos y limitaciones
- **Virtual hosts con TLS:** con `Host` fijado, httpx sobre HTTPS manda SNI con la IP. Los dos objetivos del laboratorio son HTTP, así que no pasa. Si aparece un objetivo HTTPS se revisa (httpx tiene `-sni`).
- **Fuentes pasivas de subfinder:** en un engagement real consultan servicios de terceros sobre el dominio del cliente. Es OSINT pasivo y no toca al objetivo, pero el RoE debería decir si está permitido. Queda como campo futuro del RoE (`passive_osint: true/false`). En el laboratorio no hay salida, así que no aplica.
- **Flags verificados contra la versión instalada:** los perfiles se escriben contra httpx y subfinder reales (`-h`). Si cambia la versión, el test de argv lo detecta solo si cambia el armado, no si la herramienta cambia el significado de un flag.
