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
