# Design — Change 002: bitácora persistente

## Contexto
Hoy `AuditLog` es una lista en memoria: se pierde al reiniciar y cualquier código del proceso la puede modificar. El change 008 dejó dos limitaciones que dependen de este change: el kill switch se pierde al reiniciar (L2) y la cadena no se verifica antes de actuar.

## Decisiones

### D1. Un archivo SQLite por engagement
`audits/<engagement_id>.sqlite3`. Aísla engagements por construcción (no hay consultas cruzadas que olvidar filtrar) y permite entregar, archivar o borrar la bitácora de un cliente sin tocar a otros. El `engagement_id` se valida (`^[a-z0-9][a-z0-9-]{0,62}$`) para que no sirva como ruta (`../`).

### D2. Esquema
```sql
CREATE TABLE audit (
  seq        INTEGER PRIMARY KEY,         -- 1, 2, 3… sin huecos
  ts         REAL    NOT NULL,
  engagement TEXT    NOT NULL,
  agent      TEXT    NOT NULL,
  action     TEXT    NOT NULL,
  target     TEXT    NOT NULL,
  phase      TEXT    NOT NULL,
  result     TEXT    NOT NULL CHECK (result IN ('OK','BLOCKED','PENDING_HITL','ABORTED')),
  reason     TEXT,
  evidence   TEXT,                         -- referencia, nunca contenido (ver D6)
  prev       TEXT    NOT NULL,
  hash       TEXT    NOT NULL UNIQUE
);
```
`hash = SHA-256(JSON canónico de todos los campos salvo hash y seq)`. `seq` no entra en el hash, así que si alguien borra una fila y renumera, el que lo detecta es `prev` (hay un test que lo prueba). Es el mismo cálculo que hoy, así que los registros en memoria y en disco se verifican con una única función.

### D3. Append-only: triggers **y** capa de acceso (respuesta a "¿triggers o convención?")
- Triggers `BEFORE UPDATE` y `BEFORE DELETE` que hacen `RAISE(ABORT, 'append-only')`.
- La clase `SqliteAuditLog` no expone ningún método de actualización ni borrado.

Los triggers no protegen contra alguien con acceso al archivo, que puede borrarlos o editar el archivo directamente. Para eso está la cadena de hashes: **los triggers previenen errores; la cadena detecta manipulaciones.** Son dos defensas distintas y se usan las dos.

### D4. GENESIS por engagement (respuesta a "¿cómo se maneja el primer registro?")
El `prev` del primer registro es `GENESIS:<engagement_id>`, no el literal `GENESIS`. Así no se puede trasplantar el inicio de la cadena de un engagement a otro: la verificación lo detecta.

### D5. Verificación al abrir, antes de actuar y por CLI
- `SqliteAuditLog.open()` verifica toda la cadena. Si falla, lanza `AuditIntegrityError`.
- `Harness.invoke` verifica la cadena **completa** antes de cada acción. *Cambio respecto del borrador:* la idea era verificar solo la cola (último `seq`/hash), pero eso no detecta una fila intermedia alterada, que es justo lo que pide el Scenario "manipulación durante el engagement". Para los volúmenes del MVP (cientos de registros), el costo es despreciable. Si hiciera falta optimizar, la opción sería guardar un hash acumulado por bloque.
- `python -m harness.audit verify <archivo>`: sale con código 0 si la cadena está íntegra y 1 si no, indicando el `seq` del primer registro roto.
- Con la cadena rota, el engagement no continúa: se registra ABORTED (en memoria) y se lanza `AuditIntegrityError`.

### D6. Evidencia: referencia + hash (respuesta a "¿referencia o contenido cifrado?")
La bitácora guarda `evidence = "<ruta relativa>#sha256=<hash>"`. El contenido vive aparte (`evidence/<engagement>/…`). Así se cumple "sin datos sensibles en claro", la bitácora queda chica y el hash prueba que la evidencia no cambió. El cifrado del almacén de evidencia queda fuera de este change.

### D7. Concurrencia
- SQLite en modo WAL con `BEGIN IMMEDIATE`: leer el último hash y escribir el nuevo registro ocurre en una sola transacción con lock de escritura. Dos escritores nunca toman el mismo `prev`.
- `seq` lo asigna la base. Entre hilos del mismo proceso, una conexión por hilo.

### D8. Kill switch persistente (cierra L2 del 008)
Al abrir la bitácora, si existe un registro `ABORTED` con `action = "killswitch.engage"`, el engagement arranca con el kill switch activado. Activar el kill switch escribe ese registro primero. Un reinicio ya no lo "desactiva".

### D9. Contrato público del Harness sin cambios
`SqliteAuditLog` implementa el mismo `record(...)` que `AuditLog`. `Harness` recibe cualquiera de las dos, y la de memoria queda para los tests rápidos.

## Alternativas descartadas
- **Archivo JSONL firmado:** más simple, pero sin transacciones. La concurrencia y el append atómico se complican.
- **Postgres ya:** es el destino a futuro, pero hoy suma infraestructura sin aportar al criterio de aceptación.
- **Firmar cada registro con una clave:** es el desafío de extensión C3. Se deja para después: la cadena ya detecta alteraciones y borrados, y la firma solo agregaría *autoría*.

## Riesgos
- Alguien que reescribe **toda** la cadena desde el principio con hashes válidos no es detectado por la cadena sola. Mitigación propuesta: publicar el hash del último registro en cada informe y cada checkpoint (anclaje externo). Se anota como trabajo futuro.

## Revisión del `security-reviewer` (implementación)
Corregido, cada uno con su test:
- **Write-ahead:** el OK se registra *antes* de `adapter.run`. Si no se puede registrar (token de otro engagement, base bloqueada, disco lleno), la herramienta no corre.
- **La cadena rota deja rastro:** se activa el kill switch y se intenta escribir un `killswitch.engage`/ABORTED.
- **Ancla en memoria `(cantidad, último hash)`:** detecta un truncado del final o un archivo reemplazado mientras el proceso corre.
- **Kill switch:** solo cuenta si `phase = 'control'` y el resultado es `ABORTED`. Una acción de un agente que se llame igual no aborta el engagement.
- **Triggers:** al abrir se comprueba que sean los nuestros, porque `IF NOT EXISTS` no reemplaza un trigger plantado de antemano.

Limitaciones aceptadas:
- **Truncado del final entre reinicios:** sin un ancla externa no se detecta. Si alguien borra la fila del kill switch *con el proceso apagado*, al reabrir no se nota. Mitigación futura: publicar el último hash en cada checkpoint o informe, o firmar con una clave fuera del host (desafío C3).
- **Bitácora en memoria:** no aísla engagements. Solo se usa en tests.
- **Ventana entre verificar y escribir:** queda abierta dentro de un mismo `invoke`. El ancla la acota a cambios hechos por fuera del proceso.
- **`close()`:** solo cierra la conexión del hilo que lo llama.
