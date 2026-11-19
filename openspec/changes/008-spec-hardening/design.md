# Design — Change 008

## Decisiones
1. **Aprobaciones como tupla `(engagement, fase, acción, objetivo canónico)`.** `Guard.approve` exige `engagement_id` y `phase` por nombre; `Guard.approved` las compara contra el token. Así una aprobación no se reutiliza en otro engagement ni en otra fase.
2. **`normalize_target` única y compartida.** El Guard decide sobre el objetivo canónico y el adaptador recibe ese mismo valor. Si decidieran sobre valores distintos, se abriría un hueco entre "lo que se autorizó" y "lo que se ejecutó". Solo se aceptan host ASCII (≤ 253, etiquetas ≤ 63, sin guion inicial) o IP; IPv4 mapeada a IPv6 → IPv4; todo lo demás → `out_of_scope`.
3. **Kill switch por engagement, sin `disengage`.** `disengage()` lanza `PermissionError` y el atributo no se asigna. Seguir exige un engagement nuevo.
4. **`Guard.check` devuelve el motivo.** `is_allowed` queda como envoltorio, para no romper llamadores. `AuditLog.record` exige un motivo de `BLOCK_REASONS` en todo BLOCKED.
5. **En BLOCKED/ABORTED se registra el objetivo tal como se intentó**, y en OK/PENDING_HITL el canónico. El crudo es evidencia de lo que se intentó; el canónico, de lo que se ejecutó.
6. **Subred del lab fija en 10.99.0.0/24.** Un test compara `lab/docker-compose.yml` contra `harness/profiles.yaml`.

## Limitaciones conocidas (revisión del `security-reviewer`)
| # | Limitación | Dónde se resuelve |
|---|---|---|
| L1 | `engagement_id` y fase vienen del token, que hoy se puede fabricar: un token con otro id evade el kill switch y las aprobaciones | 003 (token con integridad); test `xfail(strict)` ya escrito |
| L2 | El kill switch es estado en memoria: código malicioso en el mismo proceso puede tocar `_engaged`, y un reinicio lo pierde | 002 (persistir el evento ABORTED en la bitácora y leerlo al abrir) |
| L3 | Si `adapter.run` lanza una excepción, no queda registro (previo al change) | Proponer un resultado `ERROR` en un delta de `audit-log` |
| L4 | `record` con motivo inválido lanza sin registrar (falla cerrado, sin rastro) | Aceptado: solo pasa con un error de programación, y lo atrapan los tests |
