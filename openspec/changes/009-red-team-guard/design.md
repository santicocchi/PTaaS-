# Design — Change 009

1. **Gate humano por política (R13).** `Guard.needs_approval = action.requires_human_approval OR token.phase ∈ hitl_phases`. Las `hitl_phases` salen de `gates_hitl` en `policy.yaml` (hoy: `validate`). El flag de la Action solo puede *sumar* exigencias, nunca quitarlas.
2. **Destructivo según el adaptador (R14).** Después de elegir el adaptador, si `adapter.destructive` es verdadero (o no está declarado), la acción se bloquea con `destructive`. Ante la duda, falla cerrado.
3. **Resolución y revalidación (A4).** Para un objetivo que es un nombre, el Harness lo resuelve (A y AAAA, `resolver` inyectable) y exige que **todas** las IP estén en `allowed_cidrs` y no estén excluidas. Si no resuelve, se bloquea con `dns_unresolved`. El Guard sigue siendo determinista: recibe las IP como dato y no hace la consulta DNS él mismo.
4. **Orden en `invoke`:** bitácora íntegra → kill switch → token (MAC, revocación, vigencia) → Guard → adaptador (existe, fase, destructivo) → DNS → gate humano → kill switch (de nuevo) → write-ahead → ejecución. Primero se descarta lo imposible y recién después se pide aprobación a una persona.

## Limitaciones
- **DNS rebinding:** la herramienta vuelve a resolver el nombre cuando se ejecuta, y en ese momento el DNS podría devolver otra IP. **Ojo: ya afecta a `nmap.service_scan`, que existe hoy.** Mitigación para el 004: pasar la IP ya validada al adaptador (por ejemplo, `--resolve` en httpx o curl) y no dejar que la herramienta resuelva.
- **Un RoE solo con dominios no alcanza:** el RoE tiene que incluir los CIDR a los que resuelven esos dominios. Es deliberado: el alcance real son las IP.

## Revisión del `security-reviewer`
Corregido, cada uno con su test:
- **Resolver que lanza una excepción:** queda registrado como `dns_unresolved`.
- **`gates_hitl` con una fase mal escrita:** falla al cargar la política, en lugar de apagar el gate en silencio.
- **`destructive`:** se exige que sea exactamente `False`. `None`, `0` o un atributo ausente se bloquean.
- **Kill switch:** se vuelve a chequear justo antes del write-ahead, porque pudo activarse mientras se resolvía el nombre. Además, la consulta DNS ahora sale después de los chequeos del adaptador.
- **`system_resolver`:** consulta con punto final, así que no aplica los dominios de búsqueda del sistema.
- **Tests:** todos inyectan un DNS falso. Ningún test consulta el DNS real.
