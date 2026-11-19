# Delta — audit-log (change 002)

Tests: tests/test_audit_persistence.py

## Requirement: Persistencia por engagement
La bitácora DEBE persistir en un almacenamiento propio de cada engagement y recuperarse completa tras reiniciar el proceso.

### Scenario: recuperación tras reinicio
- GIVEN un engagement con 3 registros escritos
- WHEN se cierra el proceso y se vuelve a abrir la bitácora
- THEN se leen los 3 registros, en orden, con la cadena íntegra

### Scenario: dos engagements no comparten registros
- GIVEN los engagements `eng-1` y `eng-2` con registros propios
- WHEN se lee la bitácora de `eng-2`
- THEN no contiene ningún registro de `eng-1`

### Scenario: identificador de engagement usado como ruta
- GIVEN un `engagement_id` igual a `../otro`
- WHEN se intenta abrir su bitácora
- THEN se rechaza sin crear ni leer ningún archivo

## Requirement: Append-only sin API de modificación
El almacenamiento NO DEBE permitir actualizar ni borrar registros, y la capa de acceso NO DEBE exponer operaciones para hacerlo.

### Scenario: UPDATE directo sobre la tabla
- GIVEN una bitácora con registros
- WHEN se ejecuta un UPDATE o un DELETE por SQL
- THEN la base lo rechaza y los registros quedan iguales

## Requirement: Verificación al abrir y bajo demanda
El sistema DEBE verificar la cadena al abrir la bitácora y DEBE ofrecer `python -m harness.audit verify <archivo>`, que sale con código distinto de 0 si la cadena está rota.

### Scenario: fila alterada en el archivo
- GIVEN una bitácora íntegra
- WHEN se cambia el `target` de un registro intermedio editando el archivo (sin triggers)
- THEN `verify` sale con código 1 e indica el `seq` del registro roto, y abrir la bitácora falla

### Scenario: fila intermedia borrada en el archivo
- GIVEN una bitácora íntegra de 4 registros
- WHEN se borra el registro 2 editando el archivo
- THEN `verify` sale con código 1

### Scenario: inicio de cadena trasplantado
- GIVEN los registros de `eng-1` copiados dentro del archivo de `eng-2`
- WHEN se verifica la bitácora de `eng-2`
- THEN la verificación falla (el GENESIS es por engagement)

## Requirement: Cadena rota detiene el engagement
Con la cadena rota, el engagement NO DEBE ejecutar más acciones.

### Scenario: manipulación durante el engagement
- GIVEN un harness con bitácora persistente y un registro alterado después de abrirla
- WHEN un agente invoca una acción en alcance
- THEN la herramienta no se ejecuta y se lanza `AuditIntegrityError`

## Requirement: Escrituras concurrentes
Escrituras simultáneas DEBEN producir una cadena válida sin registros perdidos.

### Scenario: 4 hilos escribiendo 50 registros cada uno
- GIVEN una bitácora vacía
- WHEN 4 hilos escriben 50 registros cada uno al mismo tiempo
- THEN hay 200 registros y la cadena verifica

## Requirement: Kill switch persistente
Un kill switch activado DEBE seguir activado después de reiniciar.

### Scenario: reinicio después de abortar
- GIVEN un engagement con el kill switch activado
- WHEN se reinicia el proceso y se reabre la bitácora
- THEN cualquier acción se registra ABORTED y no se ejecuta

## Requirement: Evidencia por referencia
El campo de evidencia DEBE ser una referencia con hash (`<ruta>#sha256=<hex>`) y NO DEBE contener el contenido.

### Scenario: evidencia con contenido
- GIVEN un intento de registrar evidencia que no tiene la forma `<ruta>#sha256=<hex>`
- WHEN se llama a `record`
- THEN se rechaza
