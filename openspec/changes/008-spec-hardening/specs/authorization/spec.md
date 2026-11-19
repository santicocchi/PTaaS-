# Delta — authorization (change 008)

Tests: tests/test_authorization.py

## Requirement: Aprobación humana atada a engagement y fase
Una aprobación humana DEBE identificar engagement, fase, acción y objetivo. Una aprobación NO DEBE habilitar la acción en otro engagement ni en otra fase.

### Scenario: aprobación reutilizada en otro engagement
- GIVEN una aprobación de `poc_catalog.run_parametrized` sobre `dvwa.lab.test` en el engagement `eng-1`
- WHEN un agente del engagement `eng-2` invoca la misma acción sobre el mismo objetivo
- THEN el resultado es PENDING_HITL, la herramienta no se ejecuta y queda en bitácora

### Scenario: aprobación válida
- GIVEN una aprobación para `eng-1`, fase VALIDATE, acción y objetivo
- WHEN un agente de `eng-1` invoca esa acción en fase VALIDATE
- THEN la acción se ejecuta y se registra OK

## Requirement: Normalización del objetivo
El Guard DEBE normalizar el objetivo antes de decidir: minúsculas, sin espacios ni punto final; una IPv4 mapeada a IPv6 DEBE evaluarse como IPv4. Un objetivo que no se puede interpretar DEBE bloquearse.

### Scenario: hostname con mayúsculas y punto final
- GIVEN un token que autoriza `lab.example.test`
- WHEN se invoca una acción sobre `HOST.Lab.Example.Test.`
- THEN la decisión es la misma que para `host.lab.example.test` (OK)

### Scenario: IPv4 fuera de alcance escrita como IPv6 mapeada
- GIVEN un token que autoriza 10.0.0.0/24
- WHEN se invoca una acción sobre `::ffff:10.0.1.5`
- THEN la acción es bloqueada y registrada

### Scenario: objetivo con puerto, esquema o ruta
- GIVEN un token que autoriza `lab.example.test`
- WHEN se invoca una acción sobre `http://lab.example.test:80/x`
- THEN la acción es bloqueada: el objetivo debe ser un host o una IP

## Requirement: Token emitido por el harness
El harness DEBE aceptar solo tokens emitidos por su emisor (integridad verificable). Un token construido o modificado fuera del emisor NO DEBE habilitar acciones. (Implementación: change 003.)

### Scenario: token fabricado
- GIVEN un ScopeToken creado a mano con alcance 0.0.0.0/0
- WHEN un agente invoca una acción con ese token
- THEN la acción es bloqueada y registrada como token inválido

### Scenario: token alterado
- GIVEN un token emitido para la fase RECON
- WHEN se cambia su fase a VALIDATE y se usa
- THEN la acción es bloqueada y registrada como token inválido
