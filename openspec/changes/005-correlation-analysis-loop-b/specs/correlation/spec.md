# Delta — correlation (change 005)

Tests: tests/correlation/test_feeds.py, tests/correlation/test_correlate.py

## MODIFIED Requirement: Correlación sobre datos, sin tocar activos
La correlación DEBE operar solo sobre el `AssetGraph` y snapshots locales (NVD, EPSS, CWE, ATT&CK); NO DEBE iniciar conexiones hacia los activos ni hacia internet. Cada consulta (`cve.lookup`, `epss.lookup`, `cwe.map`) DEBE pasar por `Harness.invoke` con un token de fase CORRELATE, con el host del activo como objetivo. Las tecnologías consultadas DEBEN leerse del grafo, no del llamador.

### Scenario: intento de sondeo en fase CORRELATE
- GIVEN un token de fase CORRELATE
- WHEN el agente intenta una acción que contacta un activo
- THEN el harness la bloquea y la registra

### Scenario: consulta sin red
- GIVEN un entorno sin red y un snapshot local válido
- WHEN se invoca `cve.lookup` sobre `dvwa.lab.test`
- THEN el resultado sale del snapshot y no se abre ninguna conexión

### Scenario: tecnología que no está en el grafo
- GIVEN un activo cuyo grafo solo tiene `Apache httpd:2.4.25`
- WHEN se invoca `cve.lookup` sobre ese host
- THEN se buscan solo CVE de esa tecnología, sin importar lo que el llamador pida

## ADDED Requirement: Snapshots íntegros y fechados
Cada snapshot DEBE tener un manifiesto con fuente, fecha de descarga, cantidad de registros y SHA-256. Un snapshot cuyo hash no coincide, o sin manifiesto, DEBE tratarse como no disponible: no se generan candidatos por CVE y queda un registro de control `feed.unavailable`. Un snapshot más viejo que `limits.max_feed_age_days` DEBE usarse marcando cada candidato `feed_stale` y bajando su confianza.

### Scenario: snapshot alterado
- GIVEN un `nvd.json` modificado después de generar el manifiesto
- WHEN se carga el feed
- THEN el feed queda no disponible, no hay candidatos por CVE y la bitácora tiene `feed.unavailable`

### Scenario: snapshot desactualizado
- GIVEN un snapshot descargado hace 45 días y `max_feed_age_days: 30`
- WHEN se correlaciona un activo con un CVE conocido
- THEN el candidato sale con `feed_stale = true` y un nivel menos de confianza

## ADDED Requirement: Producto reconocido por tabla, sin coincidencias aproximadas
Una tecnología DEBE mapearse a CPE solo mediante la tabla curada de alias. Una tecnología que no está en la tabla, o cuya versión no se puede interpretar, NO DEBE producir candidatos por CVE. La versión DEBE compararse con los rangos de `configurations` del registro.

### Scenario: dos nombres del mismo producto
- GIVEN `Apache httpd:2.4.25` (nmap) y `Apache HTTP Server:2.4.25` (httpx)
- WHEN se mapean a CPE
- THEN los dos dan `apache:http_server` versión 2.4.25

### Scenario: producto desconocido
- GIVEN la tecnología `AppDesconocida:0.1`
- WHEN se correlaciona
- THEN no hay candidatos por CVE

### Scenario: versión fuera del rango
- GIVEN un CVE con `versionEndExcluding: 2.4.20` y la versión 2.4.25
- WHEN se correlaciona
- THEN ese CVE no genera candidato

## ADDED Requirement: Confianza del candidato
La confianza DEBE derivarse con reglas fijas:
- `medium` para un CVE por versión que reportan dos herramientas independientes, con feed al día y CWE conocido;
- `low` si la versión viene de una sola herramienta, de un banner de distribución, con `cwe: unknown` o con feed desactualizado.

Un candidato con evidencia solo de versión NO DEBE tener confianza `high`.

### Scenario: banner de distribución
- GIVEN `Apache/2.4.25 (Debian)` reportado por httpx y nmap
- WHEN se correlaciona con un CVE de esa versión
- THEN el candidato tiene confianza `low` y la evidencia dice que puede haber un backport

### Scenario: dos herramientas coinciden
- GIVEN la misma versión sin marca de distribución reportada por httpx y nmap, feed al día y CWE conocido
- WHEN se correlaciona
- THEN el candidato tiene confianza `medium`

## ADDED Requirement: Correlación solo con el engagement en CORRELATE
El correlador DEBE recibir el engagement y NO DEBE invocar ninguna capability si su estado no es `CORRELATE`.

### Scenario: engagement todavía en RECON
- GIVEN un token CORRELATE vigente y un engagement en `RECON`
- WHEN se arranca la correlación
- THEN no se consulta ningún feed y no se generan candidatos

## MODIFIED Requirement: Sin datos inventados
El sistema NO DEBE completar CVE, EPSS, CWE, CVSS ni técnicas ATT&CK inexistentes; los datos ausentes DEBEN marcarse como `unknown`/`null`. Un puntaje CVSS DEBE guardarse con su versión y NO DEBE convertirse de una versión a otra.

### Scenario: tecnología sin CVE conocido
- GIVEN una tecnología sin entradas en el feed
- WHEN se enriquece el activo
- THEN `cve` es `null` y no se genera candidato por CVE

### Scenario: CVE sin EPSS
- GIVEN un CVE presente en NVD y ausente del snapshot de EPSS
- WHEN se enriquece
- THEN `epss` es `null`, no 0

### Scenario: solo CVSS 3.1
- GIVEN un CVE con métrica CVSS 3.1 y sin CVSS 4.0
- WHEN se enriquece
- THEN se guarda el puntaje con `cvss_version = "3.1"` y no hay puntaje 4.0

## MODIFIED Requirement: Normalización de taxonomías
Cada candidato DEBERÍA mapearse a CWE y, cuando la tabla curada `data/attack_map.yaml` tenga el CWE, a una técnica MITRE ATT&CK. `NVD-CWE-noinfo` y `NVD-CWE-Other` DEBEN tratarse como `unknown`.

### Scenario: candidato sin CWE mapeable
- GIVEN un candidato sin CWE derivable
- WHEN se normaliza
- THEN se marca `cwe: unknown` y pasa a análisis con baja confianza

### Scenario: CWE sin técnica en la tabla
- GIVEN un candidato con un CWE que no está en `attack_map.yaml`
- WHEN se normaliza
- THEN `attack_technique` es `null`
