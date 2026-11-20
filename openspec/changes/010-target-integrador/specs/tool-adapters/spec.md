# Delta — tool-adapters (change 010)

Tests: tests/tool_adapters/test_zap.py::test_spider_lee_robots_txt_antes_de_escanear

## ADDED Requirement: El spider de ZAP lee `robots.txt`
Antes de lanzar el spider, el adaptador `zap.baseline_scan` DEBE fijar `setOptionParseRobotsTxt` en `true`, sin depender del valor por defecto de ZAP. El spider sigue limitado al contexto (`subtreeOnly`) y sin enviar formularios.

### Scenario: opción fijada antes del spider
- GIVEN un `zap.baseline_scan` sobre un host del alcance
- WHEN corre
- THEN `setOptionParseRobotsTxt` se llama con `true` antes de `spider/action/scan`, y `setOptionProcessForm` / `setOptionPostForm` siguen en `false`
