# Tasks — Change 005

## Spec y diseño
- [x] 1.1 `design.md`: snapshots, confianza, contradicciones, política de templates, falsos positivos, loop B
- [x] 1.2 Deltas de `correlation`, `vuln-analysis`, `tool-adapters` y `authorization`
- [ ] 1.3 Revisión cruzada (PR de spec)

## Implementación — correlación
- [ ] 2.1 Cliente de snapshot NVD (lectura offline, manifiesto con SHA-256, antigüedad) con tests
- [ ] 2.2 Cliente de snapshot EPSS con tests
- [ ] 2.3 `cwe.map` y `data/attack_map.yaml` (ATT&CK solo cuando la tabla lo tiene)
- [ ] 2.4 Tabla de alias `data/feeds/cpe_aliases.yaml` y comparación de rangos de versión
- [ ] 2.5 Correlador que produce `CandidateFinding` con evidencia y confianza por reglas (D4)
- [ ] 2.6 `tools/build_feeds.py` (lo corre una persona con internet) y snapshot sintético para la demo, marcado como tal
- [ ] 2.7 `criticality` opcional en el RoE

## Implementación — análisis
- [ ] 3.1 Servicio `zap` en el laboratorio y adaptador `zap.baseline_scan` por API (fixtures + corrida contra el lab)
- [ ] 3.2 Escribir y revisar ≥ 5 templates propios en `templates/allowlist/` y completar `MANIFEST.md` con hash
- [ ] 3.3 `nuclei.safe_templates` con host, IP fijada y templates verificados por hash; corrida contra el lab
- [ ] 3.4 Equivalencias ZAP/nuclei y lista de falsos positivos revisada
- [ ] 3.5 Orquestación del loop B por candidato con `decide_detection` y estado persistido

## Verificación
- [ ] 4.1 Test: candidato sin evidencia se rechaza
- [ ] 4.2 Test: dato ausente → `null`/`unknown` (EPSS, CWE, CVSS 4.0)
- [ ] 4.3 Test: un template fuera de la allow-list o modificado no se ejecuta
- [ ] 4.4 Test: dos iteraciones sin evidencia nueva → `inconclusive`
- [ ] 4.5 Evals de correlación y análisis ampliadas (≥ 12 casos en conjunto)
- [ ] 4.6 Demo de recon → correlación → análisis sobre el lab con bitácora verificada
- [ ] 4.7 `security-reviewer` sobre la implementación
- [ ] 4.8 Archivar deltas en `openspec/specs/`

## Agregado por el red team (009)
- [ ] 5.1 `nuclei.safe_templates` y `zap.baseline_scan` reciben un host canónico (no URL): el adaptador arma la URL desde el host autorizado, las IP validadas y el puerto del grafo (D7)
