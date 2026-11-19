# Tasks — Change 004

## Spec y diseño
- [x] 1.1 `design.md`: schemas de salida, versionado del grafo, manejo de errores
- [x] 1.2 Deltas de `asset-discovery`, `tool-adapters` y `authorization`
- [ ] 1.3 Revisión cruzada (PR de spec)

## Implementación
- [ ] 2.1 Grabar fixtures de salida de subfinder y httpx (sintéticas, con el formato de httpx v1.12.0 y subfinder v2)
- [ ] 2.2 `harness/adapters/subfinder_adapter.py` con tests de argv y de salida
- [ ] 2.3 `harness/adapters/httpx_adapter.py` con tests de argv y de salida
- [ ] 2.4 Modelo `AssetGraph` y persistencia (SQLite append-only, versión = iteración)
- [ ] 2.5 Orquestación del loop A usando `decide_recon` (`harness/recon.py`)
- [ ] 2.6 Descubrimientos fuera de alcance: registrar y no sondear
- [ ] 2.7 `ToolAdapter.run(..., addresses)`: el Harness pasa las IP validadas (actualizar Fake, nmap y nuclei)
- [ ] 2.8 Errores de herramienta tipados (`timeout`, `binary_missing`, `exit_code`, `invalid_output`) y `tool.error` en bitácora
- [ ] 2.9 `safe_env()` sin variables de proxy
- [ ] 2.10 Perfiles de subfinder y httpx en `profiles.yaml`; runner del lab con los binarios

## Verificación
- [ ] 3.1 Test: loop A termina por grafo estabilizado
- [ ] 3.2 Test: loop A termina por tope
- [ ] 3.3 Test: un activo fuera de alcance nunca llega a un adaptador (filtro del orquestador y, por separado, el Harness)
- [ ] 3.4 Test: el adaptador y el orquestador respetan el rate limit
- [ ] 3.5 Corrida real contra el lab y bitácora verificada con `audit verify`
- [ ] 3.6 Archivar deltas en `openspec/specs/`

## Agregado por el red team (009)
- [ ] 4.1 A5: los adaptadores HTTP NO DEBEN seguir redirecciones fuera de alcance (test con fixture de 302 a otro host)
- [ ] 4.2 DNS rebinding: pasar al adaptador la IP ya validada por el Harness en lugar de dejar que la herramienta resuelva (cubierto por 2.7)
