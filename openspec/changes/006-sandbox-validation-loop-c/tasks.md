# Tasks — Change 006

## Spec y diseño
- [x] 1.1 `design.md`: ciclo de vida del sandbox, límites, evidencia, timeout del Reviewer
- [x] 1.2 Deltas de `validation`, `poc-catalog`, `authorization` y `audit-log`
- [ ] 1.3 Revisión cruzada (PR de spec)

## Implementación
- [x] 2.1 Tests que fallan para el `Sender` aislado (sin red externa, sin estado)
- [x] 2.2 Sandbox efímero: contenedor en red interna que implementa `Sender` (D3), imagen `lab/sandbox/`
- [x] 2.3 Límites de tiempo, tamaño y cantidad de solicitudes (D4)
- [x] 2.4 Orquestación del loop C con `decide_validation` (D1, D9)
- [x] 2.5 CLI de aprobación: listar hallazgos pendientes, aprobar o rechazar con motivo (D6)
- [x] 2.6 Registrar aprobación, verificación elegida y resultado en bitácora
- [x] 2.7 Aprobación HITL con `subject` en `Guard` y `Harness.invoke` (D2)
- [x] 2.8 `ApprovalStore` append-only, vencimiento y timeout del Reviewer (D5)
- [x] 2.9 Evidencia redactada con hash en bitácora (D7)
- [x] 2.10 `proposed_by` y evaluador conocido en el catálogo (D10)

## Verificación
- [x] 3.1 Test: sin aprobación no se invoca el `Sender`
- [x] 3.2 Test: verificación inexistente en catálogo → "no validado"
- [x] 3.3 Test: el sandbox no alcanza hosts fuera del lab
- [x] 3.4 Test: el sandbox se destruye aunque falle la verificación
- [x] 3.5 Evals de validación ampliadas con casos donde la respuesta correcta es no actuar
- [x] 3.6 `security-reviewer` sobre la implementación
- [x] 3.7 Archivar deltas en `openspec/specs/`
