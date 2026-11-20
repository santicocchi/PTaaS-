"""Change 006 · audit-log: motivos de la validación (conjuntos cerrados)."""
import pytest

from harness.contracts import BLOCK_REASONS, AuditLog, Phase, Result
from tests.conftest import act, make_token


def test_motivo_de_sandbox():
    audit = AuditLog()
    entry = audit.record_control("eng-1", "validation-orchestrator", "validation.attempt",
                                 "F-1", Result.ABORTED, "sandbox_error")
    assert entry["result"] == "ABORTED" and entry["reason"] == "sandbox_error"
    audit.verify_integrity()


def test_motivo_inventado_se_rechaza():
    with pytest.raises(ValueError):
        AuditLog().record_control("eng-1", "x", "validation.attempt", "F-1", Result.ABORTED,
                                  "sandbox_broke")


def test_missing_subject_es_motivo_de_bloqueo():
    assert "missing_subject" in BLOCK_REASONS
    t = make_token(phase=Phase.VALIDATE)
    entry = AuditLog().record("v", act("poc_catalog.run_parametrized", Phase.VALIDATE),
                              "10.0.0.5", t, Result.BLOCKED, "missing_subject")
    assert entry["reason"] == "missing_subject"


@pytest.mark.parametrize("reason", ["no_catalog_entry", "reviewer_rejected", "reviewer_timeout",
                                    "request_budget_exhausted"])
def test_cierre_de_validacion_con_motivo(reason):
    audit = AuditLog()
    entry = audit.record_control("eng-1", "v", "validation.closed", "F-1", Result.ABORTED,
                                 reason)
    assert entry["reason"] == reason
    audit.verify_integrity()


@pytest.mark.parametrize("reason", ["timeout", "otro", None])
def test_cierre_con_motivo_fuera_de_la_lista_se_rechaza(reason):
    with pytest.raises(ValueError):
        AuditLog().record_control("eng-1", "v", "validation.closed", "F-1", Result.ABORTED,
                                  reason)


def test_motivo_de_cierre_no_vale_en_otra_accion():
    with pytest.raises(ValueError):
        AuditLog().record_control("eng-1", "v", "tool.error", "F-1", Result.ABORTED,
                                  "reviewer_rejected")


@pytest.mark.parametrize("action", ["hitl.approve", "hitl.reject", "sandbox.cleanup_failed"])
def test_controles_de_validacion_quedan_en_la_cadena(action):
    audit = AuditLog()
    result, reason = ((Result.ABORTED, "sandbox_error") if action == "sandbox.cleanup_failed"
                      else (Result.OK, None))
    audit.record_control("eng-1", "v", action, "dvwa.lab.test", result, reason)
    audit.verify_integrity()
    assert audit.entries[-1]["action"] == action


def test_control_con_evidencia():
    audit = AuditLog()
    ref = "evidence/eng-1/F-1-1.json#sha256=" + "a" * 64
    entry = audit.record_control("eng-1", "v", "validation.attempt", "F-1", Result.OK,
                                 evidence=ref)
    assert entry["evidence"] == ref
    with pytest.raises(ValueError):
        audit.record_control("eng-1", "v", "validation.attempt", "F-1", Result.OK,
                             evidence="/abs/x.json#sha256=" + "a" * 64)
