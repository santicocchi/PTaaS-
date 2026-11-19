"""Change 004 · audit-log: los errores de herramienta quedan con su motivo (conjunto cerrado)."""
import pytest

from harness.contracts import AuditLog, Result


@pytest.mark.parametrize("kind", ["timeout", "binary_missing", "exit_code", "invalid_output"])
def test_error_de_herramienta_con_motivo(kind):
    audit = AuditLog()
    entry = audit.record_control("eng-1", "recon-orchestrator", "tool.error", "dvwa.lab.test",
                                 Result.ABORTED, kind)
    assert entry["reason"] == kind
    audit.verify_integrity()


@pytest.mark.parametrize("result", [Result.ABORTED, Result.PENDING_HITL, Result.OK])
def test_motivo_fuera_del_conjunto_se_rechaza(result):
    with pytest.raises(ValueError):
        AuditLog().record_control("eng-1", "x", "tool.error", "t", result, "lo que sea")


def test_registro_sin_motivo_no_cambia():
    entry = AuditLog().record_control("eng-1", "x", "token.issue", "recon", Result.OK)
    assert "reason" not in entry
