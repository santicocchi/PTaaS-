"""Change 007 · audit-log: registros del informe."""
import pytest

from harness.audit import SqliteAuditLog, verify_file
from harness.contracts import AuditLog, Result

ENG = "eng-1"
REF = "reports/eng-1/report-v1.json#sha256=" + "ab" * 32


@pytest.fixture
def audit():
    return AuditLog()


def test_informe_generado(tmp_path):
    log = SqliteAuditLog.open(ENG, tmp_path)
    log.record_control(ENG, "report-builder", "report.generated", ENG, Result.OK,
                       evidence=REF, subject="report-v1")
    (e,) = log.entries
    assert (e["evidence"], e["subject"]) == (REF, "report-v1")
    log.close()
    assert verify_file(tmp_path / f"{ENG}.sqlite3") is None


@pytest.mark.parametrize("reason", ["missing_cwe", "invalid_cvss_vector", "missing_remediation",
                                    "evidence_mismatch", "validation_mismatch", "sensitive_data",
                                    "not_lab_target", "engagement_not_in_report",
                                    "engagement_delivered"])
def test_motivos_de_fallo(audit, reason):
    audit.record_control(ENG, "report-builder", "report.generation_failed", ENG,
                         Result.ABORTED, reason, subject="f-1")
    assert audit.entries[-1]["reason"] == reason


@pytest.mark.parametrize("kwargs", [
    {"result": Result.ABORTED, "reason": "campo_raro", "subject": "f-1"},
    {"result": Result.OK, "reason": "missing_cwe", "subject": "f-1"},
    {"result": Result.ABORTED, "reason": None, "subject": "f-1"},
    {"result": Result.ABORTED, "reason": "missing_cwe", "subject": None},
])
def test_fallo_invalido(audit, kwargs):
    with pytest.raises(ValueError):
        audit.record_control(ENG, "report-builder", "report.generation_failed", ENG,
                             kwargs["result"], kwargs["reason"], subject=kwargs["subject"])
    assert audit.entries == []


@pytest.mark.parametrize("action", ["report.generated", "report.delivered"])
def test_generado_o_entregado_sin_evidencia(audit, action):
    with pytest.raises(ValueError):
        audit.record_control(ENG, "report-builder", action, ENG, Result.OK, subject="report-v1")
    with pytest.raises(ValueError):
        audit.record_control(ENG, "report-builder", action, ENG, Result.OK, evidence=REF)
    with pytest.raises(ValueError):
        audit.record_control(ENG, "report-builder", action, ENG, Result.ABORTED,
                             evidence=REF, subject="report-v1")
    assert audit.entries == []


@pytest.mark.parametrize("result", [Result.PENDING_HITL, Result.ABORTED])
def test_entrega_pendiente_o_abortada(audit, result):
    audit.record_control(ENG, "report-delivery", "report.delivery", ENG, result,
                         subject="report-v1")
    with pytest.raises(ValueError):
        audit.record_control(ENG, "report-delivery", "report.delivery", ENG, Result.OK,
                             subject="report-v1")
    with pytest.raises(ValueError):
        audit.record_control(ENG, "report-delivery", "report.delivery", ENG, result)


def test_fallo_por_dato_sensible_sin_el_dato(audit):
    from harness.redaction import SensitiveData
    try:
        SensitiveData.check({"title": "contacto admin@juice-sh.op"})
    except SensitiveData as exc:
        audit.record_control(ENG, "report-builder", "report.generation_failed", ENG,
                             Result.ABORTED, exc.reason, subject="report-v1")
    (e,) = audit.entries
    assert e["reason"] == "sensitive_data"
    assert "juice-sh" not in repr(e)
