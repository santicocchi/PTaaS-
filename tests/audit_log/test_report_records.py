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
                                    "invalid_catalog_entry", "evidence_mismatch",
                                    "validation_mismatch", "finding_mismatch", "sensitive_data",
                                    "summary_jargon", "not_lab_target", "out_of_scope",
                                    "engagement_not_in_report", "engagement_delivered",
                                    "version_conflict", "internal_error"])
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


@pytest.mark.parametrize("subject,evidence", [
    ("f-1", "reports/eng-1/f-1.json#sha256=" + "ab" * 32),          # no es un informe
    ("report-v2", REF),                                              # otra versión
    ("report-v1", "evidence/eng-1/f-1-1.json#sha256=" + "ab" * 32),  # otro archivo
    ("report-v1", "reports/eng-2/report-v1.json#sha256=" + "ab" * 32),  # otro engagement
])
def test_informe_generado_con_otra_forma(audit, subject, evidence):
    with pytest.raises(ValueError):
        audit.record_control(ENG, "report-builder", "report.generated", ENG, Result.OK,
                             evidence=evidence, subject=subject)
    assert audit.entries == []


@pytest.mark.parametrize("action", ["report.delivery", "report.delivered"])
def test_entrega_con_sujeto_que_no_es_informe(audit, action):
    result = Result.PENDING_HITL if action == "report.delivery" else Result.OK
    evidence = None if action == "report.delivery" else REF
    with pytest.raises(ValueError):
        audit.record_control(ENG, "report-delivery", action, ENG, result, evidence=evidence,
                             subject="f-1")


@pytest.mark.parametrize("result,reason", [(Result.PENDING_HITL, None),
                                           (Result.ABORTED, "killswitch"),
                                           (Result.ABORTED, "invalid_output")])
def test_entrega_pendiente_o_abortada(audit, result, reason):
    audit.record_control(ENG, "report-delivery", "report.delivery", ENG, result, reason,
                         subject="report-v1")
    assert audit.entries[-1].get("reason") == reason
    with pytest.raises(ValueError):
        audit.record_control(ENG, "report-delivery", "report.delivery", ENG, Result.OK,
                             subject="report-v1")
    with pytest.raises(ValueError):
        audit.record_control(ENG, "report-delivery", "report.delivery", ENG, result, reason)


@pytest.mark.parametrize("result,reason", [(Result.ABORTED, None),
                                           (Result.ABORTED, "campo_raro"),
                                           (Result.PENDING_HITL, "killswitch")])
def test_entrega_con_motivo_invalido(audit, result, reason):
    with pytest.raises(ValueError):
        audit.record_control(ENG, "report-delivery", "report.delivery", ENG, result, reason,
                             subject="report-v1")


DREF = "approvals/eng-1/report-v1#sha256=" + "cd" * 32


@pytest.mark.parametrize("action", ["hitl.approve_delivery", "hitl.reject_delivery"])
def test_decision_de_entrega(audit, action):
    audit.record_control(ENG, "reviewer:beto", action, ENG, Result.OK, evidence=DREF,
                         subject="report-v1")
    for agent, evidence, subject, result in (
            ("report-builder", DREF, "report-v1", Result.OK),        # no es un reviewer
            ("reviewer:", DREF, "report-v1", Result.OK),             # sin nombre
            ("reviewer:beto", None, "report-v1", Result.OK),         # sin evidencia
            ("reviewer:beto", DREF, "f-1", Result.OK),               # no es un informe
            ("reviewer:beto", DREF.replace("report-v1", "report-v2"), "report-v1", Result.OK),
            ("reviewer:beto", DREF, "report-v1", Result.ABORTED)):
        with pytest.raises(ValueError):
            audit.record_control(ENG, agent, action, ENG, result, evidence=evidence,
                                 subject=subject)
    assert len(audit.entries) == 1


def test_entregado_apunta_al_resumen_de_la_entrega(audit):
    ok = "reports/eng-1/delivered-report-v1.json#sha256=" + "ab" * 32
    audit.record_control(ENG, "report-delivery", "report.delivered", "offline", Result.OK,
                         evidence=ok, subject="report-v1")
    with pytest.raises(ValueError):
        audit.record_control(ENG, "report-delivery", "report.delivered", "offline", Result.OK,
                             evidence=REF, subject="report-v1")


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


# --- La bitácora define la decisión de entrega vigente ------------------------------------
def test_control_de_validacion_con_sujeto_de_informe(tmp_path):
    from harness.approvals import ApprovalStore, audited_delivery
    log = SqliteAuditLog.open(ENG, tmp_path)
    log.record_control(ENG, "reviewer:beto", "hitl.approve", "dvwa.lab.test", Result.OK,
                       evidence="approvals/eng-1/report-v1#sha256=" + "ab" * 32,
                       subject="report-v1")
    store = ApprovalStore.open(ENG, tmp_path)
    assert audited_delivery(store, log.entries, ENG, "report-v1") is None


def test_fila_copiada_despues_de_un_rechazo(tmp_path):
    import sqlite3

    from harness.approvals import audited_delivery
    from tests.reporting.helpers import Lab
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    lab.decide_delivery()
    lab.decide_delivery(decision="rejected", reason="no")
    with sqlite3.connect(lab.approvals.path) as con:     # copia de la fila aprobada, al final
        con.execute("INSERT INTO delivery_decisions SELECT report_id, decision, reviewer, "
                    "reason, decided_at, expires_at, report_sha256, ack_unvalidated_high "
                    "FROM delivery_decisions WHERE decision = 'approved'")
    d = audited_delivery(lab.approvals, lab.audit.entries, lab.eng, "report-v1")
    assert d is not None and d.decision == "rejected"


def test_decision_de_entrega_no_cuenta_como_validacion(tmp_path):
    from harness.approvals import audited_decision
    from tests.reporting.helpers import Lab
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    lab.decide_delivery()
    assert audited_decision(lab.approvals, lab.audit.entries, lab.eng, "report-v1") is None
