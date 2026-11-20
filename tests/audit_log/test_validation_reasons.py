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


# --- revisión M2: el hallazgo (subject) queda en la cadena -----------------------------------
def test_subject_en_registro_y_control():
    audit = AuditLog()
    t = make_token(phase=Phase.VALIDATE)
    e1 = audit.record("v", act("poc_catalog.run_parametrized", Phase.VALIDATE), "10.0.0.5", t,
                      Result.PENDING_HITL, subject="F-1")
    e2 = audit.record_control("eng-1", "reviewer:ana", "hitl.approve", "dvwa.lab.test",
                              Result.OK, subject="F-1")
    assert e1["subject"] == "F-1" and e2["subject"] == "F-1"
    audit.verify_integrity()
    audit.entries[-1]["subject"] = "F-2"                   # cambiarlo rompe la cadena
    with pytest.raises(Exception):  # noqa: B017 - AuditIntegrityError
        audit.verify_integrity()


def test_sin_subject_el_registro_no_cambia():
    entry = AuditLog().record_control("eng-1", "x", "token.issue", "recon", Result.OK)
    assert "subject" not in entry


@pytest.mark.parametrize("subject", ["", "a/b", "F 1"])
def test_subject_invalido_se_rechaza(subject):
    with pytest.raises(ValueError):
        AuditLog().record_control("eng-1", "x", "hitl.approve", "h", Result.OK, subject=subject)


def test_subject_persistido_en_sqlite_y_bitacora_vieja(tmp_path):
    import sqlite3

    from harness import audit as audit_mod
    from harness.contracts import make_entry
    # Bitácora creada antes de 006: sin columna `subject`, con un registro.
    path = tmp_path / "eng-1.sqlite3"
    con = sqlite3.connect(path)
    con.executescript(audit_mod._SCHEMA.replace("  subject    TEXT,\n", ""))
    e = make_entry(prev=audit_mod.genesis("eng-1"), engagement="eng-1", agent="x",
                   action="token.issue", target="recon", phase="control", result=Result.OK)
    con.execute("INSERT INTO audit (ts, engagement, agent, action, target, phase, result, "
                "prev, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(e[k] for k in ("ts", "engagement", "agent", "action", "target", "phase",
                                     "result", "prev", "hash")))
    con.commit()
    assert "subject" not in [r[1] for r in con.execute("PRAGMA table_info(audit)")]
    con.close()
    assert audit_mod.verify_file(path) is None             # se lee sin la columna
    log = audit_mod.SqliteAuditLog.open("eng-1", tmp_path)  # y se agrega al abrir
    log.record_control("eng-1", "reviewer:ana", "hitl.approve", "h", Result.OK, subject="F-1")
    assert log.entries[-1]["subject"] == "F-1" and "subject" not in log.entries[0]
    log.close()
    assert audit_mod.verify_file(path) is None
