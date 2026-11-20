"""Change 006 · validation: registro de aprobaciones (D5) y CLI del Reviewer (D6)."""
import sqlite3
import subprocess

import pytest

from harness import review
from harness.approvals import ApprovalStore, QueueItem, ReviewError, load_review_limits
from harness.audit import SqliteAuditLog

ENG = "eng-1"
T0 = 1_000_000.0


def item(finding_id="F-1", host="dvwa.lab.test", at=T0):
    return QueueItem(finding_id=finding_id, cwe="CWE-693", host=host, priority=7.5,
                     poc_id="POC-CSP-001",
                     params={"base_url": f"http://{host}", "path": "/"}, enqueued_at=at)


@pytest.fixture
def lab(tmp_path, monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("la CLI no ejecuta procesos ni envía tráfico")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    store = ApprovalStore.open(ENG, tmp_path / "state")
    store.enqueue(item())
    store.enqueue(item("F-2"))

    def cli(*args, now=T0 + 60):
        monkeypatch.setattr(review, "now", lambda: now)
        return review.main(["--engagement", ENG, "--state-dir", str(tmp_path / "state"),
                            "--audit-dir", str(tmp_path / "audit"), *args])

    def audit_entries():
        log = SqliteAuditLog.open(ENG, tmp_path / "audit")
        try:
            return log.entries
        finally:
            log.close()
    return store, cli, audit_entries


def test_limites_de_revision_de_la_politica():
    assert load_review_limits() == (60, 60)


# --- aprobar / rechazar -------------------------------------------------------------------
@pytest.mark.parametrize("reason", ["", "   "])
def test_aprobar_sin_motivo(lab, reason):
    store, cli, audit = lab
    assert cli("approve", "F-1", "--reviewer", "ana", "--reason", reason) != 0
    assert store.decisions("F-1") == [] and audit() == []


def test_aprobar_sin_reviewer_es_error_de_uso(lab):
    _, cli, audit = lab
    with pytest.raises(SystemExit) as exc:
        cli("approve", "F-1", "--reason", "ok")
    assert exc.value.code == 2 and audit() == []


@pytest.mark.parametrize("reviewer", ["", " ", "ana bob", "x" * 100])
def test_reviewer_invalido(lab, reviewer):
    store, cli, audit = lab
    assert cli("approve", "F-1", "--reviewer", reviewer, "--reason", "ok") != 0
    assert store.decisions("F-1") == [] and audit() == []


def test_aprobar_un_hallazgo_que_no_esta_en_cola(lab, capsys):
    store, cli, audit = lab
    assert cli("approve", "F-999", "--reviewer", "ana", "--reason", "ok") != 0
    assert "F-999" in capsys.readouterr().err
    assert store.decisions("F-999") == [] and audit() == []


def test_decision_registrada(lab, tmp_path):
    store, cli, audit = lab
    assert cli("reject", "F-1", "--reviewer", "ana", "--reason", "fuera de horario") == 0
    (d,) = store.decisions("F-1")
    assert (d.decision, d.reviewer, d.reason, d.decided_at) == ("rejected", "ana",
                                                                "fuera de horario", T0 + 60)
    (e,) = audit()
    assert (e["action"], e["target"], e["result"], e["phase"]) == ("hitl.reject",
                                                                    "dvwa.lab.test", "OK",
                                                                    "control")
    store.close("F-2", "not_validated", "reviewer_timeout", T0 + 3600)   # una fila por tabla
    con = sqlite3.connect(store.path)
    for sql in ("UPDATE decisions SET decision = 'approved'", "DELETE FROM decisions",
                "UPDATE queue SET host = 'x'", "DELETE FROM queue", "DELETE FROM closures"):
        with pytest.raises(sqlite3.DatabaseError):
            con.execute(sql)


def test_aprobacion_registrada_con_vencimiento(lab):
    store, cli, audit = lab
    assert cli("approve", "F-1", "--reviewer", "ana", "--reason", "en alcance") == 0
    (d,) = store.decisions("F-1")
    assert d.decision == "approved" and d.expires_at == T0 + 60 + 60 * 60
    assert [e["action"] for e in audit()] == ["hitl.approve"]
    assert store.status("F-1", T0 + 120) == "approved"
    assert store.status("F-2", T0 + 120) == "pending"        # el otro hallazgo no se aprueba


def test_aprobacion_vigente_no_se_vuelve_a_aprobar(lab):
    store, cli, audit = lab
    assert cli("approve", "F-1", "--reviewer", "ana", "--reason", "ok") == 0
    assert cli("approve", "F-1", "--reviewer", "bob", "--reason", "otra vez") != 0
    assert len(store.decisions("F-1")) == 1 and len(audit()) == 1


def test_rechazo_revoca_una_aprobacion_vigente(lab):
    """Revisión M3: la última fila manda; un reject sobre una aprobación vigente la revoca."""
    store, cli, audit = lab
    assert cli("approve", "F-1", "--reviewer", "ana", "--reason", "ok") == 0
    assert cli("reject", "F-1", "--reviewer", "bob", "--reason", "revocada") == 0
    assert store.status("F-1", T0 + 120) == "rejected"
    assert store.current("F-1", T0 + 120).decision == "rejected"
    assert [e["action"] for e in audit()] == ["hitl.approve", "hitl.reject"]
    assert cli("reject", "F-1", "--reviewer", "bob", "--reason", "otra vez") != 0


def test_rechazo_no_se_vuelve_a_pedir(lab):
    store, cli, _ = lab
    assert cli("reject", "F-1", "--reviewer", "ana", "--reason", "no") == 0
    assert cli("approve", "F-1", "--reviewer", "ana", "--reason", "sí", now=T0 + 10**6) != 0
    assert store.status("F-1", T0 + 10**6) == "rejected"


def test_aprobacion_vencida_se_puede_renovar(lab):
    store, cli, _ = lab
    assert cli("approve", "F-1", "--reviewer", "ana", "--reason", "ok") == 0
    later = T0 + 60 + 61 * 60
    assert store.status("F-1", later) == "expired"
    assert store.current("F-1", later) is None              # vencida = ninguna
    assert cli("approve", "F-1", "--reviewer", "ana", "--reason", "de nuevo", now=later) == 0
    assert store.status("F-1", later) == "approved"


def test_hallazgo_cerrado_no_se_aprueba(lab):
    store, cli, audit = lab
    store.close("F-1", "not_validated", "reviewer_timeout", T0 + 3600)
    assert cli("approve", "F-1", "--reviewer", "ana", "--reason", "tarde") != 0
    assert audit() == []


# --- listar -------------------------------------------------------------------------------
def test_listar(lab, capsys):
    store, cli, _ = lab
    store.enqueue(item("F-3"))
    assert cli("approve", "F-1", "--reviewer", "ana", "--reason", "ok") == 0
    assert cli("reject", "F-2", "--reviewer", "ana", "--reason", "no") == 0
    capsys.readouterr()
    assert cli("list") == 0
    lines = capsys.readouterr().out.strip().splitlines()
    rows = {line.split()[0]: line for line in lines[1:]}
    assert rows["F-1"].endswith("approved") and rows["F-2"].endswith("rejected")
    assert rows["F-3"].endswith("pending")
    for field in ("CWE-693", "dvwa.lab.test", "7.5", "POC-CSP-001", "base_url="):
        assert field in rows["F-3"]
    assert cli("list", now=T0 + 10**6) == 0
    assert capsys.readouterr().out.count("expired") == 1


# --- registro -------------------------------------------------------------------------------
def test_enqueue_es_idempotente(tmp_path):
    store = ApprovalStore.open(ENG, tmp_path)
    assert store.enqueue(item(at=T0)) is True
    assert store.enqueue(item(at=T0 + 999)) is False
    assert store.item("F-1").enqueued_at == T0


def test_decision_directa_valida_igual(tmp_path):
    store = ApprovalStore.open(ENG, tmp_path)
    with pytest.raises(ReviewError):
        store.decide("F-1", "approved", "ana", "ok", T0)
    store.enqueue(item())
    with pytest.raises(ReviewError):
        store.decide("F-1", "maybe", "ana", "ok", T0)


def test_engagement_invalido(tmp_path):
    with pytest.raises(ValueError):
        ApprovalStore.open("../x", tmp_path)


# --- revisión M1/M2: la decisión queda atada al hallazgo en la bitácora ----------------------
def test_control_con_subject_y_referencia_a_la_decision(lab):
    from harness.approvals import decision_audited, decision_ref
    store, cli, audit = lab
    assert cli("approve", "F-1", "--reviewer", "ana", "--reason", "ok") == 0
    (d,) = store.decisions("F-1")
    (e,) = audit()
    assert e["subject"] == "F-1" and e["agent"] == "reviewer:ana"
    assert e["evidence"] == decision_ref(ENG, d)
    assert decision_audited(audit(), ENG, d)


def test_fila_insertada_sin_la_cli_no_esta_auditada(lab):
    from harness.approvals import Decision, decision_audited
    store, cli, audit = lab
    assert cli("approve", "F-1", "--reviewer", "ana", "--reason", "ok") == 0
    (d,) = store.decisions("F-1")
    forged = [Decision("F-2", "approved", "ana", "ok", d.decided_at, d.expires_at, 2),
              Decision("F-1", "approved", "ana", "ok", d.decided_at, d.expires_at + 1,
                       d.revision),
              Decision("F-1", "approved", "bob", "ok", d.decided_at, d.expires_at, d.revision)]
    for f in forged:
        assert not decision_audited(audit(), ENG, f)


# --- revisión M5: registro y bitácora no divergen en silencio --------------------------------
def test_si_la_bitacora_falla_no_se_guarda_la_decision(lab, monkeypatch, capsys):
    store, cli, audit = lab

    def broken(self, *a, **k):
        raise OSError("disco lleno")
    monkeypatch.setattr(SqliteAuditLog, "record_control", broken)
    assert cli("approve", "F-1", "--reviewer", "ana", "--reason", "ok") != 0
    assert "NO" in capsys.readouterr().err
    monkeypatch.undo()
    assert store.decisions("F-1") == [] and audit() == []


def test_decision_y_bitacora_en_una_transaccion(tmp_path):
    from harness.approvals import record_decision
    from harness.contracts import AuditLog
    store = ApprovalStore.open(ENG, tmp_path)
    store.enqueue(item())

    class Boom(AuditLog):
        def record_control(self, *a, **k):
            raise RuntimeError("falla")
    with pytest.raises(RuntimeError):
        record_decision(store, Boom(), ENG, "F-1", "approved", "ana", "ok", T0)
    assert store.decisions("F-1") == []
    audit = AuditLog()
    d = record_decision(store, audit, ENG, "F-1", "approved", "ana", "ok", T0)
    assert store.decisions("F-1") == [d] and len(audit.entries) == 1


# --- revisión B1: la aprobación es de UNA versión de la verificación -------------------------
def test_verificacion_nueva_es_otra_revision_y_pide_otra_decision(lab):
    store, cli, _ = lab
    assert cli("approve", "F-1", "--reviewer", "ana", "--reason", "ok") == 0
    first = store.item("F-1")
    changed = QueueItem("F-1", "CWE-693", "dvwa.lab.test", 7.5, "POC-CSP-001",
                        {"base_url": "http://dvwa.lab.test:8080", "path": "/admin"}, T0 + 90)
    assert store.enqueue(changed) is True
    assert store.item("F-1").revision != first.revision
    assert store.item("F-1").params == changed.params
    assert store.current("F-1", T0 + 120) is None and store.status("F-1", T0 + 120) == "pending"
    assert cli("approve", "F-1", "--reviewer", "ana", "--reason", "nueva", now=T0 + 120) == 0
    assert store.current("F-1", T0 + 130).revision == store.item("F-1").revision


def test_volver_a_una_solicitud_anterior_es_otra_revision(tmp_path):
    store = ApprovalStore.open(ENG, tmp_path)
    a, b = item(), QueueItem("F-1", "CWE-693", "dvwa.lab.test", 7.5, "POC-CSP-001",
                             {"base_url": "http://dvwa.lab.test", "path": "/b"}, T0)
    assert store.enqueue(a) and store.enqueue(b)
    rev_a = store.item("F-1").revision
    assert store.enqueue(a) is True and store.item("F-1").revision > rev_a
    assert store.enqueue(a) is False
