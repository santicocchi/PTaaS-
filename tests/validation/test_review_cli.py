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


def test_decision_vigente_no_se_pisa(lab):
    store, cli, audit = lab
    assert cli("approve", "F-1", "--reviewer", "ana", "--reason", "ok") == 0
    assert cli("reject", "F-1", "--reviewer", "bob", "--reason", "no") != 0
    assert cli("approve", "F-1", "--reviewer", "bob", "--reason", "otra vez") != 0
    assert len(store.decisions("F-1")) == 1 and len(audit()) == 1


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
