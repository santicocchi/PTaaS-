"""Change 007 · engagement-lifecycle: REPORT → DELIVERED solo con entrega registrada (D17)."""
import sqlite3

import pytest

from harness.contracts import AuditIntegrityError, KillSwitchEngaged
from harness.delivery import DeliveryError, DeliveryNotApproved
from harness.engagement import State, TransitionError
from harness.reporting import ReportError
from tests.reporting.helpers import DESTINATION, Lab


def _ready(tmp_path, **kw):
    lab = Lab(tmp_path, **kw)
    lab.finding("f-1")
    lab.generate()
    return lab


def test_entrega_aprobada(tmp_path):
    lab = _ready(tmp_path)
    lab.decide_delivery()
    lab.deliver()
    assert lab.engagement.state == State.DELIVERED
    assert [e["result"] for e in lab.control("report.delivered")] == ["OK"]


def test_avanzar_sin_entrega(tmp_path):
    lab = _ready(tmp_path)
    with pytest.raises(TransitionError) as exc:
        lab.engagement.advance()
    assert "before_deliver" in str(exc.value) and lab.engagement.state == State.REPORT
    with pytest.raises(TransitionError):
        lab.engagement.approve("before_deliver")       # ni a mano
    with pytest.raises(TransitionError):
        lab.engagement.grant_delivery(object())        # ni con otra marca
    with pytest.raises(DeliveryNotApproved):
        lab.deliver()
    assert lab.engagement.state == State.REPORT


def test_falla_la_exportacion(tmp_path, monkeypatch):
    import http.client
    monkeypatch.setenv("PTAAS_DEFECTDOJO_API_KEY", "k-test")
    lab = _ready(tmp_path, destinations=[DESTINATION])
    lab.decide_delivery()
    lab.connector = lambda ip, port, t: http.client.HTTPConnection("127.0.0.1", 1, timeout=t)
    with pytest.raises(DeliveryError) as exc:
        lab.deliver()
    assert exc.value.reason == "exec_error"
    assert lab.control("report.delivered") == [] and lab.engagement.state == State.REPORT
    (aborted,) = lab.control("report.delivery")
    assert (aborted["result"], aborted["reason"]) == ("ABORTED", "exec_error")
    sent = [e for e in lab.audit.entries if e["action"] == "defectdojo.export"]
    assert [(e["result"], e["subject"]) for e in sent] == [("OK", "report-v1")]  # write-ahead


def test_kill_switch_durante_report(tmp_path):
    lab = _ready(tmp_path)
    lab.decide_delivery()
    h = lab.harness()
    h.kill(lab.eng, "operador")
    with pytest.raises(KillSwitchEngaged):
        lab.deliver(h)
    (aborted,) = lab.control("report.delivery")
    assert (aborted["result"], aborted["reason"]) == ("ABORTED", "killswitch")
    assert lab.engagement.state == State.ABORTED
    assert not any(n.startswith(("defectdojo-", "delivered-")) for n in lab.files())


def test_cadena_rota_aborta(tmp_path):
    lab = _ready(tmp_path)
    lab.decide_delivery()
    with sqlite3.connect(lab.audit_dir / "eng-1.sqlite3") as con:   # registro intermedio
        con.execute("DROP TRIGGER IF EXISTS audit_no_update")
        con.execute("UPDATE audit SET target = 'otro' WHERE seq = 2")
    with pytest.raises(AuditIntegrityError):
        lab.deliver()
    assert lab.engagement.state == State.ABORTED and lab.control("report.delivered") == []


def test_informe_nuevo_despues_de_entregar(tmp_path):
    lab = _ready(tmp_path)
    lab.decide_delivery()
    lab.deliver()
    before = lab.files()
    with pytest.raises(ReportError) as exc:
        lab.generate()
    assert exc.value.reason == "engagement_delivered" and lab.files() == before
