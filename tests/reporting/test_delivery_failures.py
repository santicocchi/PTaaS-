"""Change 007 · reporting: fallos de la entrega, todos con su registro (D14, D17).

Revisión de seguridad del PR 2: no se entrega dos veces aunque el estado en memoria diga
REPORT, y cada intento fallido deja `report.delivery` ABORTED con su motivo.
"""
import sqlite3

import pytest

from harness.contracts import Guard, Harness, KillSwitch, KillSwitchEngaged, ScopeViolation
from harness.delivery import DeliveryError
from harness.engagement import State
from harness.policy_loader import phase_allowlist
from tests.reporting.helpers import DD_IP, DESTINATION, Lab, in_state
from tests.tool_adapters.test_defectdojo import KEY, FakeDojo


def _aborted(lab):
    return [(e["result"], e["reason"]) for e in lab.control("report.delivery")]


def _not_delivered(lab):
    assert lab.control("report.delivered") == []
    assert lab.engagement.state == State.REPORT


@pytest.fixture
def api_lab(tmp_path, monkeypatch):
    monkeypatch.setenv("PTAAS_DEFECTDOJO_API_KEY", KEY)
    dojo = FakeDojo()
    lab = Lab(tmp_path, destinations=[DESTINATION])
    lab.finding("f-1")
    lab.generate()
    lab.decide_delivery()
    lab.connector = dojo.connector
    yield lab, dojo
    dojo.close()


def test_no_se_entrega_dos_veces_offline(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    lab.decide_delivery()
    lab.deliver()
    lab.engagement = in_state(State.REPORT)            # otro proceso, estado recién armado
    with pytest.raises(DeliveryError) as exc:
        lab.deliver()
    assert exc.value.reason == "already_delivered"
    assert len(lab.control("report.delivered")) == 1


def test_no_se_envia_dos_veces_a_defectdojo(api_lab):
    lab, dojo = api_lab
    lab.deliver()
    lab.engagement = in_state(State.REPORT)
    with pytest.raises(DeliveryError) as exc:
        lab.deliver()                                 # la aprobación sigue vigente
    assert exc.value.reason == "already_delivered"
    assert len(dojo.requests) == 1 and len(lab.control("report.delivered")) == 1


def test_informe_alterado_queda_abortado(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    rep = lab.generate()
    lab.decide_delivery()
    rep.path.write_bytes(rep.path.read_bytes().replace(b"Falta", b"Sobra"))
    with pytest.raises(DeliveryError):
        lab.deliver()
    assert _aborted(lab) == [("ABORTED", "evidence_mismatch")]
    _not_delivered(lab)


def test_sin_adaptador_queda_abortado(api_lab):
    lab, dojo = api_lab
    h = Harness(Guard(phase_allowlist()), lab.audit, {}, KillSwitch(), lab.issuer,
                resolver=lambda host: [DD_IP])
    with pytest.raises(DeliveryError) as exc:
        lab.deliver(h)
    assert exc.value.reason == "adapter_error"
    assert _aborted(lab) == [("ABORTED", "adapter_error")] and dojo.requests == []
    _not_delivered(lab)


def test_token_que_no_se_emite_queda_abortado(api_lab, monkeypatch):
    lab, dojo = api_lab

    def refuse(*a, **k):
        raise ScopeViolation("fuera de la ventana", "outside_window")
    monkeypatch.setattr(lab.issuer, "issue", refuse)
    with pytest.raises(DeliveryError) as exc:
        lab.deliver()
    assert exc.value.reason == "out_of_scope"
    assert _aborted(lab) == [("ABORTED", "out_of_scope")] and dojo.requests == []
    _not_delivered(lab)


def test_bloqueo_del_guard_queda_abortado(api_lab):
    lab, dojo = api_lab
    h = lab.harness(resolver=lambda host: ["10.97.0.30"])      # resuelve fuera del /32
    with pytest.raises(DeliveryError):
        lab.deliver(h)
    assert _aborted(lab) == [("ABORTED", "out_of_scope")] and dojo.requests == []
    blocked = [e for e in lab.audit.entries if e["action"] == "defectdojo.export"]
    assert [e["result"] for e in blocked] == ["BLOCKED"]
    _not_delivered(lab)


def test_kill_switch_durante_el_envio(api_lab):
    lab, dojo = api_lab
    h = lab.harness()

    def connector(ip, port, timeout):
        h.killswitch.engage(lab.eng)                  # se activa con el POST en curso
        return dojo.connector(ip, port, timeout)
    h.tools["defectdojo.export"].connector = connector
    with pytest.raises(KillSwitchEngaged):
        lab.deliver(h)
    assert _aborted(lab) == [("ABORTED", "killswitch")]
    assert lab.control("report.delivered") == [] and lab.engagement.state == State.ABORTED


def test_la_cli_no_decide_con_la_cadena_rota(tmp_path, capsys):
    from harness import review
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    short = lab.latest().short
    lab.audit.close()
    con = sqlite3.connect(lab.audit.path)
    for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
        con.execute(f'DROP TRIGGER "{name}"')
    con.execute("UPDATE audit SET target='otro' WHERE seq=1")
    con.commit()
    con.close()
    code = review.main(["--engagement", lab.eng, "--state-dir", str(lab.state_dir),
                        "--audit-dir", str(lab.audit_dir), "report", "approve", "report-v1",
                        "--sha256", short, "--reviewer", "beto", "--reason", "ok"])
    assert code == 1 and "cadena" in capsys.readouterr().err
    assert lab.approvals.delivery_decisions("report-v1") == []
