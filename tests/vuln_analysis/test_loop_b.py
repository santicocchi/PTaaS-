"""Change 005 · vuln-analysis: loop B acotado, una vez por servicio y con estado persistido."""
import sqlite3

import pytest

from harness.analysis import AnalysisLoop, FindingStore
from harness.contracts import Phase
from harness.engagement import Engagement, State
from tests.conftest import make_token
from tests.vuln_analysis.helpers import (
    CSP_N,
    CSP_Z,
    Lab,
    nuclei_out,
    version_candidate,
    zap_out,
)


def test_plan_nuclei_y_despues_zap_una_vez_por_host(tmp_path):
    lab = Lab(tmp_path)
    lab.run([version_candidate(), version_candidate("CVE-2099-0002", "unknown"),
             version_candidate("CVE-2099-0003", "CWE-79")])
    assert lab.log == [("nuclei.safe_templates", "dvwa.lab.test"),
                       ("zap.baseline_scan", "dvwa.lab.test")]


def test_todo_pasa_por_el_harness_con_token_analyze(tmp_path):
    lab = Lab(tmp_path)
    lab.run()
    oks = [e for e in lab.audit.entries if e["result"] == "OK"]
    assert [e["action"] for e in oks] == ["nuclei.safe_templates", "zap.baseline_scan"]
    assert {e["phase"] for e in oks} == {"analyze"}


def test_reinicio_no_repite_lo_hecho(tmp_path):
    lab = Lab(tmp_path, nuclei=[nuclei_out(CSP_N)], zap=[ConnectionError("cortado")])
    first = lab.run()
    assert lab.log == [("nuclei.safe_templates", "dvwa.lab.test"),
                       ("zap.baseline_scan", "dvwa.lab.test")]
    assert first.vulns                                     # lo de nuclei quedó guardado
    again = Lab(tmp_path, zap=[zap_out(CSP_Z)], store=FindingStore(lab.store.path))
    res = again.run()
    assert again.log == [("zap.baseline_scan", "dvwa.lab.test")]   # nuclei no se repite
    assert res.vulns[0].status == "confirmed"


def test_estado_append_only(tmp_path):
    lab = Lab(tmp_path, nuclei=[nuclei_out(CSP_N)])
    lab.run()
    con = sqlite3.connect(lab.store.path)
    for sql in ("UPDATE observations SET cwe = 'x'", "DELETE FROM observations",
                "DELETE FROM events", "UPDATE events SET value = 'x'"):
        with pytest.raises(sqlite3.DatabaseError):
            con.execute(sql)


def test_dos_iteraciones_sin_evidencia_nueva_es_inconcluso(tmp_path):
    res = Lab(tmp_path).run([version_candidate()])
    (v,) = res.vulns
    assert v.status == "inconclusive"
    assert res.stop_reasons[v.finding_id] == "sin ganancia de información"


def test_tope_de_iteraciones(tmp_path):
    lab = Lab(tmp_path, max_iterations=1)
    res = lab.run([version_candidate()])
    assert res.stop_reasons[res.vulns[0].finding_id] == "tope de iteraciones alcanzado"


@pytest.mark.parametrize("bad", [0, -1, "4", 2.5])
def test_tope_invalido(tmp_path, bad):
    with pytest.raises(ValueError):
        Lab(tmp_path, max_iterations=bad)


def test_kill_switch_detiene_sin_reintentar(tmp_path):
    lab = Lab(tmp_path)
    lab.harness.killswitch.engage("eng-1")
    res = lab.run([version_candidate()])
    assert res.reason == "abortado: kill switch" and lab.log == []
    assert res.vulns[0].status == "inconclusive"


def test_token_revocado_detiene(tmp_path):
    lab = Lab(tmp_path)
    lab.loop.token = make_token(Phase.ANALYZE, cidrs=("10.99.0.0/24",),
                                domains=("dvwa.lab.test",), start=0, end=1)
    assert lab.run().reason == "abortado: token_expired"


def test_error_de_herramienta_queda_en_bitacora_y_sigue(tmp_path):
    err = {"tool": "nuclei", "status": "error", "error": "timeout"}
    lab = Lab(tmp_path, nuclei=[err], zap=[zap_out(CSP_Z)])
    res = lab.run()
    (ctrl,) = [e for e in lab.audit.entries if e["action"] == "tool.error"]
    assert ctrl["reason"] == "timeout" and ctrl["result"] == "ABORTED"
    assert ("zap.baseline_scan", "dvwa.lab.test") in lab.log
    assert res.vulns


def test_salida_invalida_dos_veces_escala_y_deshabilita(tmp_path):
    bad = {"tool": "nuclei", "status": "invalid_output", "findings": [], "invalid_lines": 3}
    lab = Lab(tmp_path, nuclei=[bad])
    lab.run(hosts=["dvwa.lab.test"])
    lab.run(hosts=["dvwa.lab.test"])
    assert "nuclei.safe_templates" in lab.store.disabled()
    assert [e for e in lab.audit.entries if e["action"] == "tool.escalated"]
    n = len(lab.log)
    lab.run(hosts=["dvwa.lab.test"])
    assert ("nuclei.safe_templates", "dvwa.lab.test") not in lab.log[n:]


def test_host_fuera_de_alcance_no_se_analiza(tmp_path):
    lab = Lab(tmp_path)
    lab.run(hosts=["203.0.113.7"])
    assert lab.log == []
    assert any(e["result"] == "BLOCKED" for e in lab.audit.entries)


def test_exige_token_analyze(tmp_path):
    lab = Lab(tmp_path)
    with pytest.raises(ValueError):
        AnalysisLoop(lab.harness, make_token(Phase.CORRELATE), lab.store,
                     engagement=lab.engagement, asset_of=lambda h: h)


def test_engagement_id_invalido(tmp_path):
    with pytest.raises(ValueError):
        FindingStore.open("../x", tmp_path)


@pytest.mark.parametrize("state", [State.AUTHORIZED, State.RECON, State.CORRELATE])
def test_sin_engagement_en_analyze_no_se_invoca_nada(tmp_path, state):
    """Revisión 005, B3: el loop B no salta la máquina de estados ni su gate HITL."""
    lab = Lab(tmp_path)
    e = Engagement(roe_valid=True)
    if state != State.AUTHORIZED:
        e.approve("first_active_action")
    while e.state != state:
        e.advance()
    lab.loop.engagement = e
    res = lab.run([version_candidate()])
    assert res.reason == "engagement fuera de ANALYZE" and lab.log == []
    assert not [x for x in lab.audit.entries if x["phase"] == "analyze"]
