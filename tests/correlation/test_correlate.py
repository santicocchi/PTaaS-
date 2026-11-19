"""Change 005 · correlation: candidatos por versión, confianza por reglas y nada inventado."""
import socket

import pytest

from harness.contracts import Phase, ScopeViolation
from harness.correlate import Correlator
from tests.conftest import act, make_token
from tests.correlation.helpers import CLEAN_TWO, DEBIAN, Lab


def by_cve(result):
    return {c.cve: c for c in result.candidates}


def test_banner_de_distribucion_da_confianza_baja(tmp_path):
    lab = Lab(tmp_path, {"dvwa.lab.test": DEBIAN})
    result = Correlator(lab.harness, lab.token).run(["dvwa.lab.test"])
    assert result.reason == "ok" and result.synthetic
    c = by_cve(result)["CVE-2099-0001"]
    assert c.confidence == "low"
    assert any("backport" in r for r in c.evidence_refs)


def test_dos_herramientas_coinciden_da_confianza_media(tmp_path):
    lab = Lab(tmp_path, {"dvwa.lab.test": CLEAN_TWO})
    c = by_cve(Correlator(lab.harness, lab.token).run(["dvwa.lab.test"]))["CVE-2099-0001"]
    assert c.confidence == "medium"
    assert {"tool:httpx", "tool:nmap", "feed:nvd:CVE-2099-0001"} <= set(c.evidence_refs)
    assert c.cwe == "CWE-22" and c.attack_technique == "T1190"
    assert (c.cvss_score, c.cvss_version, c.epss) == (8.7, "4.0", 0.42)
    assert c.host == "dvwa.lab.test"


def test_una_sola_herramienta_da_confianza_baja(tmp_path):
    lab = Lab(tmp_path, {"dvwa.lab.test": [("Apache httpd:2.4.25", "nmap")]})
    c = by_cve(Correlator(lab.harness, lab.token).run(["dvwa.lab.test"]))["CVE-2099-0001"]
    assert c.confidence == "low"


def test_dato_ausente_queda_vacio(tmp_path):
    lab = Lab(tmp_path, {"dvwa.lab.test": CLEAN_TWO})
    c = by_cve(Correlator(lab.harness, lab.token).run(["dvwa.lab.test"]))["CVE-2099-0002"]
    assert c.epss is None                          # sin EPSS: null, no 0
    assert c.cwe == "unknown" and c.attack_technique is None
    assert (c.cvss_score, c.cvss_version) == (5.3, "3.1")   # no se convierte a 4.0
    assert c.confidence == "low"                   # cwe unknown


def test_producto_desconocido_no_da_candidatos(tmp_path):
    lab = Lab(tmp_path, {"dvwa.lab.test": [("AppDesconocida:0.1", "httpx"),
                                           ("Apache Tomcat:2.4.25", "nmap")]})
    assert Correlator(lab.harness, lab.token).run(["dvwa.lab.test"]).candidates == []


def test_version_fuera_de_rango_no_da_candidato(tmp_path):
    lab = Lab(tmp_path, {"dvwa.lab.test": CLEAN_TWO})
    assert "CVE-2099-0003" not in by_cve(Correlator(lab.harness, lab.token).run(
        ["dvwa.lab.test"]))


def test_feed_desactualizado_marca_y_baja_confianza(tmp_path):
    lab = Lab(tmp_path, {"dvwa.lab.test": CLEAN_TWO}, age_days=45)
    c = by_cve(Correlator(lab.harness, lab.token).run(["dvwa.lab.test"]))["CVE-2099-0001"]
    assert c.feed_stale and c.confidence == "low"


def test_feed_alterado_no_genera_candidatos_y_queda_en_bitacora(tmp_path):
    lab = Lab(tmp_path, {"dvwa.lab.test": CLEAN_TWO})
    with open(lab.feeds_dir / "nvd.json", "a") as fh:
        fh.write(" ")
    result = Correlator(lab.harness, lab.token).run(["dvwa.lab.test"])
    assert result.candidates == [] and result.reason == "feed_unavailable:hash_mismatch:nvd.json"
    (ctrl,) = [e for e in lab.audit.entries if e["action"] == "feed.unavailable"]
    assert ctrl["result"] == "ABORTED"


def test_cada_consulta_pasa_por_el_harness_con_token_correlate(tmp_path):
    lab = Lab(tmp_path, {"dvwa.lab.test": CLEAN_TWO})
    Correlator(lab.harness, lab.token).run(["dvwa.lab.test"])
    oks = [e for e in lab.audit.entries if e["result"] == "OK"]
    assert [e["action"] for e in oks] == ["cve.lookup", "epss.lookup", "cwe.map"]
    assert {e["phase"] for e in oks} == {"correlate"} and {e["target"] for e in oks} == {
        "dvwa.lab.test"}


def test_correlacion_sin_red(tmp_path, monkeypatch):
    lab = Lab(tmp_path, {"dvwa.lab.test": CLEAN_TWO})

    def no_net(*a, **k):
        raise AssertionError("la correlación abrió una conexión")

    monkeypatch.setattr(socket.socket, "connect", no_net)
    monkeypatch.setattr(socket, "create_connection", no_net)
    assert Correlator(lab.harness, lab.token).run(["dvwa.lab.test"]).candidates


def test_las_tecnologias_salen_del_grafo(tmp_path):
    lab = Lab(tmp_path, {"dvwa.lab.test": [("Apache httpd:2.4.31", "nmap")]})
    out = lab.harness.invoke("x", act("cve.lookup", Phase.CORRELATE), "dvwa.lab.test",
                             lab.token)
    assert out["matches"] == []                    # 2.4.31 no está en ningún rango


def test_host_fuera_de_alcance_no_se_correlaciona(tmp_path):
    lab = Lab(tmp_path, {"dvwa.lab.test": CLEAN_TWO})
    result = Correlator(lab.harness, lab.token).run(["203.0.113.7"])
    assert result.candidates == []
    assert any(e["result"] == "BLOCKED" and e["target"] == "203.0.113.7"
               for e in lab.audit.entries)


def test_en_correlate_no_se_puede_sondear(tmp_path):
    lab = Lab(tmp_path, {"dvwa.lab.test": CLEAN_TWO})
    with pytest.raises(ScopeViolation):
        lab.harness.invoke("x", act("httpx.probe", Phase.CORRELATE), "dvwa.lab.test",
                           lab.token)


def test_correlador_exige_token_correlate(tmp_path):
    lab = Lab(tmp_path, {"dvwa.lab.test": CLEAN_TWO})
    with pytest.raises(ValueError):
        Correlator(lab.harness, make_token(Phase.RECON))


def test_kill_switch_detiene_la_correlacion(tmp_path):
    lab = Lab(tmp_path, {"dvwa.lab.test": CLEAN_TWO})
    lab.harness.killswitch.engage("eng-1")
    assert Correlator(lab.harness, lab.token).run(["dvwa.lab.test"]).reason == "abortado"


def test_mismos_insumos_mismos_candidatos(tmp_path):
    a = Lab(tmp_path / "a", {"dvwa.lab.test": DEBIAN})
    b = Lab(tmp_path / "b", {"dvwa.lab.test": DEBIAN})
    ra = Correlator(a.harness, a.token).run(["dvwa.lab.test"]).candidates
    rb = Correlator(b.harness, b.token).run(["dvwa.lab.test"]).candidates
    assert [c.__dict__ for c in ra] == [c.__dict__ for c in rb]
