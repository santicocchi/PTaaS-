"""Change 005 · vuln-analysis: resolución con reglas fijas, contradicciones y falsos positivos."""
import pytest

from harness.analysis import load_false_positives
from tests.vuln_analysis.helpers import (
    CSP_N,
    CSP_Z,
    SRV_Z_ROOT,
    Lab,
    by_cwe,
    fp,
    nuclei_out,
    version_candidate,
    zap_out,
)


def test_version_sola_no_confirma(tmp_path):
    res = Lab(tmp_path).run([version_candidate()])
    (v,) = res.vulns
    assert v.status == "inconclusive" and "versión" in v.rationale
    assert res.stop_reasons[v.finding_id] == "sin ganancia de información"


def test_dos_herramientas_coinciden_confirma_con_las_dos_evidencias(tmp_path):
    res = Lab(tmp_path, nuclei=[nuclei_out(CSP_N)], zap=[zap_out(CSP_Z)]).run()
    v = by_cwe(res)["CWE-693"]
    assert v.status == "confirmed" and not v.needs_review
    assert {"nuclei:ptaas-missing-csp@http://dvwa.lab.test:80/",
            "zap:10038@http://dvwa.lab.test:80/"} <= set(v.evidence_refs)
    assert res.stop_reasons[v.finding_id] == "hallazgo resuelto"


def test_contradiccion_zap_marca_y_nuclei_no(tmp_path):
    res = Lab(tmp_path, nuclei=[nuclei_out()], zap=[zap_out(CSP_Z)]).run()
    v = by_cwe(res)["CWE-693"]
    assert v.status == "inconclusive" and v.needs_review
    assert "10038" in v.rationale and "ptaas-missing-csp" in v.rationale


def test_contradiccion_nuclei_marca_y_zap_vio_la_url_y_no(tmp_path):
    res = Lab(tmp_path, nuclei=[nuclei_out(CSP_N)], zap=[zap_out(SRV_Z_ROOT)]).run()
    v = by_cwe(res)["CWE-693"]
    assert v.status == "inconclusive" and v.needs_review


def test_si_zap_no_vio_la_url_no_hay_contradiccion(tmp_path):
    res = Lab(tmp_path, nuclei=[nuclei_out(CSP_N)], zap=[zap_out()]).run()
    v = by_cwe(res)["CWE-693"]
    assert v.status == "confirmed" and not v.needs_review


def test_silencio_de_la_herramienta_no_descarta(tmp_path):
    res = Lab(tmp_path).run([version_candidate(cve=None, cwe="CWE-1021")])
    (v,) = res.vulns
    assert v.status == "inconclusive"


def test_contradiccion_en_una_url_y_confirmacion_en_otra(tmp_path):
    login = ("10038", "CWE-693", "http://dvwa.lab.test:80/login.php", "Medium", "High")
    res = Lab(tmp_path, nuclei=[nuclei_out()], zap=[zap_out(CSP_Z, login)]).run()
    v = by_cwe(res)["CWE-693"]
    assert v.status == "confirmed" and v.needs_review     # la persona igual ve la contradicción


def test_falso_positivo_conocido_queda_descartado_con_motivo(tmp_path):
    alert = ("10054", "CWE-1275", "http://dvwa.lab.test:80/", "Low", "Medium")
    lab = Lab(tmp_path, zap=[zap_out(alert)], fps=[fp("10054", r"dvwa\.lab\.test:80/$")])
    v = by_cwe(lab.run())["CWE-1275"]
    assert v.status == "discarded" and "FP-T1" in v.rationale


def test_falso_positivo_sin_revisor_no_se_aplica(tmp_path):
    alert = ("10054", "CWE-1275", "http://dvwa.lab.test:80/", "Low", "High")
    lab = Lab(tmp_path, zap=[zap_out(alert)],
              fps=[fp("10054", r"dvwa", approved=False)])
    assert by_cwe(lab.run())["CWE-1275"].status == "confirmed"


def test_falso_positivo_no_tapa_riesgo_alto(tmp_path):
    alert = ("40012", "CWE-79", "http://dvwa.lab.test:80/", "High", "High")
    lab = Lab(tmp_path, zap=[zap_out(alert)], fps=[fp("40012", r".*")])
    assert by_cwe(lab.run())["CWE-79"].status == "confirmed"


def test_falso_positivo_no_tapa_un_cve(tmp_path):
    alert = ("10036", "CWE-22", "http://dvwa.lab.test:80/", "Low", "Medium")
    lab = Lab(tmp_path, zap=[zap_out(alert)], fps=[fp("10036", r".*")])
    res = lab.run([version_candidate()])
    v = next(x for x in res.vulns if x.finding_id == "f-CVE-2099-0001")
    assert v.status != "discarded"


def test_informativas_y_sin_cwe_no_son_candidatos(tmp_path):
    info = ("10112", "CWE-200", "http://dvwa.lab.test:80/", "Informational", "Medium")
    panel = ("ptaas-dvwa-login-panel", "unknown", "http://dvwa.lab.test:80/login.php")
    res = Lab(tmp_path, nuclei=[nuclei_out(panel)], zap=[zap_out(info)]).run()
    assert res.vulns == []


def test_prioridad_con_version_de_cvss_y_criticidad(tmp_path):
    lab = Lab(tmp_path, criticality=lambda h: (4, False))
    (v,) = lab.run([version_candidate()]).vulns
    assert v.priority == round(0.6 * 8.7 + 2.5 * 0.42 + 0.25 * 4, 2)
    assert (v.cvss_score, v.cvss_version, v.cvss_v4_score) == (8.7, "4.0", 8.7)
    assert "valor por defecto" not in v.rationale


def test_criticidad_por_defecto_se_dice(tmp_path):
    (v,) = Lab(tmp_path).run([version_candidate()]).vulns
    assert "criticidad 3 (valor por defecto)" in v.rationale


def test_cvss_31_no_se_presenta_como_40(tmp_path):
    (v,) = Lab(tmp_path).run([version_candidate(cvss=5.3, version="3.1", epss=None)]).vulns
    assert v.cvss_v4_score is None and v.cvss_version == "3.1"
    assert "EPSS sin dato" in v.rationale


def test_sin_cvss_va_al_final(tmp_path):
    res = Lab(tmp_path, nuclei=[nuclei_out(CSP_N)]).run([version_candidate()])
    assert res.vulns[0].priority is not None and res.vulns[-1].priority is None
    assert "Sin puntaje" in res.vulns[-1].rationale


def test_mismos_insumos_mismo_resultado(tmp_path):
    a = Lab(tmp_path / "a", nuclei=[nuclei_out(CSP_N)], zap=[zap_out(CSP_Z)]).run(
        [version_candidate()])
    b = Lab(tmp_path / "b", nuclei=[nuclei_out(CSP_N)], zap=[zap_out(CSP_Z)]).run(
        [version_candidate()])
    assert a.vulns == b.vulns


@pytest.mark.parametrize("entry", [
    {"id": "FP-1"},
    {"id": "FP-1", "tool": "zap", "check": "1", "url_pattern": "x", "reason": "r",
     "author": "a", "reviewer": "b", "date": "d", "cve": "CVE-2099-0001"},
    {"id": "FP-1", "tool": "otra", "check": "1", "url_pattern": "x", "reason": "r",
     "author": "a", "reviewer": "b", "date": "d"},
])
def test_lista_de_falsos_positivos_invalida(tmp_path, entry):
    import yaml
    path = tmp_path / "fp.yaml"
    path.write_text(yaml.safe_dump({"entries": [entry]}))
    with pytest.raises(ValueError):
        load_false_positives(path)


def test_lista_del_repo_es_valida():
    assert all(e.approved is not None for e in load_false_positives())


def test_autor_que_se_revisa_a_si_mismo_no_aprueba(tmp_path):
    import yaml
    path = tmp_path / "fp.yaml"
    path.write_text(yaml.safe_dump({"entries": [
        {"id": "FP-1", "tool": "zap", "check": "1", "url_pattern": "x", "reason": "r",
         "author": "Ana", "reviewer": "ana", "date": "d"}]}))
    assert not load_false_positives(path)[0].approved
