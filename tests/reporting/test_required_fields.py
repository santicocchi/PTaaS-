"""Change 007 · reporting: hallazgo completo (D3). Task 3.1."""
import pytest

from harness.reporting import MissingField
from tests.reporting.helpers import ENTRIES, Lab, entry


def _failed(lab):
    return [(e["subject"], e["reason"]) for e in lab.control("report.generation_failed")]


def test_hallazgo_sin_cwe(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", cwe="unknown")
    with pytest.raises(MissingField) as exc:
        lab.generate()
    assert ("f-1", "cwe") in exc.value.missing
    assert lab.files() == []
    assert ("f-1", "missing_cwe") in _failed(lab)
    assert all(e["result"] == "ABORTED" for e in lab.control("report.generation_failed"))


def test_hallazgo_sin_remediacion(tmp_path):
    lab = Lab(tmp_path, entries={"CWE-693": entry(remediation="   ")})
    lab.finding("f-1")
    with pytest.raises(MissingField) as exc:
        lab.generate()
    assert exc.value.missing == [("f-1", "remediation")]
    assert lab.files() == [] and _failed(lab) == [("f-1", "missing_remediation")]


def test_cve_con_puntaje_31_sin_vector_curado(tmp_path):
    lab = Lab(tmp_path, entries={})
    lab.finding("f-1", cwe="CWE-22", cve="CVE-2021-41773", cvss=(7.5, "3.1"))
    with pytest.raises(MissingField) as exc:
        lab.generate()
    assert ("f-1", "cvss_v4_vector") in exc.value.missing
    assert lab.files() == []


def test_cve_usa_su_entrada_antes_que_la_del_cwe(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", cwe="CWE-22", cve="CVE-2021-41773", cvss=(7.5, "3.1"))
    rep = lab.generate()
    import json
    (f,) = json.loads(rep.path.read_bytes())["findings"]
    assert f["catalog_entry"] == "CVE-2021-41773" and f["severity"] == "Critical"
    assert f["feed_cvss"] == {"score": "7.5", "version": "3.1", "differs": False}


def test_varios_campos_faltantes(tmp_path):
    lab = Lab(tmp_path, entries={"CWE-693": entry(remediation="")})
    lab.finding("f-1", cwe="unknown")
    lab.finding("f-2", cwe="CWE-693", asset="asset-dvwa-2")
    with pytest.raises(MissingField) as exc:
        lab.generate()
    msg = str(exc.value)
    assert "f-1" in msg and "cwe" in msg and "f-2" in msg and "remediation" in msg
    # Uno por hallazgo y campo: sin CWE no hay entrada que buscar, así que no se suman
    # el vector ni la remediación de ese hallazgo.
    assert _failed(lab) == [("f-1", "missing_cwe"), ("f-2", "missing_remediation")]


@pytest.mark.parametrize("reviewer", ["ana", "pendiente", "", "Pendiente"])
def test_entrada_curada_sin_revisar(tmp_path, reviewer):
    lab = Lab(tmp_path, entries={"CWE-693": entry(reviewer=reviewer)})
    lab.finding("f-1")
    with pytest.raises(MissingField) as exc:
        lab.generate()
    assert exc.value.missing == [("f-1", "reviewer")]
    assert _failed(lab) == [("f-1", "invalid_catalog_entry")] and lab.files() == []


def test_revisor_igual_al_autor_sin_importar_mayusculas(tmp_path):
    lab = Lab(tmp_path, entries={"CWE-693": entry(author="ana", reviewer="Ana")})
    lab.finding("f-1")
    with pytest.raises(MissingField) as exc:
        lab.generate()
    assert exc.value.missing == [("f-1", "reviewer")]


def test_fecha_sin_comillas_no_vale(tmp_path):
    import datetime
    lab = Lab(tmp_path, entries={"CWE-693": entry(date=datetime.date(2026, 11, 20))})
    lab.finding("f-1")
    with pytest.raises(MissingField) as exc:
        lab.generate()
    assert exc.value.missing == [("f-1", "date")]
    assert _failed(lab) == [("f-1", "invalid_catalog_entry")]


def test_sin_entrada_para_el_cwe(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", cwe="CWE-79")
    with pytest.raises(MissingField) as exc:
        lab.generate()
    assert exc.value.missing == [("f-1", "cvss_v4_vector"), ("f-1", "remediation")]


def test_vector_curado_invalido(tmp_path):
    lab = Lab(tmp_path, entries={"CWE-693": entry(ENTRIES["CWE-693"]["cvss_v4_vector"] + "/x")})
    lab.finding("f-1")
    with pytest.raises(MissingField) as exc:
        lab.generate()
    assert exc.value.missing == [("f-1", "cvss_v4_vector")]
    assert _failed(lab) == [("f-1", "invalid_cvss_vector")]


def test_impacto_curado_con_jerga(tmp_path):
    lab = Lab(tmp_path, entries={"CWE-693": entry(business_impact="Es CWE-79 en la práctica.")})
    lab.finding("f-1")
    with pytest.raises(MissingField) as exc:
        lab.generate()
    assert ("f-1", "business_impact") in exc.value.missing


def test_tabla_del_repo_revisada_y_valida():
    """Las entradas del repo están revisadas (por alguien distinto del autor) y valen."""
    from harness.report_catalog import ReportCatalog, entry_problems
    catalog = ReportCatalog.load()
    assert catalog.raw
    assert {k: entry_problems(k, v) for k, v in catalog.raw.items()} == {
        k: [] for k in catalog.raw}


def test_tabla_sin_revisar_no_vale():
    from harness.report_catalog import ReportCatalog, entry_problems
    raw = ReportCatalog.load().raw
    for k, v in raw.items():
        assert entry_problems(k, {**v, "reviewer": "pendiente"}) == ["reviewer"]
        assert entry_problems(k, {**v, "reviewer": v["author"].upper()}) == ["reviewer"]


# ---- el CWE lo pone la tabla curada cuando el feed no lo trae (decisión del 20/11) ----------

def test_cve_sin_cwe_con_cwe_curado(tmp_path):
    import json
    lab = Lab(tmp_path, entries={"CVE-2099-0002": entry(cwe="CWE-22")})
    lab.finding("f-1", cwe="unknown", cve="CVE-2099-0002")
    rep = lab.generate()
    (f,) = json.loads(rep.path.read_bytes())["findings"]
    assert (f["cve"], f["cwe"], f["catalog_entry"]) == ("CVE-2099-0002", "CWE-22",
                                                        "CVE-2099-0002")
    assert f["references"][0] == "CWE-22"


def test_cve_sin_cwe_y_entrada_sin_cwe(tmp_path):
    lab = Lab(tmp_path, entries={"CVE-2099-0002": entry()})
    lab.finding("f-1", cwe="unknown", cve="CVE-2099-0002")
    with pytest.raises(MissingField) as exc:
        lab.generate()
    assert exc.value.missing == [("f-1", "cwe")]


def test_cwe_curado_distinto_del_feed(tmp_path):
    lab = Lab(tmp_path, entries={"CVE-2099-0001": entry(cwe="CWE-79")})
    lab.finding("f-1", cwe="CWE-22", cve="CVE-2099-0001")
    with pytest.raises(MissingField) as exc:
        lab.generate()
    assert exc.value.missing == [("f-1", "cwe")]
    assert lab.files() == []


def test_cwe_curado_igual_al_feed(tmp_path):
    lab = Lab(tmp_path, entries={"CVE-2099-0001": entry(cwe="CWE-22")})
    lab.finding("f-1", cwe="CWE-22", cve="CVE-2099-0001")
    lab.generate()


@pytest.mark.parametrize("key,cwe", [("CWE-693", "CWE-22"),        # solo en entradas por CVE
                                     ("CVE-2099-0002", "22"),
                                     ("CVE-2099-0002", "unknown"),
                                     ("CVE-2099-0002", ["CWE-22"])])
def test_cwe_curado_invalido(tmp_path, key, cwe):
    lab = Lab(tmp_path, entries={key: entry(cwe=cwe)})
    lab.finding("f-1", cwe="CWE-693" if key.startswith("CWE") else "unknown",
                cve=None if key.startswith("CWE") else key)
    with pytest.raises(MissingField) as exc:
        lab.generate()
    assert ("f-1", "cwe") in exc.value.missing
