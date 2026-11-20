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
    lab.finding("f-2", cwe="CWE-693", host="juiceshop.lab.test")
    with pytest.raises(MissingField) as exc:
        lab.generate()
    msg = str(exc.value)
    assert "f-1" in msg and "cwe" in msg and "f-2" in msg and "remediation" in msg
    assert ("f-1", "missing_cwe") in _failed(lab) and ("f-2", "missing_remediation") in _failed(lab)


@pytest.mark.parametrize("reviewer", ["ana", "pendiente", "", "Pendiente"])
def test_entrada_curada_sin_revisar(tmp_path, reviewer):
    lab = Lab(tmp_path, entries={"CWE-693": entry(reviewer=reviewer)})
    lab.finding("f-1")
    with pytest.raises(MissingField) as exc:
        lab.generate()
    assert {"cvss_v4_vector", "remediation"} <= {n for _, n in exc.value.missing}


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


def test_tabla_del_repo_sin_revisar_no_vale():
    from harness.report_catalog import ReportCatalog, entry_problems
    catalog = ReportCatalog.load()
    assert catalog.raw
    assert all(entry_problems(k, v) == ["reviewer"] for k, v in catalog.raw.items())
