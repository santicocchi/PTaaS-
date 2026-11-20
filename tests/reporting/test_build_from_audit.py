"""Change 007 · reporting: informe armado desde los hallazgos y la bitácora (D2). Task 2.1, 2.2."""
import json
import sqlite3

import pytest

from harness.contracts import AuditIntegrityError
from harness.engagement import State
from harness.reporting import ReportError
from tests.reporting.helpers import Lab


def test_evidencia_del_loop_c_en_el_informe(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    ref = lab.attempt("f-1")
    rep = lab.generate()
    doc = json.loads(rep.path.read_bytes())
    sections = {s["key"]: s["content"] for s in doc["sections"]}
    assert doc["findings"][0]["evidence"] == [ref]
    assert sections["annex_evidence"]["refs"] == [ref]
    (gen,) = lab.control("report.generated")
    assert gen["subject"] == "report-v1" and gen["evidence"] == rep.ref
    assert rep.ref.startswith("reports/eng-1/report-v1.json#sha256=")


def test_evidencia_alterada(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    ref = lab.attempt("f-1")
    path = lab.state_dir / ref.split("#")[0]
    path.write_text(path.read_text().replace('"validated"', '"validatedX"'))
    with pytest.raises(ReportError) as exc:
        lab.generate()
    assert exc.value.reason == "evidence_mismatch" and ref in str(exc.value)
    assert lab.files() == []
    assert lab.control("report.generation_failed")[-1]["reason"] == "evidence_mismatch"


def test_cadena_rota(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.closed("f-1", "no_catalog_entry")
    lab.closed("f-1", "no_catalog_entry")
    with sqlite3.connect(lab.audit_dir / "eng-1.sqlite3") as con:   # registro intermedio
        con.execute("DROP TRIGGER IF EXISTS audit_no_update")
        con.execute("UPDATE audit SET target = 'otro' WHERE seq = 2")
    with pytest.raises(AuditIntegrityError):
        lab.generate()
    assert lab.files() == []


@pytest.mark.parametrize("state,reason", [(State.VALIDATE, "engagement_not_in_report"),
                                          (State.DELIVERED, "engagement_delivered")])
def test_engagement_fuera_de_report(tmp_path, state, reason):
    lab = Lab(tmp_path, state=State.REPORT)
    if state == State.DELIVERED:
        lab.engagement.approve("before_deliver")
        lab.engagement.advance()
    else:
        lab.engagement.state = state
    lab.finding("f-1")
    with pytest.raises(ReportError) as exc:
        lab.generate()
    assert exc.value.reason == reason and lab.files() == []
    assert lab.control("report.generation_failed")[-1]["reason"] == reason


def test_host_fuera_del_laboratorio(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", host="app.example.com")
    with pytest.raises(ReportError) as exc:
        lab.generate()
    assert exc.value.reason == "not_lab_target" and lab.files() == []


def test_epss_junto_al_cvss(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", epss=0.973)
    lab.finding("f-2", cwe="CWE-1021")
    lab.finding("f-3", cwe="CWE-22", epss=0.5, feed_stale=True)
    doc = json.loads(lab.generate().path.read_bytes())
    epss = {f["finding_ids"][0]: f["epss"]["text"] for f in doc["findings"]}
    assert epss["f-1"].startswith("0.973 (snapshot del ") and epss["f-2"] == "sin dato"
    assert epss["f-3"] == "0.500 (dato desactualizado)"
    f1 = next(f for f in doc["findings"] if f["finding_ids"] == ["f-1"])
    assert (f1["cvss_v4_score"], f1["severity"]) == ("2.1", "Low")
