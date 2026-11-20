"""Change 007 · reporting: hallazgos duplicados entre ejecuciones (D10)."""
import json

import pytest

from harness.contracts import Result
from harness.reporting import PreviousReportError, fingerprint, load_previous
from tests.reporting.helpers import Lab


def test_misma_huella_en_dos_engagements():
    assert fingerprint("asset-dvwa", "CWE-693") == fingerprint("asset-dvwa", "CWE-693")
    assert fingerprint("a", "CWE-693").startswith("fp1-") and len(fingerprint("a", "x")) == 36


def test_huella_distinta_por_activo_o_clave():
    fps = {fingerprint("a1", "CWE-693"), fingerprint("a2", "CWE-693"),
           fingerprint("a1", "CWE-1021"), fingerprint("a1", "CVE-2021-41773")}
    assert len(fps) == 4


def test_dos_corridas_en_el_mismo_engagement(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", asset="asset-dvwa")
    lab.finding("f-2", asset="asset-dvwa")
    lab.attempt("f-1", result="not_validated")
    lab.attempt("f-2")
    doc = json.loads(lab.generate().path.read_bytes())
    (f,) = doc["findings"]
    assert f["finding_ids"] == ["f-1", "f-2"] and f["validation"]["status"] == "validated"
    assert [a["finding_id"] for a in f["attempts"]] == ["f-1", "f-2"]


def _delivered(tmp_path, eng, cwes):
    lab = Lab(tmp_path / eng, eng=eng)
    for i, cwe in enumerate(cwes):
        lab.finding(f"f-{i}", cwe=cwe, asset="asset-dvwa")
    rep = lab.generate()
    out = lab.reports_dir() / "export.json"
    out.write_text("{}")
    import hashlib
    ref = f"reports/{eng}/export.json#sha256={hashlib.sha256(b'{}').hexdigest()}"
    lab.audit.record_control(eng, "report-delivery", "report.delivered", eng, Result.OK,
                             evidence=ref, subject=rep.report_id)
    return lab, rep


def test_recurrente_y_no_observado(tmp_path):
    old, _ = _delivered(tmp_path, "eng-1", ["CWE-693", "CWE-1021"])     # A y B
    prev = load_previous("eng-1", "report-v1", old.state_dir, old.audit_dir)
    lab = Lab(tmp_path / "eng-2", eng="eng-2")
    lab.finding("f-a", cwe="CWE-693", asset="asset-dvwa")              # A
    lab.finding("f-c", cwe="CWE-22", asset="asset-dvwa")               # C
    lab.previous = [prev]
    doc = json.loads(lab.generate().path.read_bytes())
    rec = {f["cwe"]: f["recurrence"] for f in doc["findings"]}
    assert rec["CWE-693"] == {"status": "recurring", "engagement": "eng-1",
                              "report_id": "report-v1"}
    assert rec["CWE-22"] == {"status": "new"}
    annex = doc["sections"][12]["content"]
    assert annex["not_observed"] == [fingerprint("asset-dvwa", "CWE-1021")]
    assert "no significa corregido" in annex["not_observed_note"]


def test_informe_anterior_no_entregado(tmp_path):
    lab = Lab(tmp_path / "eng-1", eng="eng-1")
    lab.finding("f-1")
    lab.generate()
    with pytest.raises(PreviousReportError):
        load_previous("eng-1", "report-v1", lab.state_dir, lab.audit_dir)


def test_informe_anterior_alterado(tmp_path):
    old, rep = _delivered(tmp_path, "eng-1", ["CWE-693"])
    rep.path.write_bytes(rep.path.read_bytes().replace(b"Falta", b"Sobra"))
    with pytest.raises(PreviousReportError):
        load_previous("eng-1", "report-v1", old.state_dir, old.audit_dir)
