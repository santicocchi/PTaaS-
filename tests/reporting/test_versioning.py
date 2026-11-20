"""Change 007 · reporting: versiones inmutables y reproducibles (D2, D9)."""
import json

import pytest

from harness import reporting
from harness.reporting import MissingField, ReportError, reproduce
from tests.reporting.helpers import Lab, entry


def _reproduce(lab, report_id="report-v1"):
    return reproduce(lab.eng, report_id, lab.state_dir, lab.audit_dir)


def test_reproduccion_exacta(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.attempt("f-1")
    lab.observe("dvwa.lab.test", "CWE-693", "http://dvwa.lab.test/", "Set-Cookie: a=b")
    lab.generate()
    lab.closed("f-9", "no_catalog_entry")            # registros posteriores
    assert _reproduce(lab) == (True, "")
    assert reporting.main(["reproduce", "--engagement", lab.eng, "--report", "report-v1",
                           "--state-dir", str(lab.state_dir),
                           "--audit-dir", str(lab.audit_dir)]) == 0


def test_snapshot_de_entradas_alterado(tmp_path, capsys):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    path = lab.reports_dir() / "inputs-v1.json"
    path.write_bytes(path.read_bytes().replace(b"dvwa", b"dvwb"))
    ok, why = _reproduce(lab)
    assert not ok and "inputs-v1.json" in why
    assert reporting.main(["reproduce", "--engagement", lab.eng, "--report", "report-v1",
                           "--state-dir", str(lab.state_dir),
                           "--audit-dir", str(lab.audit_dir)]) == 1


def test_markdown_alterado(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    rep = lab.generate()
    rep.markdown_path.write_text(rep.markdown_path.read_text() + "x")
    assert _reproduce(lab) == (False, "el markdown no coincide")


def test_cambio_en_un_hallazgo_despues_de_generar(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    v1 = lab.generate()
    before = v1.path.read_bytes()
    lab.entries["CWE-693"] = entry(lab.entries["CWE-693"]["cvss_v4_vector"],
                                   remediation="Otra remediación. Con detalle.")
    v2 = lab.generate()
    assert v2.report_id == "report-v2" and v1.path.read_bytes() == before
    doc = json.loads(v2.path.read_bytes())
    annex = doc["sections"][12]["content"]
    assert annex["supersedes"] == {"report_id": "report-v1",
                                   "sha256": v1.ref.split("=", 1)[1]}
    (mod,) = annex["changes"]["modified"]
    assert mod["fields"] == ["remediation"]
    assert _reproduce(lab, "report-v1") == (True, "")
    assert _reproduce(lab, "report-v2") == (True, "")


def test_intento_fallido_no_consume_version(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1", cwe="unknown")
    with pytest.raises(MissingField):
        lab.generate()
    lab.vulns, lab.candidates = [], []
    lab.finding("f-1")
    assert lab.generate().report_id == "report-v1"


def test_archivo_de_la_version_ya_existente(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.reports_dir().mkdir(parents=True)
    (lab.reports_dir() / "report-v1.json").write_text("previo")
    with pytest.raises(FileExistsError):
        lab.generate()
    assert (lab.reports_dir() / "report-v1.json").read_text() == "previo"
    assert lab.control("report.generated") == []


def test_dos_generaciones_iguales_son_byte_a_byte(tmp_path):
    a, b = Lab(tmp_path / "a"), Lab(tmp_path / "b")
    for lab in (a, b):
        lab.finding("f-1")
    ra, rb = a.generate(), b.generate()
    da, db = json.loads(ra.path.read_bytes()), json.loads(rb.path.read_bytes())
    for d in (da, db):                    # lo único que depende del reloj es la bitácora
        d.pop("as_of"), d.pop("audit_hash"), d.pop("inputs")
        d["sections"] = [s for s in d["sections"] if s["key"] not in ("annex_audit",
                                                                       "annex_reproducibility")]
    assert da == db


def test_archivo_existente_queda_en_la_bitacora(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.reports_dir().mkdir(parents=True)
    (lab.reports_dir() / "report-v1.md").write_text("previo")
    with pytest.raises(FileExistsError):
        lab.generate()
    (failed,) = lab.control("report.generation_failed")
    assert (failed["reason"], failed["subject"]) == ("version_conflict", "report-v1")


def test_version_anterior_alterada(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    v1 = lab.generate()
    v1.path.write_text(v1.path.read_text().replace("Falta", "Sobra"))
    with pytest.raises(ReportError) as exc:
        lab.generate()
    assert exc.value.reason == "evidence_mismatch"
    assert "report-v2.json" not in lab.files()
    assert lab.control("report.generation_failed")[-1]["reason"] == "evidence_mismatch"


def test_reproduce_dice_que_cambio(tmp_path, monkeypatch):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    monkeypatch.setattr(reporting, "GENERATOR_VERSION", "999")
    ok, why = _reproduce(lab)
    assert not ok and "007.1" in why and "999" in why
    assert reporting._first_diff({"a": [1, {"b": 2}]}, {"a": [1, {"b": 3}]}) == "a[1].b"
